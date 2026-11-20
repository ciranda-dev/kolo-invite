package invite

import (
	"cmp"
	"context"
	"crypto/hpke"
	"errors"
	"fmt"

	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// JoinOptions sets what JoinConn sends and accepts.
type JoinOptions struct {
	// Data is sent to the inviter with the request, for example a display name; the inviter refuses more than its
	// MaxData (default 64 KiB) with ErrTooLarge.
	Data []byte
	// MaxPayload caps the payload JoinConn accepts, in bytes; a larger one is ErrTooLarge. Default 1 MiB.
	MaxPayload int

	received func() // tests: called once the inviter's RECEIVED is read
}

// JoinConn asks the inviter of code, on conn, to let id join, and returns the payload of the accept. conn must be
// a connection to the inviter (code.Matches its remote key), for example from a Connected event of a swarm that
// joined code.Topic(); the inviter must run ServePeer on it. JoinConn opens one stream and waits for the answer as
// long as ctx allows: a Manual invite waits for a person, so give ctx a deadline or cancel it.
//
// The answers are ErrDenied, ErrExpired, ErrUsedUp, ErrRevoked, ErrInvalid, ErrRateLimited, ErrBusy and
// ErrTooLarge. A failed connection or ctx ending is ErrUnreachable before the inviter received the request and
// ErrNotAnswered after; both wrap the cause, and asking again is safe.
func JoinConn(ctx context.Context, conn koloswarm.Conn, id *koloid.Identity, code Code, opts *JoinOptions) ([]byte, error) {
	var o JoinOptions
	if opts != nil {
		o = *opts
	}
	switch {
	case conn == nil || id == nil || id.PublicKey() == nil || code.c == nil || o.MaxPayload < 0:
		return nil, fmt.Errorf("%w: nil connection, identity or code, or negative MaxPayload", ErrInvalidArgument)
	case len(o.Data) > maxSend:
		return nil, fmt.Errorf("%w: data over 1 GiB", ErrTooLarge)
	case !code.Matches(conn.RemotePublicKey()):
		return nil, fmt.Errorf("%w: the peer is not the inviter", ErrProtocol)
	}
	if o.MaxPayload == 0 {
		o.MaxPayload = 1 << 20
	}
	received := false
	fail := func(err error) error {
		switch {
		case errors.Is(err, ErrProtocol):
			return err
		case errors.Is(err, errFrame):
			return fmt.Errorf("%w: a message over MaxPayload", ErrTooLarge)
		case ctx.Err() != nil:
			err = ctx.Err()
		}
		if received {
			return fmt.Errorf("%w: %w", ErrNotAnswered, err)
		}
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	st, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fail(err)
	}
	defer st.CancelRead(0)
	defer st.CancelWrite(0)
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()
	writeFrame(st, msg{typ: msgOpen}.encode()) // a failed write shows in the next read
	m, err := readMsg(st, smallFrame)
	if err != nil {
		return nil, fail(err)
	}
	if m.typ != msgChallenge {
		return nil, fmt.Errorf("%w: expected a challenge", ErrProtocol)
	}
	inviter := conn.RemotePublicKey()
	req, reply, err := newRequest(code, inviter, id, o.Data, m.nonce)
	if err != nil {
		return nil, fmt.Errorf("invite: %w", err)
	}
	// A request the inviter refuses before reading all of it fails to write; its refusal is read first.
	werr := writeFrame(st, req.encode())
	for {
		m, err := readMsg(st, maxFrame(o.MaxPayload))
		if err != nil {
			return nil, fail(cmp.Or(werr, err))
		}
		switch m.typ {
		case msgReceived:
			if received {
				return nil, fmt.Errorf("%w: a second received message", ErrProtocol)
			}
			received = true
			if o.received != nil {
				o.received()
			}
		case msgAnswer:
			pt, err := hpke.Open(reply, kdf, aead, answerInfo(inviter, code.c.k.id, req.nonce, id.PublicKey()), m.sealed)
			if err != nil {
				return nil, fmt.Errorf("%w: answer does not decrypt", ErrProtocol)
			}
			a, err := decodeAnswer(pt)
			switch {
			case err != nil:
				return nil, err
			case a.kind == kindAccepted:
				if len(a.payload) > o.MaxPayload {
					return nil, fmt.Errorf("%w: payload over MaxPayload", ErrTooLarge)
				}
				return a.payload, nil
			case a.kind == kindDenied:
				return nil, ErrDenied
			}
			return nil, stateErr(Expired + State(a.kind-kindExpired))
		case msgRefused:
			switch m.code {
			case refInvalid:
				return nil, ErrInvalid
			case refLimited:
				return nil, ErrRateLimited
			case refBusy:
				return nil, ErrBusy
			case refTooLarge:
				return nil, fmt.Errorf("%w: data over the inviter's MaxData", ErrTooLarge)
			}
			return nil, stateErr(Expired + State(m.code-refExpired))
		default:
			return nil, fmt.Errorf("%w: unexpected message type %d", ErrProtocol, m.typ)
		}
	}
}

// sentRequest is a sealed request with the challenge it answers.
type sentRequest struct {
	msg
	nonce []byte
}

// newRequest seals and signs a request of id for code and inviter under the challenge nonce, and returns it with the key its answer is
// sealed to.
func newRequest(code Code, inviter []byte, id *koloid.Identity, data, nonce []byte) (sentRequest, hpke.PrivateKey, error) {
	reply, err := kem.GenerateKey()
	if err != nil {
		return sentRequest{}, nil, err
	}
	enc, sender, err := hpke.NewSender(code.c.k.hpke.PublicKey(), kdf, aead, requestInfo(inviter, code.c.k.id, nonce))
	if err != nil {
		return sentRequest{}, nil, err
	}
	r := request{auth: code.c.k.auth[:], joiner: id.PublicKey(), answerKey: reply.PublicKey().Bytes(), data: data}
	signed := r.signed()
	if r.sig, err = id.Sign(ctxRequest, requestTranscript(inviter, code.c.k.id, nonce, enc, signed)); err != nil {
		return sentRequest{}, nil, err
	}
	sealed, err := sender.Seal(nil, r.plaintext())
	if err != nil {
		return sentRequest{}, nil, err
	}
	return sentRequest{msg{typ: msgRequest, id: code.c.k.id, enc: enc, sealed: sealed}, nonce}, reply, nil
}
