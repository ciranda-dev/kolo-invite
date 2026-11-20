package invite

import (
	"crypto/hpke"
	"errors"
	"net/netip"
	"strings"
	"testing"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// fakeInviter answers one stream with reply, which gets the request and the challenge it sent.
func fakeInviter(t *testing.T, e *env, reply func(st *kolotransport.Stream, req msg, nonce []byte)) *kolosecure.Conn {
	t.Helper()
	ln, err := kolosecure.Listen(e.ctx, "127.0.0.1:0", e.id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		c, err := ln.Accept(e.ctx)
		if err != nil {
			return
		}
		defer c.Close()
		st, err := c.AcceptStream(e.ctx)
		if err != nil {
			return
		}
		defer st.CancelRead(0)
		if _, err := readMsg(st, smallFrame); err != nil {
			return
		}
		nonce := make([]byte, nonceSize)
		writeFrame(st, msg{typ: msgChallenge, nonce: nonce}.encode())
		req, err := readMsg(st, maxFrame(1<<20))
		if err != nil {
			return
		}
		reply(st, req, nonce)
		st.Close()
		<-c.Context().Done()
	}()
	c, err := kolosecure.Dial(e.ctx, ln.Addr().String(), generate(t), e.id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sealAnswer seals plaintext to the answer key of req, which the fake inviter decrypts with code's keys.
func sealAnswer(t *testing.T, e *env, code Code, req msg, nonce, plaintext []byte) []byte {
	r, to, ok := openRequest(code.c.k, e.id.PublicKey(), req, nonce)
	if !ok {
		t.Error("fake inviter could not open the request")
		return nil
	}
	b, err := hpke.Seal(to, kdf, aead, answerInfo(e.id.PublicKey(), code.c.k.id, nonce, r.joiner), plaintext)
	if err != nil {
		t.Error(err)
	}
	return b
}

func TestJoinerAnswers(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	send := func(ms ...msg) func(*kolotransport.Stream, msg, []byte) {
		return func(st *kolotransport.Stream, _ msg, _ []byte) {
			for _, m := range ms {
				writeFrame(st, m.encode())
			}
		}
	}
	sealed := func(pt []byte) func(*kolotransport.Stream, msg, []byte) {
		return func(st *kolotransport.Stream, req msg, nonce []byte) {
			writeFrame(st, msg{typ: msgReceived}.encode())
			writeFrame(st, msg{typ: msgAnswer, sealed: sealAnswer(t, e, code, req, nonce, pt)}.encode())
		}
	}
	rcv := msg{typ: msgReceived}
	cases := map[string]struct {
		reply func(*kolotransport.Stream, msg, []byte)
		want  error
	}{
		"invalid":          {send(rcv, msg{typ: msgRefused, code: refInvalid}), ErrInvalid},
		"limited":          {send(rcv, msg{typ: msgRefused, code: refLimited}), ErrRateLimited},
		"busy":             {send(rcv, msg{typ: msgRefused, code: refBusy}), ErrBusy},
		"too large":        {send(msg{typ: msgRefused, code: refTooLarge}), ErrTooLarge},
		"expired plain":    {send(rcv, msg{typ: msgRefused, code: refExpired}), ErrExpired},
		"used up plain":    {send(rcv, msg{typ: msgRefused, code: refUsedUp}), ErrUsedUp},
		"revoked plain":    {send(rcv, msg{typ: msgRefused, code: refRevoked}), ErrRevoked},
		"denied":           {sealed(answer{kind: kindDenied}.encode()), ErrDenied},
		"expired":          {sealed(answer{kind: kindExpired}.encode()), ErrExpired},
		"used up":          {sealed(answer{kind: kindUsedUp}.encode()), ErrUsedUp},
		"revoked":          {sealed(answer{kind: kindRevoked}.encode()), ErrRevoked},
		"bad kind":         {sealed(answer{kind: 9}.encode()), ErrProtocol},
		"unpadded":         {sealed([]byte{0, kindDenied}), ErrProtocol},
		"non-zero padding": {sealed(append([]byte{0, kindDenied, 1}, make([]byte, minPlain-3)...)), ErrProtocol},
		"not decrypting":   {send(rcv, msg{typ: msgAnswer, sealed: make([]byte, 64)}), ErrProtocol},
		"wrong message":    {send(msg{typ: msgChallenge, nonce: make([]byte, nonceSize)}), ErrProtocol},
		"two received":     {send(rcv, rcv), ErrProtocol},
		"bad refusal code": {func(st *kolotransport.Stream, _ msg, _ []byte) {
			writeFrame(st, append([]byte{0, msgRefused, 9}, make([]byte, refusedPad)...))
		}, ErrProtocol},
		"huge frame": {func(st *kolotransport.Stream, _ msg, _ []byte) {
			st.Write([]byte{0xff, 0xff, 0xff, 0xff})
		}, ErrTooLarge},
		"closed before received": {func(*kolotransport.Stream, msg, []byte) {}, ErrUnreachable},
		"closed after received":  {send(rcv), ErrNotAnswered},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			conn := fakeInviter(t, e, c.reply)
			if _, err := e.joinAs(conn, generate(t), code, nil); !errors.Is(err, c.want) {
				t.Fatalf("JoinConn = %v, want %v", err, c.want)
			}
		})
	}
	t.Run("challenge expected", func(t *testing.T) {
		ln, err := kolosecure.Listen(e.ctx, "127.0.0.1:0", e.id, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := ln.Accept(e.ctx)
			if err != nil {
				return
			}
			defer c.Close()
			st, err := c.AcceptStream(e.ctx)
			if err != nil {
				return
			}
			readMsg(st, smallFrame)
			writeFrame(st, msg{typ: msgReceived}.encode())
			st.Close()
			<-c.Context().Done()
		}()
		conn, err := kolosecure.Dial(e.ctx, ln.Addr().String(), generate(t), e.id.PublicKey(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.joinAs(conn, generate(t), code, nil); !errors.Is(err, ErrProtocol) {
			t.Fatalf("JoinConn = %v", err)
		}
		conn.Close()
		<-done
	})
}

func TestFramesHideTheAnswer(t *testing.T) {
	// A deny, every refusal and an accept with a small payload give frames of one size.
	accept := msg{typ: msgAnswer, sealed: make([]byte, encSize+len(answer{kind: kindAccepted, payload: make([]byte, 300)}.encode())+tagSize)}
	deny := msg{typ: msgAnswer, sealed: make([]byte, encSize+len(answer{kind: kindDenied}.encode())+tagSize)}
	n := len(accept.encode())
	if len(deny.encode()) != n {
		t.Fatalf("accept %d, deny %d", n, len(deny.encode()))
	}
	for c := uint64(refInvalid); c <= refTooLarge; c++ {
		if l := len(msg{typ: msgRefused, code: c}.encode()); l != n {
			t.Fatalf("refusal %d: %d bytes, answer %d", c, l, n)
		}
	}
	// Requests and answers are padded to Padmé lengths.
	for _, l := range []int{0, 100, 511, 512, 513, 1000, 5000, 70000} {
		p := padLen(l)
		if p < l || p < minPlain || p > max(minPlain, l+l/8+1) {
			t.Fatalf("padLen(%d) = %d", l, p)
		}
	}
	if padme(0) != 0 || padme(1) != 1 || padme(9) != 10 || padme(1000) != 1024 {
		t.Fatalf("padme: %d %d %d %d", padme(0), padme(1), padme(9), padme(1000))
	}
}

func TestSource(t *testing.T) {
	key := generate(t).PublicKey()
	if s := source(netip.MustParseAddrPort("10.1.2.3:4000"), key); s != "10.1.2.3" {
		t.Fatal(s)
	}
	if s := source(netip.AddrPort{}, key); !strings.HasPrefix(s, "key ") || len(s) != 4+64 {
		t.Fatal(s)
	}
}

func TestAcceptOf508BytesLooksLikeDeny(t *testing.T) {
	if a, d := len(answer{kind: kindAccepted, payload: make([]byte, 508)}.encode()), len(answer{kind: kindDenied}.encode()); a != d {
		t.Fatalf("accept %d, deny %d", a, d)
	}
	if len(answer{kind: kindAccepted, payload: make([]byte, 509)}.encode()) == minPlain {
		t.Fatal("509 bytes still fit the floor")
	}
}
