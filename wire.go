package invite

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

const (
	version    = 0
	nonceSize  = 32
	encSize    = 32 // DHKEM(X25519) encapsulated key
	tagSize    = 16 // ChaCha20-Poly1305
	sigSize    = ed25519.SignatureSize
	minPlain   = 512 // every sealed plaintext is padded to at least this
	smallFrame = 64  // bound on OPEN and CHALLENGE frames
	ctxRequest = "kolo-invite/request/v0"
	ctxAnswer  = "kolo-invite/answer/v0"
)

// Message types.
const (
	msgOpen = iota + 1
	msgChallenge
	msgRequest
	msgReceived
	msgAnswer
	msgRefused
)

// Answer kinds, sealed to the joiner.
const (
	kindAccepted = iota + 1
	kindDenied
	kindExpired
	kindUsedUp
	kindRevoked
)

// Refusal codes, sent in the clear when no sealed answer is possible.
const (
	refInvalid = iota + 1
	refLimited
	refBusy
	refExpired
	refUsedUp
	refRevoked
	refTooLarge
)

// minSealed is the smallest sealed answer, and refusedPad pads a REFUSED body to the size of its frame.
const (
	minSealed  = encSize + minPlain + tagSize
	refusedPad = 2 + 2 + minSealed - 3 // ANSWER body: version, type, uvarint(minSealed) of 2 bytes, sealed
)

var errFrame = errors.New("invite: frame too large")

// padme returns the Padmé length of n (Nikitin et al., PURBs, 2019): at most about 12% more, with fewer distinct
// lengths.
func padme(n uint64) uint64 {
	if n < 2 {
		return n
	}
	e := uint64(bits.Len64(n) - 1)
	s := uint64(bits.Len64(e))
	mask := uint64(1)<<(e-s) - 1
	return (n + mask) &^ mask
}

// padLen is the padded length of a plaintext of n bytes.
func padLen(n int) int { return int(max(minPlain, padme(uint64(n)))) }

func pad(b []byte) []byte { return append(b, make([]byte, padLen(len(b))-len(b))...) }

// unpad checks that what is left in d is the zero padding of a plaintext of total bytes.
func unpad(d *kolocodec.Decoder, total int) error {
	rest := d.Len()
	z, _ := d.Fixed(rest)
	for _, c := range z {
		if c != 0 {
			return errors.New("non-zero padding")
		}
	}
	if total != padLen(total-rest) {
		return errors.New("wrong padding length")
	}
	return nil
}

// maxFrame is the frame bound for data of at most n bytes, with every header, signature, tag and padding.
func maxFrame(n int) int { return padLen(n+256) + 256 }

func writeFrame(w io.Writer, body []byte) error {
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}

// readFrame reads one frame of at most max bytes; a longer one is errFrame, before its body is read.
func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(h[:])
	if uint64(n) > uint64(max) {
		return nil, errFrame
	}
	// The buffer grows with the bytes that arrive, so a header alone never allocates n.
	b, err := io.ReadAll(io.LimitReader(r, int64(n)))
	switch {
	case err != nil:
		return nil, err
	case len(b) < int(n) && len(b) == 0:
		return nil, io.EOF
	case len(b) < int(n):
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

// msg is one decoded message; which fields are set depends on typ.
type msg struct {
	typ    uint64
	nonce  []byte // challenge
	id     ID     // request
	enc    []byte // request
	sealed []byte // request ciphertext, or answer enc ‖ ciphertext
	code   uint64 // refused
}

func (m msg) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutUvarint(m.typ)
	switch m.typ {
	case msgChallenge:
		e.PutFixed(m.nonce)
	case msgRequest:
		e.PutFixed(m.id[:])
		e.PutFixed(m.enc)
		e.PutBytes(m.sealed)
	case msgAnswer:
		e.PutBytes(m.sealed)
	case msgRefused:
		e.PutUvarint(m.code)
		e.PutFixed(make([]byte, refusedPad))
	}
	return e.Bytes()
}

func decodeMsg(b []byte) (msg, error) {
	d := kolocodec.NewDecoder(b)
	var m msg
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		m.typ, err = d.Uvarint()
	}
	if err == nil {
		switch m.typ {
		case msgOpen, msgReceived:
		case msgChallenge:
			m.nonce, err = d.Fixed(nonceSize)
		case msgRequest:
			var id []byte
			if id, err = d.Fixed(len(m.id)); err == nil {
				m.id = ID(id)
				if m.enc, err = d.Fixed(encSize); err == nil {
					m.sealed, err = d.Bytes(len(b))
				}
			}
		case msgAnswer:
			m.sealed, err = d.Bytes(len(b))
		case msgRefused:
			var z []byte
			if m.code, err = d.Uvarint(); err == nil && (m.code < refInvalid || m.code > refTooLarge) {
				err = fmt.Errorf("refusal code %d", m.code)
			}
			if err == nil {
				z, err = d.Fixed(refusedPad)
			}
			if err == nil && string(z) != string(make([]byte, refusedPad)) {
				err = errors.New("non-zero padding")
			}
		default:
			err = fmt.Errorf("message type %d", m.typ)
		}
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return msg{}, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	return m, nil
}

// request is the plaintext of a join request.
type request struct {
	auth      []byte
	joiner    ed25519.PublicKey
	answerKey []byte
	data      []byte
	sig       []byte
}

// signed returns the request without its signature and padding, as signed.
func (r request) signed() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutFixed(r.auth)
	e.PutFixed(r.joiner)
	e.PutFixed(r.answerKey)
	e.PutBytes(r.data)
	return e.Bytes()
}

// plaintext returns the padded request with its signature, as sealed.
func (r request) plaintext() []byte { return pad(append(r.signed(), r.sig...)) }

func decodeRequest(b []byte) (request, error) {
	d := kolocodec.NewDecoder(b)
	var r request
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		r.auth, err = d.Fixed(32)
	}
	if err == nil {
		r.joiner, err = d.Fixed(ed25519.PublicKeySize)
	}
	if err == nil {
		r.answerKey, err = d.Fixed(encSize)
	}
	if err == nil {
		r.data, err = d.Bytes(len(b))
	}
	if err == nil {
		r.sig, err = d.Fixed(sigSize)
	}
	if err == nil {
		err = unpad(d, len(b))
	}
	if err != nil {
		return request{}, fmt.Errorf("%w: request: %w", ErrInvalid, err)
	}
	return r, nil
}

// requestTranscript is what the joiner signs: the identifiers of the exchange and the request before its signature.
func requestTranscript(inviter ed25519.PublicKey, id ID, nonce, enc, signed []byte) []byte {
	b := make([]byte, 0, len(inviter)+len(id)+len(nonce)+len(enc)+len(signed))
	b = append(b, inviter...)
	b = append(b, id[:]...)
	b = append(b, nonce...)
	b = append(b, enc...)
	return append(b, signed...)
}

func requestInfo(inviter ed25519.PublicKey, id ID, nonce []byte) []byte {
	b := append([]byte(ctxRequest), inviter...)
	b = append(b, id[:]...)
	return append(b, nonce...)
}

func answerInfo(inviter ed25519.PublicKey, id ID, nonce []byte, joiner ed25519.PublicKey) []byte {
	b := append([]byte(ctxAnswer), inviter...)
	b = append(b, id[:]...)
	b = append(b, nonce...)
	return append(b, joiner...)
}

// answer is the plaintext of a sealed answer.
type answer struct {
	kind    uint64
	payload []byte
}

func (a answer) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutUvarint(a.kind)
	if a.kind == kindAccepted {
		e.PutBytes(a.payload)
	}
	return pad(e.Bytes())
}

func decodeAnswer(b []byte) (answer, error) {
	d := kolocodec.NewDecoder(b)
	var a answer
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		a.kind, err = d.Uvarint()
	}
	if err == nil {
		switch a.kind {
		case kindAccepted:
			a.payload, err = d.Bytes(len(b))
		case kindDenied, kindExpired, kindUsedUp, kindRevoked:
		default:
			err = fmt.Errorf("answer kind %d", a.kind)
		}
	}
	if err == nil {
		err = unpad(d, len(b))
	}
	if err != nil {
		return answer{}, fmt.Errorf("%w: answer: %w", ErrProtocol, err)
	}
	return a, nil
}
