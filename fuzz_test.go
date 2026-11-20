package invite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kolostore "github.com/ciranda-dev/kolo-store"
)

func FuzzParse(f *testing.F) {
	s := encodeCode(bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{1}, secretSize))
	f.Add(s)
	f.Add(strings.ToUpper(s))
	f.Add(Prefix)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse(s)
		if err != nil {
			return
		}
		fp, secret := c.c.fp, c.c.secret
		again := Prefix + strings.ToLower(b32.EncodeToString(append(append(fp[:], secret[:]...), checksum(fp[:], secret[:])...)))
		if again != s && strings.ToUpper(again) != s {
			t.Fatalf("Parse accepted %q, which encodes as %q", s, again)
		}
	})
}

func FuzzDecodeMsg(f *testing.F) {
	for _, m := range []msg{{typ: msgOpen}, {typ: msgChallenge, nonce: make([]byte, nonceSize)},
		{typ: msgRequest, enc: make([]byte, encSize), sealed: []byte{1, 2}}, {typ: msgReceived},
		{typ: msgAnswer, sealed: []byte{3}}, {typ: msgRefused, code: refBusy}} {
		f.Add(m.encode())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeMsg(b)
		if err != nil {
			return
		}
		if again := m.encode(); !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
	})
}

func FuzzDecodeRequest(f *testing.F) {
	r := request{auth: make([]byte, 32), joiner: make([]byte, 32), answerKey: make([]byte, 32), data: []byte("x"),
		sig: make([]byte, sigSize)}
	f.Add(r.plaintext())
	r.data = make([]byte, 3000)
	f.Add(r.plaintext())
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeRequest(b)
		if err != nil {
			return
		}
		if again := r.plaintext(); !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
	})
}

func FuzzDecodeAnswer(f *testing.F) {
	f.Add(answer{kind: kindAccepted, payload: []byte("p")}.encode())
	f.Add(answer{kind: kindAccepted, payload: make([]byte, 2000)}.encode())
	f.Add(answer{kind: kindDenied}.encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := decodeAnswer(b)
		if err != nil {
			return
		}
		if again := a.encode(); !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
	})
}

func FuzzDecodeRecord(f *testing.F) {
	secret := bytes.Repeat([]byte{3}, secretSize)
	id := mustKeys(secret).id
	f.Add((&record{secret: secret, created: 1, expires: 2, maxUses: 3, used: 1, payload: []byte("p")}).encode())
	f.Add((&record{created: 1, ended: 2, maxUses: 1, used: 1, revoked: true}).encode())
	f.Add((&record{secret: secret, created: 1, expires: 2, maxUses: 1, manual: true, device: true}).encode())
	f.Add(recordV0(&record{secret: secret, created: 1, expires: 2, maxUses: 3, used: 1, payload: []byte("p")}))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeRecord(id, b)
		if err != nil {
			return
		}
		again := r.encode()
		// A device record is version 1 and any other is version 0: the same bytes in, the same bytes out.
		if !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
		r2, err := decodeRecord(id, again)
		if err != nil || !bytes.Equal(r2.encode(), again) || r2.device != r.device {
			t.Fatalf("record does not survive a rewrite: %v", err)
		}
	})
}

func FuzzDecodeStored(f *testing.F) {
	f.Add(byte(0), joined{payload: []byte("p"), data: []byte("d"), at: 5}.encode())
	f.Add(byte(1), encodeVersion())
	f.Add(byte(2), encodeMeta(make([]byte, 32)))
	f.Fuzz(func(t *testing.T, which byte, b []byte) {
		switch which % 3 {
		case 0:
			if j, err := decodeJoined(b); err == nil && !bytes.Equal(j.encode(), b) {
				t.Fatalf("accept %x", b)
			}
		case 1:
			if err := decodeDenied(b); err == nil && !bytes.Equal(encodeVersion(), b) {
				t.Fatalf("deny %x", b)
			}
		default:
			if k, err := decodeMeta(b); err == nil && !bytes.Equal(encodeMeta(k), b) {
				t.Fatalf("meta %x", b)
			}
		}
	})
}

// FuzzLoad opens an inviter on a store with one fuzzed key and value next to a valid invite.
func FuzzLoad(f *testing.F) {
	secret := bytes.Repeat([]byte{3}, secretSize)
	id := mustKeys(secret).id
	good := (&record{secret: secret, created: 1, maxUses: 2}).encode()
	f.Add(inviteKey(id), good)
	f.Add(joinerKey(pAccepted, id, make([]byte, 32)), joined{}.encode())
	f.Add([]byte("m"), []byte{0})
	f.Fuzz(func(t *testing.T, key, value []byte) {
		db := kolostore.NewMemory()
		defer db.Close()
		db.Put([]byte{pMeta}, encodeMeta(fuzzID.PublicKey()))
		db.Put(inviteKey(id), good)
		if len(key) > 0 {
			db.Put(key, value)
		}
		in, err := Open(db, fuzzID, nil)
		if err != nil {
			return
		}
		in.List()
		in.Joiners(id)
		in.Close()
	})
}

var fuzzID, _ = koloid.FromSeed(bytes.Repeat([]byte{5}, 32))

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{3, 0, 0, 0, 1, 2, 3, 4}, 8)
	f.Add([]byte{9, 0, 0, 0}, 8)
	f.Add([]byte{0, 0, 0, 0}, 0)
	f.Add([]byte{1, 2}, 8)
	f.Fuzz(func(t *testing.T, in []byte, max int) {
		max %= 1 << 16
		if max < 0 {
			max = -max
		}
		b, err := readFrame(bytes.NewReader(in), max)
		var n uint64
		if len(in) >= 4 {
			n = uint64(binary.LittleEndian.Uint32(in))
		}
		switch {
		case len(in) < 4:
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("short header: %v", err)
			}
		case n > uint64(max):
			if !errors.Is(err, errFrame) {
				t.Fatalf("frame of %d over %d: %v", n, max, err)
			}
		case uint64(len(in)-4) < n:
			if err == nil {
				t.Fatal("a cut frame was read")
			}
		case err != nil || !bytes.Equal(b, in[4:4+n]):
			t.Fatalf("frame of %d: %x, %v", n, b, err)
		}
	})
}
