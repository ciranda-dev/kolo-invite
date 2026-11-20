package invite

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testCode(t *testing.T) (string, ed25519.PublicKey, []byte) {
	t.Helper()
	inviter := generate(t).PublicKey()
	secret := bytes.Repeat([]byte{0xa5}, secretSize)
	return encodeCode(inviter, secret), inviter, secret
}

func TestParseRoundTrip(t *testing.T) {
	s, inviter, secret := testCode(t)
	if len(s) != 92 || !strings.HasPrefix(s, Prefix) || s != strings.ToLower(s) {
		t.Fatalf("code %q, length %d", s, len(s))
	}
	for _, in := range []string{s, strings.ToUpper(s)} {
		c, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q) = %v", in, err)
		}
		if !c.Matches(inviter) || !bytes.Equal(c.c.secret[:], secret) || c.ID() != mustKeys(secret).id ||
			c.Topic() != mustKeys(secret).topic {
			t.Fatalf("Parse(%q) returned other values", in)
		}
		if c.Matches(generate(t).PublicKey()) || c.Matches(inviter[:31]) {
			t.Fatal("Matches accepted another key")
		}
	}
}

func TestDerivedValuesDiffer(t *testing.T) {
	k := mustKeys(bytes.Repeat([]byte{1}, secretSize))
	vals := [][]byte{k.id[:], k.topic[:], k.auth[:], k.hpke.PublicKey().Bytes()}
	for i := range vals {
		for j := range i {
			if bytes.Equal(vals[i][:16], vals[j][:16]) {
				t.Fatalf("derived values %d and %d are equal", i, j)
			}
		}
	}
	k2 := mustKeys(bytes.Repeat([]byte{2}, secretSize))
	if k2.topic == k.topic || k2.id == k.id {
		t.Fatal("two secrets gave the same topic or ID")
	}
}

func TestParseRejects(t *testing.T) {
	s, _, secret := testCode(t)
	body := s[len(Prefix):]
	flip := func(i int) string {
		b := []byte(s)
		if b[i] == 'a' {
			b[i] = 'b'
		} else {
			b[i] = 'a'
		}
		return string(b)
	}
	// The last character holds 1 data bit and 4 unused bits; setting an unused bit gives another spelling.
	last := strings.IndexByte(strings.ToLower(b32Alphabet), s[len(s)-1])
	cases := map[string]string{
		"empty":                  "",
		"prefix only":            Prefix,
		"other version":          "koloinv1" + body,
		"other prefix":           "kolozzz0" + body,
		"short":                  s[:len(s)-1],
		"long":                   s + "a",
		"mixed case body":        Prefix + strings.ToUpper(body[:10]) + body[10:],
		"upper prefix":           strings.ToUpper(Prefix) + body,
		"upper body":             Prefix + strings.ToUpper(body),
		"mixed prefix":           "KoLoInV0" + body,
		"bad character":          s[:20] + "1" + s[21:],
		"padding":                s[:len(s)-1] + "=",
		"space":                  " " + s[1:],
		"newline":                s[:len(s)-1] + "\n",
		"checksum":               flip(len(s) - 2),
		"fingerprint changed":    flip(len(Prefix) + 3),
		"secret changed":         flip(len(Prefix) + 40),
		"unused bits set":        s[:len(s)-1] + string(strings.ToLower(b32Alphabet)[last|1]),
		"non-ascii":              s[:len(s)-2] + "é",
		"other inviter, same ck": encodeCode(generate(t).PublicKey(), secret)[:len(Prefix)+20] + s[len(Prefix)+20:],
	}
	for name, in := range cases {
		if in == s {
			t.Fatalf("%s: case equals the valid code", name)
		}
		if _, err := Parse(in); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("%s: Parse = %v, want ErrInvalidCode", name, err)
		}
	}
}

const b32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func TestCodePrintsNoSecret(t *testing.T) {
	s, _, secret := testCode(t)
	c, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	type hidden struct{ code Code }
	type shown struct{ Code Code }
	outs := []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s %q %x", c, c, c, c, c, c), c.String(), c.GoString(),
		fmt.Sprintf("%v %+v %#v", hidden{c}, hidden{c}, hidden{c}), fmt.Sprintf("%v %+v %#v", shown{c}, shown{c}, shown{c}),
		fmt.Sprintf("%v %+v", []Code{c}, map[string]Code{"a": c}), fmt.Sprintf("%v %+v %#v", &c, &c, &c)}
	forms := []string{fmt.Sprintf("%x", secret[:4]), fmt.Sprint(secret[:4])[1:12], s[len(Prefix) : len(Prefix)+20],
		fmt.Sprintf("%#v", secret[:4])[8:20]}
	for _, out := range outs {
		for _, f := range forms {
			if strings.Contains(out, f) {
				t.Fatalf("printed %q, which holds %q", out, f)
			}
		}
	}
	if !strings.Contains(fmt.Sprint(c), c.ID().String()) {
		t.Fatal("String does not show the ID")
	}
}
