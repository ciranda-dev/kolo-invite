package invite

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// Prefix starts every invite code written in lower case; its last character is the format version.
const Prefix = "koloinv0"

const (
	fingerprintSize = 16
	secretSize      = 32
	checksumSize    = 4
	codeBytes       = fingerprintSize + secretSize + checksumSize
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// codeLen is the length of every invite code.
var codeLen = len(Prefix) + b32.EncodedLen(codeBytes)

// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

// ID identifies an invite; it is derived from the invite secret and reveals nothing about it.
type ID [16]byte

// String returns the ID as hex.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Code is a parsed invite code. It holds the invite secret behind a pointer, so it prints only its ID, also inside
// other values.
type Code struct {
	c *code
}

type code struct {
	fp     [fingerprintSize]byte
	secret [secretSize]byte
	k      keys
}

// keys are the values derived from an invite secret.
type keys struct {
	id    ID
	topic koloswarm.Topic
	auth  [32]byte
	hpke  hpke.PrivateKey
}

// derive computes the values of an invite secret; the errors of HKDF and of DeriveKeyPair are returned, though they cannot
// happen for these lengths.
func derive(secret []byte) (keys, error) {
	var k keys
	out := func(label string, dst []byte) error {
		b, err := hkdf.Key(sha256.New, secret, nil, label, len(dst))
		copy(dst, b)
		clear(b)
		return err
	}
	if err := out("kolo-invite/id/v0", k.id[:]); err != nil {
		return keys{}, err
	}
	if err := out("kolo-invite/topic/v0", k.topic[:]); err != nil {
		return keys{}, err
	}
	if err := out("kolo-invite/auth/v0", k.auth[:]); err != nil {
		return keys{}, err
	}
	seed := make([]byte, 32)
	defer clear(seed)
	if err := out("kolo-invite/hpke/v0", seed); err != nil {
		return keys{}, err
	}
	var err error
	if k.hpke, err = kem.DeriveKeyPair(seed); err != nil {
		return keys{}, err
	}
	return k, nil
}

// fingerprint returns the first 16 bytes of SHA-256 over a label and the inviter's key.
func fingerprint(inviter ed25519.PublicKey) [fingerprintSize]byte {
	h := sha256.Sum256(append([]byte("kolo-invite/fingerprint/v0"), inviter...))
	return [fingerprintSize]byte(h[:fingerprintSize])
}

func checksum(fp, secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte(Prefix))
	h.Write(fp)
	h.Write(secret)
	return h.Sum(nil)[:checksumSize]
}

// encodeCode returns the lower-case invite code of inviter and secret.
func encodeCode(inviter ed25519.PublicKey, secret []byte) string {
	fp := fingerprint(inviter)
	b := make([]byte, 0, codeBytes)
	b = append(b, fp[:]...)
	b = append(b, secret...)
	b = append(b, checksum(fp[:], secret)...)
	s := Prefix + strings.ToLower(b32.EncodeToString(b))
	clear(b)
	return s
}

// Parse reads an invite code: all in lower case, or all in upper case. It does not trim spaces.
func Parse(s string) (Code, error) {
	if len(s) != codeLen {
		return Code{}, fmt.Errorf("%w: length %d, want %d", ErrInvalidCode, len(s), codeLen)
	}
	upper := strings.ToUpper(s)
	if s != upper && s != strings.ToLower(s) {
		return Code{}, fmt.Errorf("%w: mixed case", ErrInvalidCode)
	}
	if upper[:len(Prefix)] != strings.ToUpper(Prefix) {
		return Code{}, fmt.Errorf("%w: prefix is not %s", ErrInvalidCode, Prefix)
	}
	body := upper[len(Prefix):]
	b, err := b32.DecodeString(body)
	if err != nil || len(b) != codeBytes || b32.EncodeToString(b) != body {
		return Code{}, fmt.Errorf("%w: bad base32", ErrInvalidCode)
	}
	defer clear(b)
	fp, secret := b[:fingerprintSize], b[fingerprintSize:fingerprintSize+secretSize]
	if string(checksum(fp, secret)) != string(b[fingerprintSize+secretSize:]) {
		return Code{}, fmt.Errorf("%w: checksum mismatch", ErrInvalidCode)
	}
	c := &code{fp: [fingerprintSize]byte(fp), secret: [secretSize]byte(secret)}
	if c.k, err = derive(c.secret[:]); err != nil {
		return Code{}, fmt.Errorf("%w: %w", ErrInvalidCode, err)
	}
	return Code{c}, nil
}

// Matches reports whether key is the inviter's kolo-id key: a 16-byte fingerprint of it is in the code.
func (c Code) Matches(key ed25519.PublicKey) bool {
	return c.c != nil && len(key) == ed25519.PublicKeySize && fingerprint(key) == c.c.fp
}

// ID returns the invite's ID; zero for a zero Code.
func (c Code) ID() ID {
	if c.c == nil {
		return ID{}
	}
	return c.c.k.id
}

// Topic returns the kolo-swarm topic on which the inviter announces the invite; zero for a zero Code.
func (c Code) Topic() koloswarm.Topic {
	if c.c == nil {
		return koloswarm.Topic{}
	}
	return c.c.k.topic
}

// String returns the invite ID as hex, never the secret.
func (c Code) String() string { return "invite " + c.ID().String() }

// GoString returns the same as String.
func (c Code) GoString() string { return c.String() }

// Format prints String for every verb.
func (c Code) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
