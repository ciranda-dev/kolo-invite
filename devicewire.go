package invite

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// maxOffer is the largest CertOffer encoding of kolo-id: a body, a signature and an approver certificate.
const maxOffer = 450

// invisible says whether r draws nothing: the Default_Ignorable_Code_Point characters that are not format characters (the Other
// ones, which hold the fillers, the combining grapheme joiner and more, and the variation selectors), and the blank braille cell.
func invisible(r rune) bool {
	return r == 0x2800 || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Variation_Selector, r)
}

// checkName checks a device name: 1 to max bytes of UTF-8 made of letters, numbers, marks, punctuation, symbols and
// single ordinary spaces between them, so a name cannot be blank or hide characters on a screen; look-alike letters of other
// scripts remain possible, which is why the person compares digits and not names.
func checkName(name string, max int) error {
	if len(name) == 0 || len(name) > max || !utf8.ValidString(name) {
		return fmt.Errorf("device name of %d bytes", len(name))
	}
	prev := ' ' // a leading space is refused like a double one
	for _, r := range name {
		switch {
		case r == ' ':
			if prev == ' ' {
				return errors.New("device name with a leading or double space")
			}
		case r == utf8.RuneError || invisible(r):
			return errors.New("device name with an invisible character")
		case unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r):
		case unicode.IsMark(r) && prev != ' ':
		default:
			return errors.New("device name with a character that is not a letter, number, mark, punctuation or symbol")
		}
		prev = r
	}
	if prev == ' ' {
		return errors.New("device name with a trailing space")
	}
	return nil
}

// linkData is the data of a link-a-device request.
type linkData struct {
	name string
}

func (r linkData) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutString(r.name)
	return e.Bytes()
}

func decodeLinkData(b []byte, max int) (linkData, error) {
	d := kolocodec.NewDecoder(b)
	var r linkData
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		r.name, err = d.String(max)
	}
	if err == nil {
		err = d.Done()
	}
	if err == nil {
		err = checkName(r.name, max)
	}
	if err != nil {
		return linkData{}, fmt.Errorf("%w: device request: %w", ErrInvalid, err)
	}
	return r, nil
}

// linkAnswer is the payload of an accepted link-a-device request: the person key and the signed offer.
type linkAnswer struct {
	person ed25519.PublicKey
	offer  []byte
}

func (a linkAnswer) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutFixed(a.person)
	e.PutBytes(a.offer)
	return e.Bytes()
}

func decodeLinkAnswer(b []byte) (linkAnswer, error) {
	d := kolocodec.NewDecoder(b)
	var a linkAnswer
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		a.person, err = d.Fixed(ed25519.PublicKeySize)
	}
	if err == nil {
		a.offer, err = d.Bytes(maxOffer)
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return linkAnswer{}, fmt.Errorf("%w: link answer: %w", ErrProtocol, err)
	}
	return a, nil
}
