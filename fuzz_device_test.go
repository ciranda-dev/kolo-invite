package invite

import (
	"bytes"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
)

// recordV0 encodes r in the version 0 layout, which has no device flag.
func recordV0(r *record) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutBytes(r.secret)
	e.PutVarint(r.created)
	e.PutVarint(r.expires)
	e.PutVarint(r.ended)
	e.PutUvarint(r.maxUses)
	e.PutUvarint(r.used)
	e.PutBool(r.manual)
	e.PutBool(r.revoked)
	e.PutBytes(r.payload)
	return e.Bytes()
}

func FuzzDecodeDeviceRequest(f *testing.F) {
	f.Add(linkData{name: "phone"}.encode())
	f.Add(linkData{name: "Maria's telefone"}.encode())
	f.Add([]byte{})
	f.Add([]byte{0, 3, 'a', 0, 'b'})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeLinkData(b, DefaultMaxDeviceName)
		if err != nil {
			return
		}
		if again := r.encode(); !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
		if checkName(r.name, DefaultMaxDeviceName) != nil {
			t.Fatalf("decoded the name %q, which checkName refuses", r.name)
		}
	})
}

func FuzzDecodeDeviceAnswer(f *testing.F) {
	person := bytes.Repeat([]byte{4}, 32)
	f.Add(linkAnswer{person, []byte("offer")}.encode())
	f.Add(linkAnswer{person, bytes.Repeat([]byte{1}, maxOffer)}.encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := decodeLinkAnswer(b)
		if err != nil {
			return
		}
		if again := a.encode(); !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
	})
}

// FuzzAcceptDeviceAnswer feeds the new device's checks with arbitrary payloads: it must never panic, and anything it
// accepts must be a certificate of this device that chains to the person the payload names.
func FuzzAcceptDeviceAnswer(f *testing.F) {
	person, approver, dev := fuzzIdentity(1), fuzzIdentity(2), fuzzIdentity(3)
	aOffer, _ := person.OfferDeviceCert(approver.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	aCert, _ := approver.AcceptDeviceCert(aOffer, person.PublicKey())
	offer, _ := approver.OfferDeviceCert(dev.PublicKey(), &koloid.IssueOptions{Parent: aCert, Serial: 1})
	f.Add(linkAnswer{person.PublicKey(), offer.Encode()}.encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := acceptDeviceAnswer(dev, approver.PublicKey(), nil, b)
		if err != nil {
			return
		}
		if !l.Cert.Device().Equal(dev.PublicKey()) || !l.Cert.Person().Equal(l.Person) {
			t.Fatalf("accepted a certificate of another device or person")
		}
		if err := l.Cert.Verify(&koloid.VerifyOptions{Person: l.Person}); err != nil {
			t.Fatalf("accepted a certificate that does not verify: %v", err)
		}
	})
}

func fuzzIdentity(n byte) *koloid.Identity {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{n}, 32))
	if err != nil {
		panic(err)
	}
	return id
}
