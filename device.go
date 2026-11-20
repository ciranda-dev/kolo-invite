package invite

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// The link-a-device defaults.
const (
	// DefaultDeviceTTL is how long a link-a-device code lasts when DeviceOptions.TTL is zero.
	DefaultDeviceTTL = 5 * time.Minute
	// DefaultMaxDeviceName is the default of Options.MaxDeviceName and DeviceJoinOptions.MaxName, in bytes.
	DefaultMaxDeviceName = 64
	// DefaultMaxDevicePayload is the default of DeviceJoinOptions.MaxPayload, in bytes: an answer is under 600.
	DefaultMaxDevicePayload = 4096

	defaultDevicePendingTTL = 2 * time.Minute
)

// DeviceOptions describes a link-a-device invite.
type DeviceOptions struct {
	// TTL is how long the code can be used, on the inviter's clock: default DefaultDeviceTTL; negative is an error.
	TTL time.Duration
}

// CreateDevice makes a link-a-device invite: Manual, one use, short-lived, burned by a refusal or an unanswered request. The
// code is the invite's secret: show it only to the new device. The rules are in docs/guide.md.
func (in *Inviter) CreateDevice(opts *DeviceOptions) (string, Info, error) {
	var o DeviceOptions
	if opts != nil {
		o = *opts
	}
	if o.TTL < 0 {
		return "", Info{}, fmt.Errorf("%w: negative TTL", ErrInvalidArgument)
	}
	if o.TTL == 0 {
		o.TTL = DefaultDeviceTTL
	}
	return in.create(CreateOptions{TTL: o.TTL, MaxUses: 1, Manual: true}, true)
}

// pendingDevicesLocked counts the pending requests of link-a-device invites.
func (in *Inviter) pendingDevicesLocked() int {
	n := 0
	for _, p := range in.pending {
		if p.device {
			n++
		}
	}
	return n
}

// burn ends v's code at once; a failed store write is retried by the clock.
func (in *Inviter) burn(v *inv) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !in.closed {
		in.burnLocked(v)
	}
}

// LinkRequest is what an approver shows for a pending link-a-device request. It has no fingerprint: the person types the one the
// new device shows into MatchDevice.
type LinkRequest struct {
	Request RequestID
	Invite  ID
	// Device is the key the request is signed with, the key that would be certified.
	Device ed25519.PublicKey
	// Name is the name the new device chose; it proves nothing, so two requests with one name differ only by their fingerprints.
	Name string
}

// PendingLink returns what to show for the pending request req of a link-a-device invite: ErrNotFound for a request that is
// gone, ErrInvalidArgument for a request of another kind of invite.
func (in *Inviter) PendingLink(req RequestID) (LinkRequest, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	p, err := in.pendingLocked(req)
	if err != nil {
		return LinkRequest{}, err
	}
	if !p.device {
		return LinkRequest{}, fmt.Errorf("%w: not a link-a-device request", ErrInvalidArgument)
	}
	d, err := decodeLinkData(p.data, in.opts.MaxDeviceName)
	if err != nil {
		return LinkRequest{}, err
	}
	return LinkRequest{Request: p.id, Invite: p.inv.id, Device: bytes.Clone(p.joiner), Name: d.name}, nil
}

// DeviceMatch is a pending link-a-device request whose fingerprint the person typed. Only MatchDevice makes one, and the two
// approve calls take nothing else. An application must not compute the fingerprint itself (DeviceFingerprint is for the new
// device): it must ask the person to type what the new device shows. The match names the request as it was when matched: if the same
// key asks again with another name, the match no longer applies.
type DeviceMatch struct {
	req    RequestID
	inv    ID
	joiner ed25519.PublicKey
	name   string // the name the request had when it was matched
}

// Request returns the request the match names, for example to look its name up with PendingLink.
func (m DeviceMatch) Request() RequestID { return m.req }

// normalizeDigits removes the spaces of a typed fingerprint.
func normalizeDigits(s string) string { return strings.ReplaceAll(s, " ", "") }

// MatchDevice finds the pending link-a-device request whose fingerprint is typed, the digits the person read on the new device's
// screen (spaces are ignored). It returns ErrFingerprint when none matches. The comparison takes the same time for every digit.
func (in *Inviter) MatchDevice(typed string) (DeviceMatch, error) {
	typed = normalizeDigits(typed)
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return DeviceMatch{}, ErrClosed
	}
	var found *pending
	for _, p := range in.pending {
		if !p.device {
			continue
		}
		fp, err := linkFingerprint(p.inv.rec.secret, in.pub, p.joiner)
		if err != nil {
			return DeviceMatch{}, fmt.Errorf("invite: fingerprint: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(normalizeDigits(fp)), []byte(typed)) == 1 {
			found = p
		}
	}
	if found == nil {
		return DeviceMatch{}, ErrFingerprint
	}
	d, err := decodeLinkData(found.data, in.opts.MaxDeviceName)
	if err != nil {
		return DeviceMatch{}, err
	}
	return DeviceMatch{req: found.id, inv: found.inv.id, joiner: bytes.Clone(found.joiner), name: d.name}, nil
}

// matchLocked returns the pending request a match names, if it is still that one.
func (in *Inviter) matchLocked(m DeviceMatch) (*pending, error) {
	if m.req == 0 {
		return nil, fmt.Errorf("%w: a zero match", ErrInvalidArgument)
	}
	p, err := in.pendingLocked(m.req)
	if err != nil {
		return nil, err
	}
	if !p.device || p.inv.id != m.inv || !p.joiner.Equal(m.joiner) {
		return nil, ErrNotFound
	}
	// the same key may ask again with another name: what the person matched is what they saw, so a changed request is a new one
	if d, err := decodeLinkData(p.data, in.opts.MaxDeviceName); err != nil || d.name != m.name {
		return nil, fmt.Errorf("%w: the request changed after it was matched", ErrNotFound)
	}
	return p, nil
}

// DeviceApproval is the choices of ApproveDevice.
type DeviceApproval struct {
	// Signer is the approving device's identity; its key must be the Inviter's.
	Signer *koloid.Identity
	// Cert is the approver certificate of Signer.
	Cert *koloid.DeviceCert
	// Serial is the serial of the new certificate, at least 1, chosen by the caller.
	Serial uint64
	// ExpiresAt is zero for a certificate that never expires.
	ExpiresAt time.Time
}

// ApproveDevice links the matched device as an ordinary device of the person of a.Cert. ErrNotApprover means a.Cert is not an
// unexpired approver certificate of a.Signer; the other errors are those of Approve. The signed offer reaches the new device
// inside the answer.
func (in *Inviter) ApproveDevice(m DeviceMatch, a *DeviceApproval) error {
	if a == nil || a.Signer == nil || a.Signer.PublicKey() == nil || a.Cert == nil {
		return fmt.Errorf("%w: nil approval, signer or certificate", ErrInvalidArgument)
	}
	if !a.Signer.PublicKey().Equal(in.pub) || !a.Cert.Device().Equal(in.pub) {
		return fmt.Errorf("%w: the signer and its certificate must be the inviter's key", ErrInvalidArgument)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	p, err := in.matchLocked(m)
	if err != nil {
		return err
	}
	if exp := a.Cert.ExpiresAt(); !exp.IsZero() && !exp.After(in.now()) {
		return fmt.Errorf("%w: %w", ErrNotApprover, koloid.ErrCertExpired)
	}
	// kolo-id refuses an ordinary certificate as a parent: that is where ErrNotApprover comes from.
	offer, err := a.Signer.OfferDeviceCert(p.joiner, &koloid.IssueOptions{Parent: a.Cert, Serial: a.Serial, ExpiresAt: a.ExpiresAt})
	if err != nil {
		return offerError(err)
	}
	return in.approveLocked(p, linkAnswer{person: a.Cert.Person(), offer: offer.Encode()}.encode())
}

func offerError(err error) error {
	if errors.Is(err, koloid.ErrNotApprover) {
		return fmt.Errorf("%w: %w", ErrNotApprover, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
}

// ApproverApproval is the choices of ApproveApprover.
type ApproverApproval struct {
	// Person derives the person key from the words the person typed on this device. It is called only after the match checks
	// pass, without the inviter's lock; its key is cleared before ApproveApprover returns, whatever the result.
	Person func() (*koloid.Identity, error)
	// ExpectPerson is the person key this device already belongs to; another key is ErrPersonMismatch and nothing is signed.
	ExpectPerson ed25519.PublicKey
	// FirstDevice says this device has no person yet, so there is nothing to expect. Exactly one of ExpectPerson and
	// FirstDevice is required (ErrPersonRequired): the person key cannot be checked otherwise.
	FirstDevice bool
	// Serial is the serial of the new certificate, at least 1, chosen by the caller.
	Serial uint64
	// ExpiresAt is zero for a certificate that never expires.
	ExpiresAt time.Time
}

// ApproveApprover links the matched device as an APPROVER of the person key a.Person derives, signed once and cleared at once. The
// words never reach this library or the network. The other errors are those of ApproveDevice.
func (in *Inviter) ApproveApprover(m DeviceMatch, a *ApproverApproval) error {
	if a == nil || a.Person == nil {
		return fmt.Errorf("%w: nil approval or person function", ErrInvalidArgument)
	}
	switch {
	case a.ExpectPerson == nil && !a.FirstDevice:
		return ErrPersonRequired
	case a.ExpectPerson != nil && (a.FirstDevice || len(a.ExpectPerson) != ed25519.PublicKeySize):
		return fmt.Errorf("%w: ExpectPerson and FirstDevice together, or a short key", ErrInvalidArgument)
	}
	in.mu.Lock()
	p, err := in.matchLocked(m)
	in.mu.Unlock()
	if err != nil {
		return err
	}
	person, err := a.Person()
	if person != nil {
		defer person.Clear() // whatever came back with an error is cleared too
	}
	if err != nil {
		return fmt.Errorf("invite: person key: %w", err)
	}
	if person == nil {
		return fmt.Errorf("%w: no person key", ErrInvalidArgument)
	}
	pub := person.PublicKey()
	if pub == nil {
		return fmt.Errorf("%w: cleared person key", ErrInvalidArgument)
	}
	if a.ExpectPerson != nil && !a.ExpectPerson.Equal(pub) {
		return ErrPersonMismatch
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if p2, err := in.matchLocked(m); err != nil || p2 != p {
		return cmpErr(err, ErrNotFound)
	}
	offer, err := person.OfferDeviceCert(p.joiner, &koloid.IssueOptions{Serial: a.Serial, ExpiresAt: a.ExpiresAt, Approver: true})
	if err != nil {
		return offerError(err)
	}
	return in.approveLocked(p, linkAnswer{person: pub, offer: offer.Encode()}.encode())
}

// cmpErr returns err, or fallback when err is nil.
func cmpErr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

// linkFingerprint is the 12-digit code both screens show: HKDF-SHA256 (RFC 5869) over the invite secret, bound to the inviter and
// the device key, 8 bytes read as a number modulo 10^12.
func linkFingerprint(secret, inviter, device []byte) (string, error) {
	info := "kolo-invite/link-fingerprint/v0" + string(inviter) + string(device)
	b, err := hkdf.Key(sha256.New, secret, nil, info, 8)
	if err != nil {
		return "", err
	}
	n := fmt.Sprintf("%012d", binary.BigEndian.Uint64(b)%1_000_000_000_000)
	return n[0:3] + " " + n[3:6] + " " + n[6:9] + " " + n[9:12], nil
}

// DeviceFingerprint returns the fingerprint the new device shows for code, the inviter's key (its connection's remote key) and its
// own device key. The code must be the inviter's (Code.Matches), else ErrInvalidArgument.
func DeviceFingerprint(code Code, inviter, device ed25519.PublicKey) (string, error) {
	if code.c == nil || !code.Matches(inviter) || len(device) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: a code of another inviter, or a bad device key", ErrInvalidArgument)
	}
	return linkFingerprint(code.c.secret[:], inviter, device)
}

// DeviceJoinOptions sets what JoinDevice sends and accepts.
type DeviceJoinOptions struct {
	// Name is the name the approver sees; required, letters, numbers, marks, punctuation, symbols and single spaces.
	Name string
	// MaxName is the longest Name in bytes: default DefaultMaxDeviceName. An inviter with a smaller Options.MaxDeviceName refuses
	// a longer one.
	MaxName int
	// MaxPayload bounds the answer JoinDevice accepts, in bytes: default DefaultMaxDevicePayload.
	MaxPayload int
	// Person is the person key the new device expects to join; another key is ErrProtocol.
	Person ed25519.PublicKey
	// FirstDevice says this device belongs to no person yet. Exactly one of Person and FirstDevice is required
	// (ErrPersonRequired): without a person to compare, the approver's person key cannot be checked.
	FirstDevice bool

	received func() // tests: called once the inviter's RECEIVED is read
}

// DeviceLink is the result of JoinDevice.
type DeviceLink struct {
	// Person is the person key the certificate chains to: pin it as the person.
	Person ed25519.PublicKey
	// Cert is the finished certificate; Cert.Approver() is true only when the person key signed it (ApproveApprover).
	Cert *koloid.DeviceCert
}

// JoinDevice asks the inviter of a link-a-device code, on conn, to link id as a device, waits for the approval and returns the
// certificate, after it checked it. Show DeviceFingerprint on screen before calling it. The errors are those of JoinConn; a
// certificate that fails a check is ErrProtocol. The checks are in docs/guide.md.
func JoinDevice(ctx context.Context, conn koloswarm.Conn, id *koloid.Identity, code Code, o *DeviceJoinOptions) (*DeviceLink, error) {
	if o == nil || id == nil || id.PublicKey() == nil || conn == nil || o.MaxName < 0 || o.MaxPayload < 0 {
		return nil, fmt.Errorf("%w: nil options, identity or connection, or a negative bound", ErrInvalidArgument)
	}
	maxName, maxPayload := cmp.Or(o.MaxName, DefaultMaxDeviceName), cmp.Or(o.MaxPayload, DefaultMaxDevicePayload)
	if checkName(o.Name, maxName) != nil {
		return nil, fmt.Errorf("%w: a bad name", ErrInvalidArgument)
	}
	switch {
	case o.Person == nil && !o.FirstDevice:
		return nil, ErrPersonRequired
	case o.Person != nil && (o.FirstDevice || len(o.Person) != ed25519.PublicKeySize):
		return nil, fmt.Errorf("%w: Person and FirstDevice together, or a short key", ErrInvalidArgument)
	}
	payload, err := JoinConn(ctx, conn, id, code, &JoinOptions{Data: linkData{name: o.Name}.encode(),
		MaxPayload: maxPayload, received: o.received})
	if err != nil {
		return nil, err
	}
	return acceptDeviceAnswer(id, conn.RemotePublicKey(), o.Person, payload)
}

// acceptDeviceAnswer checks the payload of an accepted link request, sent by the inviter with key inviter, and completes the
// certificate with id; expect is the person the caller pinned, if any.
func acceptDeviceAnswer(id *koloid.Identity, inviter, expect ed25519.PublicKey, payload []byte) (*DeviceLink, error) {
	bad := func(why string) error { return fmt.Errorf("%w: link answer: %s", ErrProtocol, why) }
	a, err := decodeLinkAnswer(payload)
	if err != nil {
		return nil, err
	}
	if expect != nil && !expect.Equal(a.person) {
		return nil, bad("another person than expected")
	}
	offer, err := koloid.DecodeCertOffer(a.offer)
	if err != nil {
		return nil, bad("offer does not decode")
	}
	cert, err := id.AcceptDeviceCert(offer, a.person)
	if err != nil {
		return nil, fmt.Errorf("%w: link answer: %w", ErrProtocol, err)
	}
	if issuer := cert.Issuer(); !issuer.Equal(inviter) && !issuer.Equal(a.person) {
		return nil, bad("certificate signed by a third key")
	}
	return &DeviceLink{Person: bytes.Clone(a.person), Cert: cert}, nil
}
