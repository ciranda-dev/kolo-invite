package invite

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
)

// approver returns a new person key and an approver certificate of the inviter's identity.
func (e *env) approver() (*koloid.Identity, *koloid.DeviceCert) {
	e.t.Helper()
	person := generate(e.t)
	offer, err := person.OfferDeviceCert(e.id.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	if err != nil {
		e.t.Fatal(err)
	}
	cert, err := e.id.AcceptDeviceCert(offer, person.PublicKey())
	if err != nil {
		e.t.Fatal(err)
	}
	return person, cert
}

func (e *env) createDevice(o *DeviceOptions) (Code, Info) {
	e.t.Helper()
	s, info, err := e.in.CreateDevice(o)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := Parse(s)
	if err != nil {
		e.t.Fatal(err)
	}
	return c, info
}

type linkResult struct {
	link *DeviceLink
	err  error
}

// link runs JoinDevice of id on a new connection in the background; person is the key the device expects, nil for a first
// device. got is closed once the inviter has received the request.
func (e *env) link(ctx context.Context, id *koloid.Identity, code Code, name string, person []byte) (got <-chan struct{}, done <-chan linkResult) {
	g, d := make(chan struct{}), make(chan linkResult, 1)
	c := e.dial(id)
	go func() {
		l, err := JoinDevice(ctx, c, id, code, &DeviceJoinOptions{Name: name, Person: person, FirstDevice: person == nil, received: func() { close(g) }})
		d <- linkResult{l, err}
	}()
	return g, d
}

// nextRequest returns what an approver shows for the pending request the next event reports.
func (e *env) nextRequest() LinkRequest {
	e.t.Helper()
	ev := e.next()
	if ev.Kind != Requested {
		e.t.Fatalf("event = %+v, want Requested", ev)
	}
	r, err := e.in.PendingLink(ev.Request)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// shown is the fingerprint the new device of r shows on its own screen.
func (e *env) shown(r LinkRequest) string {
	e.t.Helper()
	e.in.mu.Lock()
	defer e.in.mu.Unlock()
	fp, err := linkFingerprint(e.in.invites[r.Invite].rec.secret, e.id.PublicKey(), r.Device)
	if err != nil {
		e.t.Fatal(err)
	}
	return fp
}

// match types the fingerprint the new device of r shows.
func (e *env) match(r LinkRequest) DeviceMatch {
	e.t.Helper()
	m, err := e.in.MatchDevice(e.shown(r))
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

func (e *env) approveDevice(r LinkRequest, cert *koloid.DeviceCert, serial uint64) error {
	return e.in.ApproveDevice(e.match(r), &DeviceApproval{Signer: e.id, Cert: cert, Serial: serial})
}

// derived is a Person function that returns p and counts its calls.
func derived(p *koloid.Identity, calls *int) func() (*koloid.Identity, error) {
	return func() (*koloid.Identity, error) {
		if calls != nil {
			*calls++
		}
		return p, nil
	}
}

func result(t *testing.T, done <-chan linkResult) linkResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("JoinDevice did not return")
		return linkResult{}
	}
}

func TestLinkDeviceOrdinary(t *testing.T) {
	e := newEnv(t, nil)
	person, cert := e.approver()
	code, info := e.createDevice(nil)
	if !info.Device || !info.Manual || info.MaxUses != 1 || !info.Expires.Equal(e.clk.now().Add(DefaultDeviceTTL)) {
		t.Fatalf("info = %+v", info)
	}
	dev := generate(t)
	shown, err := DeviceFingerprint(code, e.id.PublicKey(), dev.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	_, done := e.link(e.ctx, dev, code, "Maria's phone", person.PublicKey())
	r := e.nextRequest()
	if r.Name != "Maria's phone" || !r.Device.Equal(dev.PublicKey()) || r.Invite != code.ID() {
		t.Fatalf("request = %+v", r)
	}
	// The person types what the new device shows.
	m, err := e.in.MatchDevice(shown)
	if err != nil || m.Request() != r.Request {
		t.Fatalf("MatchDevice = %+v, %v", m, err)
	}
	if err := e.in.ApproveDevice(m, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 7}); err != nil {
		t.Fatal(err)
	}
	res := result(t, done)
	if res.err != nil {
		t.Fatal(res.err)
	}
	l := res.link
	if !l.Person.Equal(person.PublicKey()) || l.Cert.Approver() || l.Cert.Serial() != 7 || !l.Cert.Device().Equal(dev.PublicKey()) ||
		!l.Cert.Issuer().Equal(e.id.PublicKey()) {
		t.Fatalf("link = %+v", l)
	}
	msg, _ := dev.Sign("test/msg/v0", []byte("hi"))
	if err := koloid.VerifyDevice(l.Cert, &koloid.VerifyOptions{Person: person.PublicKey()}, "test/msg/v0", []byte("hi"), msg); err != nil {
		t.Fatal(err)
	}
	if ev := e.next(); ev.Kind != Joined || !ev.Joiner.Equal(dev.PublicKey()) || ev.Request != r.Request {
		t.Fatalf("event = %+v", ev)
	}
	if ev := e.next(); ev.Kind != Ended || ev.State != UsedUp {
		t.Fatalf("event = %+v", ev)
	}
	// A second device with the same code finds it used up.
	if _, err := JoinDevice(e.ctx, e.dial(generate(t)), generate(t), code, &DeviceJoinOptions{Name: "x", FirstDevice: true}); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("second device = %v, want ErrUsedUp", err)
	}
}

func TestLinkDeviceApproverByWords(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	ph, err := koloid.GeneratePhrase()
	if err != nil {
		t.Fatal(err)
	}
	words := ph.Words()
	sentence := strings.Join(words, " ")
	person, err := ph.Person()
	if err != nil {
		t.Fatal(err)
	}
	ph.Clear()
	pub := person.PublicKey()
	dev := generate(t)
	c := e.dial(dev)
	var payload []byte
	jerr := make(chan error, 1)
	go func() {
		var err error
		payload, err = JoinConn(e.ctx, c, dev, code, &JoinOptions{Data: linkData{name: "laptop"}.encode()})
		jerr <- err
	}()
	ev := e.next()
	r, err := e.in.PendingLink(ev.Request)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := e.in.ApproveApprover(e.match(r), &ApproverApproval{Person: derived(person, &calls), ExpectPerson: pub, Serial: 1}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("Person was called %d times", calls)
	}
	if person.PublicKey() != nil {
		t.Fatal("the person key was not cleared")
	}
	if err := <-jerr; err != nil {
		t.Fatal(err)
	}
	l, err := acceptDeviceAnswer(dev, e.id.PublicKey(), pub, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Cert.Approver() || !l.Person.Equal(pub) || !l.Cert.Issuer().Equal(pub) {
		t.Fatalf("link = %+v", l)
	}
	// The words are in no message, event, stored value or key.
	secrets := []string{sentence}
	for _, w := range words {
		if len(w) >= 5 {
			secrets = append(secrets, w)
		}
	}
	seen := [][]byte{payload, ev.Data}
	if err := e.db.Scan(nil, nil, false, 0, func(k, v []byte) bool { seen = append(seen, append(bytes.Clone(k), v...)); return true }); err != nil {
		t.Fatal(err)
	}
	for _, b := range seen {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("a message or stored value contains a word of the phrase")
			}
		}
	}
}

func TestApproverByWordsErrorsClearTheKey(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, done := e.link(e.ctx, dev, code, "tablet", nil)
	r := e.nextRequest()
	m := e.match(r)
	for name, a := range map[string]func(p *koloid.Identity) *ApproverApproval{
		"wrong person": func(p *koloid.Identity) *ApproverApproval {
			return &ApproverApproval{Person: derived(p, nil), ExpectPerson: generate(t).PublicKey(), Serial: 1}
		},
		"zero serial": func(p *koloid.Identity) *ApproverApproval {
			return &ApproverApproval{Person: derived(p, nil), FirstDevice: true}
		},
	} {
		p := generate(t)
		err := e.in.ApproveApprover(m, a(p))
		if err == nil {
			t.Fatalf("%s: approved", name)
		}
		if p.PublicKey() != nil {
			t.Errorf("%s: the person key was not cleared", name)
		}
		if name == "wrong person" && !errors.Is(err, ErrPersonMismatch) {
			t.Errorf("%s: %v", name, err)
		}
		if name == "zero serial" && !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A function that fails, that returns no key and a cleared key.
	boom := errors.New("typed words were wrong")
	if err := e.in.ApproveApprover(m, &ApproverApproval{FirstDevice: true, Serial: 1,
		Person: func() (*koloid.Identity, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Errorf("failing Person = %v", err)
	}
	if err := e.in.ApproveApprover(m, &ApproverApproval{FirstDevice: true, Serial: 1,
		Person: func() (*koloid.Identity, error) { return nil, nil }}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("no key = %v", err)
	}
	cleared := generate(t)
	cleared.Clear()
	if err := e.in.ApproveApprover(m, &ApproverApproval{Person: derived(cleared, nil), FirstDevice: true, Serial: 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("cleared = %v", err)
	}
	// Nothing was sent: the request is still pending and can be refused.
	if s := e.in.Stats(); s.Pending != 1 || s.Accepted != 0 {
		t.Fatalf("Stats = %+v", s)
	}
	if err := e.in.Deny(r.Request); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); !errors.Is(res.err, ErrDenied) {
		t.Fatalf("join = %v", res.err)
	}
}

// TestApproverPersonIsCalledLast: the function that derives the person key does not run unless every check before it passed.
func TestApproverPersonIsCalledLast(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "tablet", nil)
	r := e.nextRequest()
	m := e.match(r)
	calls := 0
	approval := func() *ApproverApproval {
		return &ApproverApproval{Person: derived(generate(t), &calls), FirstDevice: true, Serial: 1}
	}
	// A typed fingerprint that does not match gives no match to approve with.
	if _, err := e.in.MatchDevice("000 000 000 000"); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("MatchDevice = %v", err)
	}
	// Neither a zero match, nor options without a person to expect, call it.
	if err := e.in.ApproveApprover(DeviceMatch{}, approval()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero match = %v", err)
	}
	if err := e.in.ApproveApprover(m, &ApproverApproval{Person: derived(generate(t), &calls), Serial: 1}); !errors.Is(err, ErrPersonRequired) {
		t.Fatalf("no expected person = %v", err)
	}
	if err := e.in.ApproveApprover(m, &ApproverApproval{Person: derived(generate(t), &calls), FirstDevice: true,
		ExpectPerson: generate(t).PublicKey(), Serial: 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("both = %v", err)
	}
	// A match of a request that is not a device request, or that is gone, does not call it either.
	plain, _ := e.create(&CreateOptions{Manual: true})
	pid := generate(t)
	_, pdone := e.joinReceived(e.dial(pid), pid, plain)
	pev := e.next()
	forged := DeviceMatch{req: pev.Request, inv: plain.ID(), joiner: pid.PublicKey()}
	if err := e.in.ApproveApprover(forged, approval()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("match of a plain request = %v", err)
	}
	if err := e.in.ApproveApprover(DeviceMatch{req: 9999, inv: code.ID(), joiner: pid.PublicKey()}, approval()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("match of nothing = %v", err)
	}
	if err := e.in.ApproveApprover(DeviceMatch{req: r.Request, inv: code.ID(), joiner: pid.PublicKey()}, approval()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("match with another joiner = %v", err)
	}
	if calls != 0 {
		t.Fatalf("Person was called %d times before the checks passed", calls)
	}
	e.in.Deny(pev.Request)
	<-pdone
	// The request goes away while the key is derived: nothing is signed and the key is cleared.
	p := generate(t)
	err := e.in.ApproveApprover(m, &ApproverApproval{FirstDevice: true, Serial: 1, Person: func() (*koloid.Identity, error) {
		if err := e.in.Deny(r.Request); err != nil {
			t.Error(err)
		}
		return p, nil
	}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("approval of a request that went away = %v, want ErrNotFound", err)
	}
	if p.PublicKey() != nil {
		t.Fatal("the key was not cleared")
	}
	if res := result(t, done); !errors.Is(res.err, ErrDenied) {
		t.Fatalf("join = %v", res.err)
	}
}

func TestMatchDevice(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code1, _ := e.createDevice(nil)
	code2, _ := e.createDevice(nil)
	a, b := generate(t), generate(t)
	_, doneA := e.link(e.ctx, a, code1, "same name", nil)
	ra := e.nextRequest()
	_, doneB := e.link(e.ctx, b, code2, "same name", nil)
	rb := e.nextRequest()
	fa, _ := DeviceFingerprint(code1, e.id.PublicKey(), a.PublicKey())
	fb, _ := DeviceFingerprint(code2, e.id.PublicKey(), b.PublicKey())
	for name, typed := range map[string]string{
		"empty": "", "short": fa[:7], "long": fa + "0", "zeros": "000 000 000 000", "letters": "abc def ghi jkl",
		"of nothing": "123 456 789 012", "with a typo": fa[:len(fa)-1] + string(rune('0'+(fa[len(fa)-1]-'0'+1)%10)),
	} {
		if m, err := e.in.MatchDevice(typed); !errors.Is(err, ErrFingerprint) || m.Request() != 0 {
			t.Errorf("%s: %+v, %v; want ErrFingerprint", name, m, err)
		}
	}
	// The digits pick the request among two with one name, with or without the spaces.
	mb, err := e.in.MatchDevice(strings.ReplaceAll(fb, " ", ""))
	if err != nil || mb.Request() != rb.Request {
		t.Fatalf("MatchDevice(b) = %+v, %v", mb, err)
	}
	ma, err := e.in.MatchDevice(fa)
	if err != nil || ma.Request() != ra.Request {
		t.Fatalf("MatchDevice(a) = %+v, %v", ma, err)
	}
	// A request of an ordinary Manual invite is not matched, whatever it is typed as.
	plain, _ := e.create(&CreateOptions{Manual: true})
	pid := generate(t)
	_, pdone := e.joinReceived(e.dial(pid), pid, plain)
	pev := e.next()
	if _, err := e.in.MatchDevice("000 000 000 000"); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("with a plain request pending = %v", err)
	}
	// Not even the digits such a request would have: only link-a-device requests are matched.
	plainFP, err := linkFingerprint(plain.c.secret[:], e.id.PublicKey(), pid.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if m, err := e.in.MatchDevice(plainFP); !errors.Is(err, ErrFingerprint) || m.Request() != 0 {
		t.Fatalf("the digits of a plain request matched: %+v, %v", m, err)
	}
	e.in.Deny(pev.Request)
	<-pdone
	if err := e.in.ApproveDevice(ma, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); err != nil {
		t.Fatal(err)
	}
	if res := result(t, doneA); res.err != nil {
		t.Fatal(res.err)
	}
	// The match is used up with its request.
	if err := e.in.ApproveDevice(ma, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve again = %v", err)
	}
	if err := e.in.ApproveDevice(DeviceMatch{}, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero match = %v", err)
	}
	e.in.Deny(rb.Request)
	result(t, doneB)
	e.in.Close()
	if _, err := e.in.MatchDevice(fa); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed = %v", err)
	}
}

func TestFingerprintDerivation(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	a, b := generate(t), generate(t)
	fa, err := DeviceFingerprint(code, e.id.PublicKey(), a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := DeviceFingerprint(code, e.id.PublicKey(), b.PublicKey())
	if fa == fb {
		t.Fatal("two device keys share a fingerprint")
	}
	if len(fa) != 15 || fa[3] != ' ' || fa[7] != ' ' || fa[11] != ' ' {
		t.Fatalf("fingerprint %q is not four groups of three digits", fa)
	}
	for _, r := range strings.ReplaceAll(fa, " ", "") {
		if r < '0' || r > '9' {
			t.Fatalf("fingerprint %q is not digits", fa)
		}
	}
	other, _ := e.createDevice(nil)
	if fo, _ := DeviceFingerprint(other, e.id.PublicKey(), a.PublicKey()); fo == fa {
		t.Fatal("two invites share a fingerprint")
	}
	if _, err := DeviceFingerprint(code, generate(t).PublicKey(), a.PublicKey()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("other inviter = %v", err)
	}
	if _, err := DeviceFingerprint(code, e.id.PublicKey(), a.PublicKey()[:31]); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("short key = %v", err)
	}
	if _, err := DeviceFingerprint(Code{}, e.id.PublicKey(), a.PublicKey()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero code = %v", err)
	}
	inviterA, _ := linkFingerprint(code.c.secret[:], e.id.PublicKey(), a.PublicKey())
	inviterB, _ := linkFingerprint(code.c.secret[:], generate(t).PublicKey(), a.PublicKey())
	if inviterA != fa || inviterA == inviterB {
		t.Fatal("the fingerprint does not bind the inviter key")
	}
}

// TestFingerprintKnownAnswer checks linkFingerprint against HKDF-SHA256 (RFC 5869) written out with HMAC.
func TestFingerprintKnownAnswer(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	inviter := bytes.Repeat([]byte{0x22}, 32)
	device := bytes.Repeat([]byte{0x33}, 32)
	prk := hmacSHA256(make([]byte, 32), secret)
	info := append(append([]byte("kolo-invite/link-fingerprint/v0"), inviter...), device...)
	okm := hmacSHA256(prk, append(info, 1))[:8]
	var n uint64
	for _, c := range okm {
		n = n<<8 | uint64(c)
	}
	d := make([]byte, 12)
	n %= 1_000_000_000_000
	for i := 11; i >= 0; i-- {
		d[i] = byte('0' + n%10)
		n /= 10
	}
	want := string(d[0:3]) + " " + string(d[3:6]) + " " + string(d[6:9]) + " " + string(d[9:12])
	if got, err := linkFingerprint(secret, inviter, device); err != nil || got != want {
		t.Fatalf("fingerprint = %q, %v; want %q", got, err, want)
	}
}

func TestDenyBurnsTheCode(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, done := e.link(e.ctx, dev, code, "phone", nil)
	r := e.nextRequest()
	if err := e.in.Deny(r.Request); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); !errors.Is(res.err, ErrDenied) {
		t.Fatalf("join = %v, want ErrDenied", res.err)
	}
	if ev := e.next(); ev.Kind != Ended || ev.State != Revoked {
		t.Fatalf("event = %+v", ev)
	}
	if l := e.list(); l[0].State != Revoked || l[0].Used != 0 {
		t.Fatalf("List = %+v", l)
	}
	if _, err := JoinDevice(e.ctx, e.dial(generate(t)), generate(t), code, &DeviceJoinOptions{Name: "x", FirstDevice: true}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("second device = %v, want ErrRevoked", err)
	}
	if _, err := JoinDevice(e.ctx, e.dial(dev), dev, code, &DeviceJoinOptions{Name: "phone", FirstDevice: true}); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied device again = %v, want ErrDenied", err)
	}
}

// TestBurnSurvivesAFailingDisk: the end of a burned code holds in memory at once, and the clock stores it when the disk works.
func TestBurnSurvivesAFailingDisk(t *testing.T) {
	e := newEnv(t, nil)
	e.stopFn()
	f := &faulty{Backend: e.db}
	e.db = f
	e.start(nil)
	code, info := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	f.putOnly.Store(int32(pInvite))
	f.fail.Store(true)
	if err := e.in.Deny(r.Request); err != nil {
		t.Fatalf("Deny with a failing disk = %v", err)
	}
	if res := result(t, done); !errors.Is(res.err, ErrDenied) {
		t.Fatalf("join = %v", res.err)
	}
	if l := e.list(); l[0].State != Revoked {
		t.Fatalf("the code is not burned in memory: %+v", l)
	}
	if _, err := JoinDevice(e.ctx, e.dial(generate(t)), generate(t), code, &DeviceJoinOptions{Name: "x", FirstDevice: true}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a burned code on a failing disk = %v, want ErrRevoked", err)
	}
	stored := func() bool {
		b, err := e.db.Get(inviteKey(info.ID))
		if err != nil {
			t.Fatal(err)
		}
		r, err := decodeRecord(info.ID, b)
		if err != nil {
			t.Fatal(err)
		}
		return r.revoked
	}
	if stored() {
		t.Fatal("the end was stored on a failing disk")
	}
	f.fail.Store(false)
	signal(e.in.wake)
	eventually(t, "the end to be stored", stored)
}

func TestPendingTimeoutBurnsTheCode(t *testing.T) {
	e := newEnv(t, &Options{DevicePendingTTL: 200 * time.Millisecond, PendingTTL: time.Hour})
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, done := e.link(e.ctx, dev, code, "phone", nil)
	// The approver is offline: nobody reads the request.
	if res := result(t, done); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("join = %v, want ErrNotAnswered", res.err)
	}
	eventually(t, "the code to be burned", func() bool { return e.list()[0].State == Revoked })
	if _, err := JoinDevice(e.ctx, e.dial(dev), dev, code, &DeviceJoinOptions{Name: "phone", FirstDevice: true}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("again = %v, want ErrRevoked", err)
	}
	if s := e.in.Stats(); s.Pending != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

// TestRetakeDoesNotBurn: a joiner that asks again takes over its pending request; the old wait ends without withdrawing it, so the
// timer of the old wait does not burn the code.
func TestRetakeDoesNotBurn(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, first := e.link(e.ctx, dev, code, "first name", nil)
	r1 := e.nextRequest()
	e.in.mu.Lock()
	var p *pending
	for _, x := range e.in.pending {
		p = x
	}
	old := p.answer
	e.in.mu.Unlock()
	// The channel of the wait that the retake will end: a takeover sends it a zero answer.
	stale := make(chan answer, 1)
	stale <- answer{}
	// The same device asks again on another connection, with another name.
	_, second := e.link(e.ctx, dev, code, "second name", nil)
	if res := result(t, first); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("the first wait = %v, want ErrNotAnswered", res.err)
	}
	// The old wait now reaches its timer: it did not withdraw, so it reports so and the code stays alive.
	if a, withdrew := e.in.withdraw(p, stale); withdrew || a.kind != 0 {
		t.Fatalf("withdraw of the old wait = %+v, %v", a, withdrew)
	}
	if l := e.list(); l[0].State != Active {
		t.Fatalf("List = %+v", l)
	}
	// The approver sees the new request's name, under the same request ID.
	e.in.mu.Lock()
	for len(e.in.pending) != 1 || e.in.pending[r1.Request].answer == old {
		e.in.mu.Unlock()
		time.Sleep(time.Millisecond)
		e.in.mu.Lock()
	}
	e.in.mu.Unlock()
	l, err := e.in.PendingLink(r1.Request)
	if err != nil || l.Name != "second name" {
		t.Fatalf("PendingLink after the retake = %+v, %v", l, err)
	}
	if err := e.in.ApproveDevice(e.match(l), &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); err != nil {
		t.Fatal(err)
	}
	if res := result(t, second); res.err != nil {
		t.Fatal(res.err)
	}
}

func TestPendingTTLDoesNotApplyToADeviceRequest(t *testing.T) {
	e := newEnv(t, &Options{DevicePendingTTL: time.Hour, PendingTTL: 200 * time.Millisecond})
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	// A request of an ordinary Manual invite is withdrawn by PendingTTL; the device request, older, is still waiting by then.
	plain, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	_, jd := e.joinReceived(e.dial(id), id, plain)
	if err := <-jd; !errors.Is(err, ErrNotAnswered) {
		t.Fatalf("join = %v", err)
	}
	if s := e.in.Stats(); s.Pending != 1 {
		t.Fatalf("Stats = %+v", s)
	}
	for _, i := range e.list() {
		if i.State != Active {
			t.Fatalf("List = %+v", e.list())
		}
	}
	if err := e.in.Deny(r.Request); err != nil {
		t.Fatal(err)
	}
	result(t, done)
}

func TestCancelDoesNotBurnTheCode(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	dev := generate(t)
	ctx, cancel := context.WithCancel(e.ctx)
	got, done := e.link(ctx, dev, code, "phone", nil)
	r := e.nextRequest()
	m := e.match(r)
	<-got // RECEIVED is read: leaving now is a cancel of a received request
	cancel()
	if res := result(t, done); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("join = %v, want ErrNotAnswered", res.err)
	}
	if ev := e.next(); ev.Kind != Withdrawn || ev.Request != r.Request {
		t.Fatalf("event = %+v, want Withdrawn", ev)
	}
	if err := e.in.ApproveDevice(m, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve after cancel = %v, want ErrNotFound", err)
	}
	if l := e.list(); l[0].State != Active {
		t.Fatalf("List = %+v", l)
	}
	dev2 := generate(t)
	_, done2 := e.link(e.ctx, dev2, code, "phone", nil)
	r2 := e.nextRequest()
	if err := e.approveDevice(r2, cert, 1); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done2); res.err != nil {
		t.Fatal(res.err)
	}
}

func TestTwoDevicesRaceForOneCode(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	a, b := generate(t), generate(t)
	_, doneA := e.link(e.ctx, a, code, "A", nil)
	_, doneB := e.link(e.ctx, b, code, "B", nil)
	r1, r2 := e.nextRequest(), e.nextRequest()
	m1, m2 := e.match(r1), e.match(r2)
	if m1.Request() == m2.Request() {
		t.Fatal("two requests share a match")
	}
	if err := e.in.ApproveDevice(m1, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); err != nil {
		t.Fatal(err)
	}
	// The other request is answered used up and cannot be approved any more.
	if err := e.in.ApproveDevice(m2, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("approve of the loser = %v, want ErrUsedUp", err)
	}
	var winner, loser linkResult
	if r1.Device.Equal(a.PublicKey()) {
		winner, loser = result(t, doneA), result(t, doneB)
	} else {
		winner, loser = result(t, doneB), result(t, doneA)
	}
	if winner.err != nil || !winner.link.Cert.Device().Equal(r1.Device) {
		t.Fatalf("winner = %+v", winner)
	}
	if !errors.Is(loser.err, ErrUsedUp) {
		t.Fatalf("loser = %v, want ErrUsedUp", loser.err)
	}
	if l := e.list(); l[0].Used != 1 {
		t.Fatalf("List = %+v", l)
	}
}

func TestFloodOfPendingRequests(t *testing.T) {
	e := newEnv(t, &Options{MaxPendingDevices: 2})
	code, _ := e.createDevice(nil)
	other, _ := e.createDevice(nil)
	var dones []<-chan linkResult
	for _, c := range []Code{code, other} {
		_, d := e.link(e.ctx, generate(t), c, "x", nil)
		e.nextRequest()
		dones = append(dones, d)
	}
	// The limit counts the requests of all device invites; the next one is refused at once.
	if _, err := JoinDevice(e.ctx, e.dial(generate(t)), generate(t), code, &DeviceJoinOptions{Name: "flood", FirstDevice: true}); !errors.Is(err, ErrBusy) {
		t.Fatalf("third request = %v, want ErrBusy", err)
	}
	if s := e.in.Stats(); s.Pending != 2 || s.RefusedBusy != 1 {
		t.Fatalf("Stats = %+v", s)
	}
	plain, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	_, jd := e.joinReceived(e.dial(id), id, plain)
	ev := e.next()
	if ev.Kind != Requested {
		t.Fatalf("event = %+v", ev)
	}
	if err := e.in.Deny(ev.Request); err != nil {
		t.Fatal(err)
	}
	<-jd
	for _, c := range []Code{code, other} {
		if err := e.in.Revoke(c.ID()); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range dones {
		if res := result(t, d); !errors.Is(res.err, ErrRevoked) {
			t.Fatalf("join = %v, want ErrRevoked", res.err)
		}
	}
}

func TestPlainRequestsDoNotUseDeviceSlots(t *testing.T) {
	e := newEnv(t, &Options{MaxPendingDevices: 1})
	plain, _ := e.create(&CreateOptions{Manual: true, MaxUses: 3})
	id := generate(t)
	_, jd := e.joinReceived(e.dial(id), id, plain)
	pev := e.next()
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	if s := e.in.Stats(); s.Pending != 2 {
		t.Fatalf("Stats = %+v", s)
	}
	e.in.Deny(r.Request)
	result(t, done)
	e.in.Deny(pev.Request)
	<-jd
}

func TestOnlyAnApproverMayApprove(t *testing.T) {
	person, approver, stolen := generate(t), generate(t), generate(t)
	aOffer, _ := person.OfferDeviceCert(approver.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	approverCert, err := approver.AcceptDeviceCert(aOffer, person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// The stolen device is an ordinary device of the person, certified by the approver.
	offer, _ := approver.OfferDeviceCert(stolen.PublicKey(), &koloid.IssueOptions{Parent: approverCert, Serial: 1})
	ordinary, err := stolen.AcceptDeviceCert(offer, person.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	se := newEnvAs(t, stolen, nil, Linger)
	code, _ := se.createDevice(nil)
	dev := generate(t)
	_, done := se.link(se.ctx, dev, code, "thief's phone", nil)
	r := se.nextRequest()
	m := se.match(r)
	if err := se.in.ApproveDevice(m, &DeviceApproval{Signer: stolen, Cert: ordinary, Serial: 1}); !errors.Is(err, ErrNotApprover) {
		t.Fatalf("an ordinary device approved: %v", err)
	}
	// Nor can it pass the approver certificate of another device: the certificate must be the signer's own.
	if err := se.in.ApproveDevice(m, &DeviceApproval{Signer: stolen, Cert: approverCert, Serial: 1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("another device's approver certificate = %v", err)
	}
	// kolo-id refuses too: that refusal is where ErrNotApprover comes from.
	if _, err := stolen.OfferDeviceCert(dev.PublicKey(), &koloid.IssueOptions{Parent: ordinary, Serial: 1}); !errors.Is(err, koloid.ErrNotApprover) {
		t.Fatalf("OfferDeviceCert = %v", err)
	}
	if _, err := approver.OfferDeviceCert(dev.PublicKey(), &koloid.IssueOptions{Parent: approverCert, Serial: 1, Approver: true}); err == nil {
		t.Fatal("a certificate with a parent became an approver")
	}
	if s := se.in.Stats(); s.Accepted != 0 || s.Pending != 1 {
		t.Fatalf("Stats = %+v", s)
	}
	se.in.Deny(r.Request)
	result(t, done)
}

// TestApproveDeviceNeverMakesAnApprover checks the certificate that comes out of the ordinary path.
func TestApproveDeviceNeverMakesAnApprover(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	if err := e.approveDevice(r, cert, 1); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); res.err != nil || res.link.Cert.Approver() {
		t.Fatalf("link = %+v, %v", res.link, res.err)
	}
}

func TestApproveDeviceChecksItsArguments(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, done := e.link(e.ctx, dev, code, "phone", nil)
	r := e.nextRequest()
	m := e.match(r)
	good := func() *DeviceApproval { return &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1} }
	other, otherPerson := generate(t), generate(t)
	otherOffer, _ := otherPerson.OfferDeviceCert(other.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	otherCert, _ := other.AcceptDeviceCert(otherOffer, otherPerson.PublicKey())
	for name, mut := range map[string]func(*DeviceApproval){
		"no signer":          func(a *DeviceApproval) { a.Signer = nil },
		"no certificate":     func(a *DeviceApproval) { a.Cert = nil },
		"signer not inviter": func(a *DeviceApproval) { a.Signer = other },
		"cert of another":    func(a *DeviceApproval) { a.Cert = otherCert },
		"another approver":   func(a *DeviceApproval) { a.Signer, a.Cert = other, otherCert },
		"zero serial":        func(a *DeviceApproval) { a.Serial = 0 },
		"expiry before now":  func(a *DeviceApproval) { a.ExpiresAt = time.Unix(100, 0) },
	} {
		a := good()
		mut(a)
		if err := e.in.ApproveDevice(m, a); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	if err := e.in.ApproveDevice(m, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil: %v", err)
	}
	if err := e.in.ApproveDevice(DeviceMatch{req: 999, inv: code.ID(), joiner: dev.PublicKey()}, good()); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown request: %v", err)
	}
	if s := e.in.Stats(); s.Accepted != 0 {
		t.Fatalf("Stats = %+v", s)
	}
	if err := e.in.ApproveDevice(m, good()); err != nil {
		t.Fatal(err)
	}
	result(t, done)
}

func TestExpiredApproverCertificateRefused(t *testing.T) {
	e := newEnv(t, nil)
	person := generate(t)
	expires := e.clk.now().Add(time.Minute)
	offer, err := person.OfferDeviceCert(e.id.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true, IssuedAt: e.clk.now().Add(-time.Hour), ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := e.id.AcceptDeviceCert(offer, person.PublicKey())
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	e.clk.add(time.Minute)
	if err := e.approveDevice(r, cert, 1); !errors.Is(err, ErrNotApprover) || !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("approve with an expired certificate = %v", err)
	}
	e.clk.add(-time.Second)
	if err := e.approveDevice(r, cert, 1); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
	result(t, done)
}

func TestPlainApproveRefusedOnADeviceInvite(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	if err := e.in.Approve(r.Request, []byte("anything")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Approve = %v, want ErrInvalidArgument", err)
	}
	if s := e.in.Stats(); s.Accepted != 0 || s.Pending != 1 {
		t.Fatalf("Stats = %+v", s)
	}
	// PendingLink refuses a request of an ordinary Manual invite, and a match cannot name one.
	plain, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	_, jd := e.joinReceived(e.dial(id), id, plain)
	ev := e.next()
	if _, err := e.in.PendingLink(ev.Request); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("PendingLink of a plain request = %v", err)
	}
	forged := DeviceMatch{req: ev.Request, inv: plain.ID(), joiner: id.PublicKey()}
	if err := e.in.ApproveDevice(forged, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ApproveDevice of a plain request = %v", err)
	}
	e.in.Deny(ev.Request)
	<-jd
	if _, err := e.in.PendingLink(12345); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PendingLink of nothing = %v", err)
	}
	e.in.Deny(r.Request)
	result(t, done)
}

func TestDeviceInviteExpires(t *testing.T) {
	e := newEnv(t, nil)
	code, info := e.createDevice(&DeviceOptions{TTL: time.Minute})
	if !info.Expires.Equal(e.clk.now().Add(time.Minute)) {
		t.Fatalf("Expires = %v", info.Expires)
	}
	e.clk.add(time.Minute)
	dev := generate(t)
	if _, err := JoinDevice(e.ctx, e.dial(dev), dev, code, &DeviceJoinOptions{Name: "phone", FirstDevice: true}); !errors.Is(err, ErrExpired) {
		t.Fatalf("join after the TTL = %v, want ErrExpired", err)
	}
	if _, _, err := e.in.CreateDevice(&DeviceOptions{TTL: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("negative TTL = %v", err)
	}
	// Any positive TTL is the caller's choice.
	if _, info, err := e.in.CreateDevice(&DeviceOptions{TTL: 48 * time.Hour}); err != nil || !info.Expires.Equal(e.clk.now().Add(48*time.Hour)) {
		t.Fatalf("a long TTL = %+v, %v", info, err)
	}
	in2 := newEnv(t, nil)
	in2.in.Close()
	if _, _, err := in2.in.CreateDevice(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed = %v", err)
	}
}

func TestReplayedDeviceRequest(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	dev := generate(t)
	c := e.dial(dev)
	r1 := e.raw(c)
	nonce := r1.challenge()
	req := e.request(code, dev, linkData{name: "phone"}.encode(), nonce)
	r1.send(req)
	ev := e.next()
	if ev.Kind != Requested {
		t.Fatalf("event = %+v", ev)
	}
	// The same sealed request on a new stream, under the new challenge, does not open.
	r2 := e.raw(e.dial(generate(t)))
	r2.challenge()
	r2.send(req)
	r2.refused(refInvalid)
	if s := e.in.Stats(); s.Pending != 1 || s.RefusedInvalid != 1 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestDeviceRequestNameRules(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	long := strings.Repeat("a", DefaultMaxDeviceName+1)
	cases := map[string]string{
		"empty":                     "",
		"too long":                  long,
		"newline":                   "a\nb",
		"tab":                       "a\tb",
		"escape":                    "a\x1b[2Jb",
		"bidi override":             "ab\u202ecd",
		"zero width":                "a\u200bb",
		"invalid utf8":              "a\xffb",
		"line separator":            "a\u2028b",
		"paragraph separator":       "a\u2029b",
		"private use":               "a\ue000b",
		"replacement rune":          "a\ufffdb",
		"only spaces":               "   ",
		"one space":                 " ",
		"leading space":             " phone",
		"trailing space":            "phone ",
		"double space":              "my  phone",
		"no-break space":            "my\u00a0phone",
		"em space":                  "my\u2003phone",
		"ideographic space":         "my\u3000phone",
		"braille blank":             "\u2800",
		"hangul filler":             "\u3164",
		"hangul choseong fill":      "a\u115fb",
		"hangul jungseong fill":     "a\u1160b",
		"variation selector 16":     "a\ufe0fb",
		"variation selector 1":      "a\ufe00b",
		"variation selector sup":    "a\U000e0100b",
		"combining grapheme joiner": "a\u034fb",
		"mongolian selector 1":      "a\u180bb",
		"mongolian selector 3":      "a\u180db",
		"mongolian selector 4":      "a\u180fb",
		"tag character":             "a\U000e0041b",
		"khmer inherent vowel":      "a\u17b4b",
		"khmer inherent vowel aa":   "a\u17b5b",
		"halfwidth hangul filler":   "a\uffa0b",
		"only a mark":               "\u0301",
		"mark after a space":        "a \u0301",
		"soft hyphen":               "a\u00adb",
		"word joiner":               "a\u2060b",
	}
	for name, n := range cases {
		dev := generate(t)
		r := e.raw(e.dial(dev))
		nonce := r.challenge()
		t.Logf("name case %s", name)
		var enc []byte
		if name == "too long" || name == "invalid utf8" || name == "empty" {
			enc = append([]byte{version, byte(len(n))}, n...)
		} else {
			enc = linkData{name: n}.encode()
		}
		r.send(e.request(code, dev, enc, nonce))
		r.refused(refInvalid)
	}
	if s := e.in.Stats(); s.Pending != 0 || s.RefusedInvalid != uint64(len(cases)) {
		t.Fatalf("Stats = %+v", s)
	}
	good := linkData{name: "phone"}.encode()
	for name, data := range map[string][]byte{
		"none":     nil,
		"garbage":  {0xff, 0xff, 0xff},
		"version":  append([]byte{1}, good[1:]...),
		"trailing": append(bytes.Clone(good), 0),
	} {
		dev := generate(t)
		r := e.raw(e.dial(dev))
		r.send(e.request(code, dev, data, r.challenge()))
		r.refused(refInvalid)
		t.Logf("data case %s", name)
	}
	if s := e.in.Stats(); s.Pending != 0 {
		t.Fatalf("Stats = %+v", s)
	}
	// Names that are accepted: the longest one, accents, other scripts, symbols, emoji, a mark after a letter.
	for _, n := range []string{strings.Repeat("a", DefaultMaxDeviceName), "Maria's telefone Pixel 9", "Telefone da Mari\u00e1", "\u041c\u0430\u0440\u0438\u044f", "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35",
		"e\u0301cran", "phone #2 (work)", "\u260e phone", "\U0001f4f1 phone"} {
		dev := generate(t)
		_, d := e.link(e.ctx, dev, code, n, nil)
		r := e.nextRequest()
		if r.Name != n {
			t.Fatalf("name = %q, want %q", r.Name, n)
		}
		e.in.Deny(r.Request)
		result(t, d)
		if ev := e.next(); ev.Kind != Ended || ev.State != Revoked {
			t.Fatalf("event = %+v", ev)
		}
		code, _ = e.createDevice(nil)
	}
}

func TestDeviceInviteSurvivesARestart(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, info := e.createDevice(nil)
	e.stopFn()
	e.start(nil)
	l := e.list()
	if len(l) != 1 || !l[0].Device || !l[0].Manual || l[0].ID != info.ID || l[0].State != Active {
		t.Fatalf("List = %+v", l)
	}
	dev := generate(t)
	_, done := e.link(e.ctx, dev, code, "phone", nil)
	r := e.nextRequest()
	if err := e.in.Approve(r.Request, []byte("x")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Approve after a restart = %v", err)
	}
	if err := e.approveDevice(r, cert, 1); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); res.err != nil {
		t.Fatal(res.err)
	}
}

func TestApproverClosedWhilePending(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	got, done := e.link(e.ctx, generate(t), code, "phone", nil)
	e.nextRequest()
	<-got // the joiner has read RECEIVED: a closed inviter now leaves it unanswered, not unreachable
	e.stopFn()
	if res := result(t, done); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("join = %v, want ErrNotAnswered", res.err)
	}
}

func TestJoinDeviceChecksItsArguments(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	dev := generate(t)
	c := e.dial(dev)
	person := generate(t).PublicKey()
	for name, c := range map[string]struct {
		f    func() error
		want error
	}{
		"no options": {func() error { _, err := JoinDevice(e.ctx, c, dev, code, nil); return err }, ErrInvalidArgument},
		"no name": {func() error {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{FirstDevice: true})
			return err
		}, ErrInvalidArgument},
		"bad name": {func() error {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{Name: "a\nb", FirstDevice: true})
			return err
		}, ErrInvalidArgument},
		"no identity": {func() error {
			_, err := JoinDevice(e.ctx, c, nil, code, &DeviceJoinOptions{Name: "a", FirstDevice: true})
			return err
		}, ErrInvalidArgument},
		"no conn": {func() error {
			_, err := JoinDevice(e.ctx, nil, dev, code, &DeviceJoinOptions{Name: "a", FirstDevice: true})
			return err
		}, ErrInvalidArgument},
		"short person": {func() error {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{Name: "a", Person: []byte{1}})
			return err
		}, ErrInvalidArgument},
		"person and first device": {func() error {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{Name: "a", Person: person, FirstDevice: true})
			return err
		}, ErrInvalidArgument},
		"neither": {func() error {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{Name: "a"})
			return err
		}, ErrPersonRequired},
	} {
		if err := c.f(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// Nothing was sent by any of them.
	if s := e.in.Stats(); s.Requests != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestJoinDevicePinnedPerson(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", generate(t).PublicKey())
	r := e.nextRequest()
	if err := e.approveDevice(r, cert, 1); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); !errors.Is(res.err, ErrProtocol) {
		t.Fatalf("a device that expected another person = %v, want ErrProtocol", res.err)
	}
}

// TestApproveApproverNeedsAnExpectedPerson: without the person the device belongs to, a mistyped phrase could not be told.
func TestApproveApproverNeedsAnExpectedPerson(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "tablet", nil)
	r := e.nextRequest()
	calls := 0
	if err := e.in.ApproveApprover(e.match(r), &ApproverApproval{Person: derived(generate(t), &calls), Serial: 1}); !errors.Is(err, ErrPersonRequired) {
		t.Fatalf("no ExpectPerson and no FirstDevice = %v, want ErrPersonRequired", err)
	}
	if calls != 0 {
		t.Fatal("the key was derived for nothing")
	}
	// With the person to expect, the right key passes.
	person := generate(t)
	if err := e.in.ApproveApprover(e.match(r), &ApproverApproval{Person: derived(person, nil), ExpectPerson: person.PublicKey(), Serial: 1}); err != nil {
		t.Fatal(err)
	}
	if res := result(t, done); res.err != nil {
		t.Fatal(res.err)
	}
}

// TestPayloadBound: JoinDevice accepts at most 4096 bytes of answer, and what it accepts goes through the decoder.
func TestPayloadBound(t *testing.T) {
	e := newEnv(t, nil)
	for size, want := range map[int]error{DefaultMaxDevicePayload + 1: ErrTooLarge, DefaultMaxDevicePayload: ErrProtocol} {
		code, _ := e.create(&CreateOptions{Manual: true})
		dev := generate(t)
		c := e.dial(dev)
		done := make(chan error, 1)
		go func() {
			_, err := JoinDevice(e.ctx, c, dev, code, &DeviceJoinOptions{Name: "phone", FirstDevice: true})
			done <- err
		}()
		ev := e.next()
		if err := e.in.Approve(ev.Request, make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		e.next() // Joined
		e.next() // Ended
		if err := <-done; !errors.Is(err, want) {
			t.Errorf("payload of %d bytes = %v, want %v", size, err, want)
		}
	}
}

// TestAcceptDeviceAnswerChecks drives the checks of the new device against answers a hostile or buggy inviter could send.
func TestAcceptDeviceAnswerChecks(t *testing.T) {
	person := generate(t)
	approver := generate(t)
	aOffer, _ := person.OfferDeviceCert(approver.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	aCert, _ := approver.AcceptDeviceCert(aOffer, person.PublicKey())
	dev := generate(t)
	offerFor := func(d *koloid.Identity, signer *koloid.Identity, parent *koloid.DeviceCert, serial uint64) []byte {
		o, err := signer.OfferDeviceCert(d.PublicKey(), &koloid.IssueOptions{Parent: parent, Serial: serial})
		if err != nil {
			t.Fatal(err)
		}
		return o.Encode()
	}
	good := offerFor(dev, approver, aCert, 1)
	inviter := approver.PublicKey()

	if l, err := acceptDeviceAnswer(dev, inviter, person.PublicKey(), linkAnswer{person.PublicKey(), good}.encode()); err != nil || l.Cert.Approver() {
		t.Fatalf("good answer = %+v, %v", l, err)
	}
	third := generate(t)
	tOffer, _ := person.OfferDeviceCert(third.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	tCert, _ := third.AcceptDeviceCert(tOffer, person.PublicKey())
	relayed := offerFor(dev, third, tCert, 1)
	someoneElse := offerFor(generate(t), approver, aCert, 1)
	otherPerson := generate(t)
	opOffer, _ := otherPerson.OfferDeviceCert(dev.PublicKey(), &koloid.IssueOptions{Serial: 1})
	small := make([]byte, 32)
	small[0] = 1 // the identity point, a small-order key
	// The leaf's issuer signature sits just before the approver certificate that ends the offer: flip a byte of it on purpose.
	const tail = 1 + 2 + 256 // bool, length, the approver certificate
	badSig := bytes.Clone(good)
	badSig[len(badSig)-tail-64/2] ^= 1
	bodyAltered := bytes.Clone(good)
	bodyAltered[60] ^= 1
	cut := bytes.Clone(good)
	cut[len(cut)-1] ^= 1

	for name, c := range map[string]struct {
		payload []byte
		expect  []byte
		cause   error // the error the check wraps, when it comes from kolo-id
	}{
		"offer for another device":   {linkAnswer{person.PublicKey(), someoneElse}.encode(), nil, koloid.ErrInvalidCert},
		"relayed from a third key":   {linkAnswer{person.PublicKey(), relayed}.encode(), nil, nil},
		"another person than pinned": {linkAnswer{person.PublicKey(), good}.encode(), generate(t).PublicKey(), nil},
		"chain of another person":    {linkAnswer{person.PublicKey(), opOffer.Encode()}.encode(), nil, koloid.ErrCertPerson},
		"person is not the chain's":  {linkAnswer{otherPerson.PublicKey(), good}.encode(), nil, koloid.ErrCertPerson},
		"small-order person":         {linkAnswer{small, good}.encode(), nil, koloid.ErrInvalidArgument},
		"offer does not decode":      {linkAnswer{person.PublicKey(), []byte{1, 2, 3}}.encode(), nil, nil},
		"issuer signature flipped":   {linkAnswer{person.PublicKey(), badSig}.encode(), nil, koloid.ErrCertSignature},
		"offer body altered":         {linkAnswer{person.PublicKey(), bodyAltered}.encode(), nil, nil},
		"offer with a bad tail":      {linkAnswer{person.PublicKey(), cut}.encode(), nil, nil},
		"empty":                      {nil, nil, nil},
		"truncated":                  {linkAnswer{person.PublicKey(), good}.encode()[:40], nil, nil},
		"trailing byte":              {append(linkAnswer{person.PublicKey(), good}.encode(), 0), nil, nil},
		"other version":              {append([]byte{1}, linkAnswer{person.PublicKey(), good}.encode()[1:]...), nil, nil},
	} {
		l, err := acceptDeviceAnswer(dev, inviter, c.expect, c.payload)
		if !errors.Is(err, ErrProtocol) || l != nil {
			t.Errorf("%s: %v, %v; want ErrProtocol", name, l, err)
			continue
		}
		if c.cause != nil && !errors.Is(err, c.cause) {
			t.Errorf("%s: %v does not wrap %v", name, err, c.cause)
		}
	}
	pOffer, _ := person.OfferDeviceCert(dev.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	if l, err := acceptDeviceAnswer(dev, generate(t).PublicKey(), nil, linkAnswer{person.PublicKey(), pOffer.Encode()}.encode()); err != nil || !l.Cert.Approver() {
		t.Fatalf("person-issued answer = %+v, %v", l, err)
	}
}

func TestDeviceWireRoundTripsAndRefusals(t *testing.T) {
	r, err := decodeLinkData(linkData{name: "phone"}.encode(), DefaultMaxDeviceName)
	if err != nil || r.name != "phone" {
		t.Fatalf("request = %+v, %v", r, err)
	}
	person := bytes.Repeat([]byte{7}, 32)
	a, err := decodeLinkAnswer(linkAnswer{person, []byte("offer")}.encode())
	if err != nil || !bytes.Equal(a.person, person) || string(a.offer) != "offer" {
		t.Fatalf("answer = %+v, %v", a, err)
	}
	big := bytes.Repeat([]byte{1}, maxOffer+1)
	if _, err := decodeLinkAnswer(linkAnswer{person, big}.encode()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an offer over the bound = %v", err)
	}
	if _, err := decodeLinkAnswer(linkAnswer{person, bytes.Repeat([]byte{1}, maxOffer)}.encode()); err != nil {
		t.Fatalf("an offer at the bound = %v", err)
	}
}

func TestLinkedCertificateCarriesItsExpiry(t *testing.T) {
	e := newEnv(t, nil)
	person, cert := e.approver()
	exp := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	if err := e.in.ApproveDevice(e.match(r), &DeviceApproval{Signer: e.id, Cert: cert, Serial: 3, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	res := result(t, done)
	if res.err != nil || !res.link.Cert.ExpiresAt().Equal(exp) || res.link.Cert.Serial() != 3 {
		t.Fatalf("ordinary: %+v, %v", res.link, res.err)
	}
	if err := res.link.Cert.Verify(&koloid.VerifyOptions{Person: person.PublicKey(), Now: exp.Add(time.Second)}); !errors.Is(err, koloid.ErrCertExpired) {
		t.Fatalf("after the expiry = %v", err)
	}
	e.next() // Joined
	e.next() // Ended
	code, _ = e.createDevice(nil)
	_, done = e.link(e.ctx, generate(t), code, "laptop", nil)
	r = e.nextRequest()
	typed := generate(t)
	if err := e.in.ApproveApprover(e.match(r), &ApproverApproval{Person: derived(typed, nil), FirstDevice: true, Serial: 5, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	res = result(t, done)
	if res.err != nil || !res.link.Cert.ExpiresAt().Equal(exp) || res.link.Cert.Serial() != 5 || !res.link.Cert.Approver() {
		t.Fatalf("approver: %+v, %v", res.link, res.err)
	}
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// TestDenyBurnsEvenWhenTheRefusalCannotBeStored: the deny marker fails to write, the code is burned all the same.
func TestDenyBurnsEvenWhenTheRefusalCannotBeStored(t *testing.T) {
	e := newEnv(t, nil)
	e.stopFn()
	f := &faulty{Backend: e.db}
	e.db = f
	e.start(nil)
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "phone", nil)
	r := e.nextRequest()
	f.putOnly.Store(int32(pDenied))
	f.fail.Store(true)
	if err := e.in.Deny(r.Request); !errors.Is(err, errDisk) {
		t.Fatalf("Deny with a failing disk = %v, want the disk error", err)
	}
	if res := result(t, done); !errors.Is(res.err, ErrRevoked) {
		t.Fatalf("join = %v, want ErrRevoked", res.err)
	}
	if l := e.list(); l[0].State != Revoked {
		t.Fatalf("List = %+v", l)
	}
	// An ordinary Manual invite is not burned by a refusal that failed.
	plain, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	_, jd := e.joinReceived(e.dial(id), id, plain)
	ev := e.next()
	for ev.Kind != Requested {
		ev = e.next()
	}
	if err := e.in.Deny(ev.Request); !errors.Is(err, errDisk) {
		t.Fatalf("Deny of a plain request = %v", err)
	}
	for _, i := range e.list() {
		if i.ID == plain.ID() && i.State != Active {
			t.Fatalf("a plain invite was burned: %+v", i)
		}
	}
	f.fail.Store(false)
	e.in.Deny(ev.Request)
	<-jd
}

// TestRetakeKeepsTheDeviceDeadline: a joiner that asks again does not restart the clock of its pending request.
func TestRetakeKeepsTheDeviceDeadline(t *testing.T) {
	e := newEnv(t, &Options{DevicePendingTTL: time.Hour})
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, first := e.link(e.ctx, dev, code, "first", nil)
	e.nextRequest()
	// The first arrival was a while ago: its deadline is near.
	e.in.mu.Lock()
	for _, p := range e.in.pending {
		p.deadline = time.Now().Add(300 * time.Millisecond)
	}
	e.in.mu.Unlock()
	_, second := e.link(e.ctx, dev, code, "second", nil)
	if res := result(t, first); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("first = %v", res.err)
	}
	// The retake waits only until the original deadline, then the code is burned: it would wait an hour if the clock restarted.
	if res := result(t, second); !errors.Is(res.err, ErrNotAnswered) {
		t.Fatalf("second = %v, want ErrNotAnswered at the first deadline", res.err)
	}
	eventually(t, "the code to be burned", func() bool { return e.list()[0].State == Revoked })
}

// TestAMatchIsFrozenToTheNameItWasMadeFor: the same key asks again with another name after the person typed the digits.
func TestAMatchIsFrozenToTheNameItWasMadeFor(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.approver()
	code, _ := e.createDevice(nil)
	dev := generate(t)
	_, first := e.link(e.ctx, dev, code, "Maria's phone", nil)
	r := e.nextRequest()
	m := e.match(r)
	_, second := e.link(e.ctx, dev, code, "Mallory's phone", nil)
	result(t, first)
	eventually(t, "the retake to change the name", func() bool {
		l, err := e.in.PendingLink(r.Request)
		return err == nil && l.Name == "Mallory's phone"
	})
	if err := e.in.ApproveDevice(m, &DeviceApproval{Signer: e.id, Cert: cert, Serial: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approving a match whose name changed = %v, want ErrNotFound", err)
	}
	// Typing the digits again matches the new request, and that match is approved.
	if err := e.approveDevice(LinkRequest{Request: r.Request, Invite: r.Invite, Device: r.Device}, cert, 1); err != nil {
		t.Fatal(err)
	}
	if res := result(t, second); res.err != nil {
		t.Fatal(res.err)
	}
}

func TestApproverClearsAKeyReturnedWithAnError(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.createDevice(nil)
	_, done := e.link(e.ctx, generate(t), code, "tablet", nil)
	r := e.nextRequest()
	p := generate(t)
	boom := errors.New("wrong words")
	err := e.in.ApproveApprover(e.match(r), &ApproverApproval{FirstDevice: true, Serial: 1,
		Person: func() (*koloid.Identity, error) { return p, boom }})
	if !errors.Is(err, boom) {
		t.Fatalf("ApproveApprover = %v", err)
	}
	if p.PublicKey() != nil {
		t.Fatal("a key returned with an error was not cleared")
	}
	e.in.Deny(r.Request)
	result(t, done)
}
