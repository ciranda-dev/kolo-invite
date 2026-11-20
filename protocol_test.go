package invite

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
)

func TestAutoAccept(t *testing.T) {
	e := newEnv(t, nil)
	code, info := e.create(&CreateOptions{Payload: []byte("log id and capability")})
	if info.State != Active || info.MaxUses != 1 || info.Used != 0 || info.Manual || !info.Expires.IsZero() {
		t.Fatalf("info = %+v", info)
	}
	id := generate(t)
	p, pending, err := exchange(e.ctx, e.dial(id), id, code, []byte("hi"))
	if err != nil || pending || string(p) != "log id and capability" {
		t.Fatalf("exchange = %q, %v, %v", p, pending, err)
	}
	if ev := e.next(); ev.Kind != Joined || ev.Invite != code.ID() || !ev.Joiner.Equal(id.PublicKey()) || ev.Request != 0 {
		t.Fatalf("event = %+v", ev)
	}
	if ev := e.next(); ev.Kind != Ended || ev.State != UsedUp {
		t.Fatalf("event = %+v", ev)
	}
	l := e.list()
	if len(l) != 1 || l[0].Used != 1 || l[0].State != UsedUp || l[0].Ended.IsZero() {
		t.Fatalf("List = %+v", l)
	}
	s := e.in.Stats()
	if s.Requests != 1 || s.Accepted != 1 || s.Ended != 1 || s.Active != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestManualApprove(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true, MaxUses: 2})
	id := generate(t)
	type result struct {
		p       []byte
		pending bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		p, pending, err := exchange(e.ctx, e.dial(id), id, code, []byte("Bob"))
		done <- result{p, pending, err}
	}()
	ev := e.next()
	if ev.Kind != Requested || ev.Invite != code.ID() || !ev.Joiner.Equal(id.PublicKey()) || string(ev.Data) != "Bob" || ev.Request == 0 {
		t.Fatalf("event = %+v", ev)
	}
	if s := e.in.Stats(); s.Pending != 1 {
		t.Fatalf("Pending = %d", s.Pending)
	}
	if err := e.in.Approve(ev.Request, []byte("welcome")); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || string(r.p) != "welcome" {
		t.Fatalf("exchange = %q, %v, %v", r.p, r.pending, r.err)
	}
	if j := e.next(); j.Kind != Joined || j.Request != ev.Request {
		t.Fatalf("event = %+v", j)
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Approve = %v", err)
	}
	if l := e.list(); l[0].Used != 1 || l[0].State != Active {
		t.Fatalf("List = %+v", l)
	}
	e.noEvent()
}

func TestDenyReturnsDenied(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	c := e.dial(id)
	done := make(chan error, 1)
	go func() {
		_, _, err := exchange(e.ctx, c, id, code, nil)
		done <- err
	}()
	ev := e.next()
	start := time.Now()
	if err := e.in.Deny(ev.Request); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatalf("exchange = %v, want ErrDenied", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("deny took as long as a timeout")
	}
	if _, _, err := exchange(e.ctx, c, id, code, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("retry = %v, want ErrDenied", err)
	}
	if err := e.in.Deny(ev.Request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Deny = %v", err)
	}
	if s := e.in.Stats(); s.Denied != 1 || s.Pending != 0 {
		t.Fatalf("Stats = %+v", s)
	}
	if l := e.list(); l[0].Used != 0 || l[0].State != Active {
		t.Fatalf("a deny used the invite: %+v", l)
	}
	e.noEvent()
}

func TestExpired(t *testing.T) {
	e := newEnv(t, nil)
	code, info := e.create(&CreateOptions{TTL: time.Hour})
	if !info.Expires.Equal(e.clk.now().Add(time.Hour)) {
		t.Fatalf("Expires = %v", info.Expires)
	}
	e.clk.add(time.Hour - time.Nanosecond)
	if l := e.list(); l[0].State != Active {
		t.Fatalf("expired early: %+v", l)
	}
	e.clk.add(time.Nanosecond)
	if _, err := e.join(code, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("join = %v, want ErrExpired", err)
	}
	if ev := e.next(); ev.Kind != Ended || ev.State != Expired {
		t.Fatalf("event = %+v", ev)
	}
	l := e.list()
	if l[0].State != Expired || !l[0].Ended.Equal(info.Expires) || l[0].Used != 0 {
		t.Fatalf("List = %+v", l)
	}
	if s := e.in.Stats(); s.RefusedEnded != 1 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestExpiryTimerAnswersPending(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{TTL: time.Minute, Manual: true})
	done := make(chan error, 1)
	go func() { _, err := e.join(code, nil); done <- err }()
	ev := e.next()
	e.clk.add(time.Minute)
	signal(e.in.wake)
	if err := <-done; !errors.Is(err, ErrExpired) {
		t.Fatalf("join = %v, want ErrExpired", err)
	}
	if w := e.next(); w.Kind != Withdrawn || w.Request != ev.Request {
		t.Fatalf("event = %+v", w)
	}
	if end := e.next(); end.Kind != Ended || end.State != Expired {
		t.Fatalf("event = %+v", end)
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("Approve = %v, want ErrExpired", err)
	}
}

func TestApproveAfterExpiry(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{TTL: time.Minute, Manual: true})
	done := make(chan error, 1)
	go func() { _, err := e.join(code, nil); done <- err }()
	ev := e.next()
	e.clk.add(time.Minute) // the clock goroutine is not woken: Approve itself must check
	if err := e.in.Approve(ev.Request, []byte("late")); !errors.Is(err, ErrExpired) {
		t.Fatalf("Approve = %v, want ErrExpired", err)
	}
	if err := <-done; !errors.Is(err, ErrExpired) {
		t.Fatalf("join = %v, want ErrExpired", err)
	}
	if l := e.list(); l[0].Used != 0 {
		t.Fatalf("an expired invite was used: %+v", l)
	}
}

func TestUsedUp(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{MaxUses: 3, Payload: []byte("p")})
	for i := range 3 {
		if p, err := e.join(code, nil); err != nil || string(p) != "p" {
			t.Fatalf("join %d = %q, %v", i, p, err)
		}
	}
	if _, err := e.join(code, nil); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("fourth join = %v, want ErrUsedUp", err)
	}
	if l := e.list(); l[0].Used != 3 || l[0].State != UsedUp {
		t.Fatalf("List = %+v", l)
	}
}

func TestUsedUpAnswersOtherPending(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	done := make(chan error, 2)
	for range 2 {
		go func() { _, err := e.join(code, nil); done <- err }()
	}
	a, b := e.next(), e.next()
	if a.Kind != Requested || b.Kind != Requested || a.Request == b.Request {
		t.Fatalf("events = %+v %+v", a, b)
	}
	if err := e.in.Approve(a.Request, nil); err != nil {
		t.Fatal(err)
	}
	errs := []error{<-done, <-done}
	if !(errs[0] == nil && errors.Is(errs[1], ErrUsedUp) || errs[1] == nil && errors.Is(errs[0], ErrUsedUp)) {
		t.Fatalf("joins = %v", errs)
	}
	if err := e.in.Approve(b.Request, nil); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("Approve of the other = %v, want ErrUsedUp", err)
	}
	if err := e.in.Deny(b.Request); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("Deny of the other = %v, want ErrUsedUp", err)
	}
}

func TestRevoked(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	done := make(chan error, 1)
	go func() { _, err := e.join(code, nil); done <- err }()
	ev := e.next()
	if err := e.in.Revoke(code.ID()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrRevoked) {
		t.Fatalf("pending join = %v, want ErrRevoked", err)
	}
	if _, err := e.join(code, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("join = %v, want ErrRevoked", err)
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Approve = %v, want ErrRevoked", err)
	}
	if err := e.in.Revoke(code.ID()); err != nil {
		t.Fatalf("second Revoke = %v", err)
	}
	if err := e.in.Revoke(ID{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Revoke of an unknown ID = %v", err)
	}
	if l := e.list(); l[0].State != Revoked || l[0].Ended.IsZero() {
		t.Fatalf("List = %+v", l)
	}
}

func TestRevokeKeepsUsedUpState(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	if _, err := e.join(code, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Revoke(code.ID()); err != nil {
		t.Fatal(err)
	}
	if l := e.list(); l[0].State != UsedUp {
		t.Fatalf("List = %+v", l)
	}
}

func TestRetryAfterAcceptUsesNoUse(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{MaxUses: 2, Payload: []byte("p")})
	id := generate(t)
	c := e.dial(id)
	for i := range 3 {
		if p, _, err := exchange(e.ctx, c, id, code, nil); err != nil || string(p) != "p" {
			t.Fatalf("exchange %d = %q, %v", i, p, err)
		}
	}
	if l := e.list(); l[0].Used != 1 {
		t.Fatalf("retries used the invite: %+v", l)
	}
	e.in.Revoke(code.ID())
	if p, _, err := exchange(e.ctx, c, id, code, nil); err != nil || string(p) != "p" {
		t.Fatalf("retry after revoke = %q, %v", p, err)
	}
}

func TestConcurrentSingleUse(t *testing.T) {
	e := newEnv(t, &Options{SourceRate: 1 << 20, InviteRate: 1 << 20})
	const joiners = 8
	ids := make([]*koloid.Identity, joiners)
	conns := make([]*testConn, joiners)
	for i := range ids {
		ids[i] = generate(t)
		conns[i] = e.dial(ids[i])
	}
	for run := range 100 {
		code, _ := e.create(&CreateOptions{Payload: []byte("p")})
		errs := make([]error, joiners)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range joiners {
			wg.Go(func() {
				<-start
				_, _, errs[i] = exchange(e.ctx, conns[i], ids[i], code, nil)
			})
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, ErrUsedUp):
				t.Fatalf("run %d: %v", run, err)
			}
		}
		if won != 1 {
			t.Fatalf("run %d: %d joiners accepted on a single-use invite", run, won)
		}
		info := e.list()[run]
		if info.Used != 1 || info.State != UsedUp {
			t.Fatalf("run %d: %+v", run, info)
		}
	}
}

func TestReplayedRequest(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{MaxUses: 5})
	id := generate(t)
	c := e.dial(id)
	r := e.raw(c)
	nonce := r.challenge()
	req := e.request(code, id, nil, nonce)
	r.send(req)
	if m, err := r.answer(); err != nil || m.typ != msgAnswer {
		t.Fatalf("first request: %+v, %v", m, err)
	}
	r.reset() // one request per stream: the inviter ended it
	r2 := e.raw(c)
	r2.challenge()
	r2.send(req)
	r2.refused(refInvalid)
	if l := e.list(); l[0].Used != 1 {
		t.Fatalf("Used = %d", l[0].Used)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	id := generate(t)
	c := e.dial(id)
	fields := map[string]func(*msg){
		"sealed": func(m *msg) { m.sealed[len(m.sealed)/2] ^= 1 },
		"tag":    func(m *msg) { m.sealed[len(m.sealed)-1] ^= 1 },
		"enc":    func(m *msg) { m.enc[0] ^= 1 },
		"short":  func(m *msg) { m.sealed = m.sealed[:len(m.sealed)-1] },
	}
	for name, f := range fields {
		r := e.raw(c)
		req := e.request(code, id, []byte("data"), r.challenge())
		f(&req)
		r.send(req)
		r.refused(refInvalid)
		t.Log(name, "refused")
	}
	if s := e.in.Stats(); s.RefusedInvalid != uint64(len(fields)) || s.Accepted != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestWrongKey(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	id := generate(t)
	c := e.dial(id)

	// A code with the inviter's key and another secret: unknown invite.
	other, err := Parse(encodeCode(e.id.PublicKey(), bytes.Repeat([]byte{7}, secretSize)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := exchange(e.ctx, c, id, other, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other secret = %v, want ErrInvalid", err)
	}

	// The right invite ID sealed to another HPKE key.
	wk := *other.c
	wk.k.id = code.c.k.id
	wrong := Code{&wk}
	if _, _, err := exchange(e.ctx, c, id, wrong, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong HPKE key = %v, want ErrInvalid", err)
	}

	// The right keys but a wrong auth value.
	bk := *code.c
	bk.k.auth[0] ^= 1
	bad := Code{&bk}
	if _, _, err := exchange(e.ctx, c, id, bad, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong auth = %v, want ErrInvalid", err)
	}

	// A request signed by another key than the one it names.
	r := e.raw(c)
	nonce := r.challenge()
	r.send(sealRequest(t, code, e.id.PublicKey(), nonce, request{auth: code.c.k.auth[:], joiner: id.PublicKey(),
		answerKey: answerKey(t)}, generate(t)))
	r.refused(refInvalid)

	// The same request signed by the key it names is accepted, so only the signature differed.
	r = e.raw(c)
	nonce = r.challenge()
	r.send(sealRequest(t, code, e.id.PublicKey(), nonce, request{auth: code.c.k.auth[:], joiner: id.PublicKey(),
		answerKey: answerKey(t)}, id))
	if m, err := r.answer(); err != nil || m.typ != msgAnswer {
		t.Fatalf("well signed request: %+v, %v", m, err)
	}

	// The joiner talks only to the inviter's key.
	nk := *code.c
	nk.fp[0] ^= 1
	notInviter := Code{&nk}
	if _, _, err := exchange(e.ctx, c, id, notInviter, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("peer is not the inviter = %v, want ErrProtocol", err)
	}
	if l := e.list(); l[0].Used != 1 {
		t.Fatalf("Used = %d", l[0].Used)
	}
}

func TestMalformedMessages(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	id := generate(t)
	c := e.dial(id)
	cases := map[string]func(r *raw){
		"request first":      func(r *raw) { r.send(msg{typ: msgRequest, enc: make([]byte, encSize)}) },
		"bad version":        func(r *raw) { r.sendBytes([]byte{1, msgOpen}) },
		"trailing bytes":     func(r *raw) { r.sendBytes([]byte{0, msgOpen, 0}) },
		"unknown type":       func(r *raw) { r.sendBytes([]byte{0, 9}) },
		"open twice":         func(r *raw) { r.challenge(); r.send(msg{typ: msgOpen}) },
		"huge frame":         func(r *raw) { r.st.Write([]byte{0xff, 0xff, 0xff, 0x7f}) },
		"pending as request": func(r *raw) { r.challenge(); r.send(msg{typ: msgReceived}) },
		"answer as request":  func(r *raw) { r.challenge(); r.send(msg{typ: msgAnswer, sealed: []byte{1}}) },
		"short request": func(r *raw) {
			r.challenge()
			r.sendBytes([]byte{0, msgRequest, 1, 2})
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.raw(c)
			r.t = t
			f(r)
			for {
				m, err := r.recv()
				if err != nil {
					break
				}
				if m.typ != msgChallenge {
					t.Fatalf("got %+v", m)
				}
			}
		})
	}
	if _, _, err := exchange(e.ctx, c, id, code, nil); err != nil {
		t.Fatalf("the connection stopped working: %v", err)
	}
}

func TestStreamTimeout(t *testing.T) {
	e := newEnv(t, &Options{Timeout: 200 * time.Millisecond})
	c := e.dial(generate(t))
	r := e.raw(c)
	r.challenge()
	start := time.Now()
	r.reset()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("a silent joiner held the stream for %v", d)
	}
}

func TestRateLimitPerSource(t *testing.T) {
	e := newEnv(t, &Options{SourceRate: 3})
	code, _ := e.create(&CreateOptions{MaxUses: 100})
	c := e.dial(generate(t))
	for i := range 3 {
		if _, _, err := exchange(e.ctx, c, generate(t), code, nil); err != nil {
			t.Fatalf("join %d = %v", i, err)
		}
	}
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fourth join = %v, want ErrRateLimited", err)
	}
	// Another source is not limited.
	e.srcMu.Lock()
	e.src = func(*testConn) string { return "10.0.0.2" }
	e.srcMu.Unlock()
	if _, err := e.join(code, nil); err != nil {
		t.Fatalf("other source = %v", err)
	}
	// The bucket refills at SourceRate per minute.
	e.clk.add(20 * time.Second)
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); err != nil {
		t.Fatalf("after refill = %v", err)
	}
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("after one token = %v, want ErrRateLimited", err)
	}
	if s := e.in.Stats(); s.RefusedLimited != 2 || s.Accepted != 5 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestRateLimitPerInvite(t *testing.T) {
	e := newEnv(t, &Options{InviteRate: 2})
	code, _ := e.create(&CreateOptions{MaxUses: 100})
	other, _ := e.create(&CreateOptions{MaxUses: 100})
	n := 0
	e.srcMu.Lock()
	e.src = func(*testConn) string { n++; return "10.0.1." + string(rune('0'+n)) }
	e.srcMu.Unlock()
	for range 2 {
		if _, err := e.join(code, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.join(code, nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third join = %v, want ErrRateLimited", err)
	}
	if _, err := e.join(other, nil); err != nil {
		t.Fatalf("other invite = %v", err)
	}
}

func TestMaxSources(t *testing.T) {
	e := newEnv(t, &Options{MaxSources: 2, SourceRate: 1})
	code, _ := e.create(&CreateOptions{MaxUses: 100})
	n := 0
	e.srcMu.Lock()
	e.src = func(*testConn) string { n++; return "10.0.2." + string(rune('0'+n)) }
	e.srcMu.Unlock()
	for range 2 {
		if _, err := e.join(code, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.join(code, nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third source = %v, want ErrRateLimited", err)
	}
	e.clk.add(time.Minute) // both buckets are full again and can be forgotten
	if _, err := e.join(code, nil); err != nil {
		t.Fatalf("after refill = %v", err)
	}
	e.in.mu.Lock()
	n = len(e.in.sources)
	e.in.mu.Unlock()
	if n > 2 {
		t.Fatalf("%d sources tracked, MaxSources 2", n)
	}
}

func TestPendingBoundedUnderFlood(t *testing.T) {
	const max = 20
	e := newEnv(t, &Options{MaxPending: max, MaxPendingPerSource: 1000, SourceRate: 1 << 20, InviteRate: 1 << 20,
		MaxStreams: 64})
	code, _ := e.create(&CreateOptions{Manual: true})
	c := e.dial(generate(t))
	ctx, cancel := context.WithCancel(e.ctx)
	var wg sync.WaitGroup
	const flood = 60
	errs := make(chan error, flood)
	for range flood {
		wg.Go(func() {
			_, _, err := exchange(ctx, c, generate(t), code, nil)
			errs <- err
		})
	}
	busy := 0
	for busy < flood-max {
		err := <-errs
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("flood join = %v, want ErrBusy", err)
		}
		busy++
	}
	eventually(t, "pending requests", func() bool { return e.in.Stats().Pending == max })
	e.in.mu.Lock()
	queued := len(e.in.events)
	e.in.mu.Unlock()
	if queued > max {
		t.Fatalf("%d events queued for %d pending", queued, max)
	}
	cancel()
	wg.Wait()
	eventually(t, "pending requests to leave", func() bool { return e.in.Stats().Pending == 0 })
	e.in.mu.Lock()
	queued = len(e.in.events)
	e.in.mu.Unlock()
	if queued != 0 {
		t.Fatalf("%d Requested events left for requests that left before being read", queued)
	}
}

func TestPendingPerSource(t *testing.T) {
	e := newEnv(t, &Options{MaxPendingPerSource: 2})
	code, _ := e.create(&CreateOptions{Manual: true})
	c := e.dial(generate(t))
	done := make(chan error, 2)
	for range 2 {
		go func() { _, _, err := exchange(e.ctx, c, generate(t), code, nil); done <- err }()
	}
	e.next()
	e.next()
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("third pending from one source = %v, want ErrBusy", err)
	}
	e.in.Revoke(code.ID())
	for range 2 {
		if err := <-done; !errors.Is(err, ErrRevoked) {
			t.Fatal(err)
		}
	}
}

func TestWithdrawnWhenJoinerLeaves(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan error, 1)
	c := e.dial(id)
	go func() { _, _, err := exchange(ctx, c, id, code, nil); done <- err }()
	ev := e.next()
	cancel()
	if err := <-done; err == nil {
		t.Fatal("exchange succeeded after cancel")
	}
	if w := e.next(); w.Kind != Withdrawn || w.Request != ev.Request {
		t.Fatalf("event = %+v", w)
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Approve = %v", err)
	}
	if s := e.in.Stats(); s.Pending != 0 {
		t.Fatalf("Pending = %d", s.Pending)
	}
}

func TestUnreadRequestedRemoved(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan error, 1)
	go func() { _, _, err := exchange(ctx, e.dial(generate(t)), generate(t), code, nil); done <- err }()
	eventually(t, "pending", func() bool { return e.in.Stats().Pending == 1 })
	cancel()
	<-done
	eventually(t, "withdrawn", func() bool { return e.in.Stats().Pending == 0 })
	e.noEvent()
}

func TestTakeoverKeepsRequestID(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	c := e.dial(id)
	first := make(chan error, 1)
	go func() { _, _, err := exchange(e.ctx, c, id, code, []byte("one")); first <- err }()
	ev := e.next()
	second := make(chan []byte, 1)
	go func() { p, _, _ := exchange(e.ctx, c, id, code, []byte("two")); second <- p }()
	if err := <-first; err == nil {
		t.Fatal("the replaced stream got an answer")
	}
	e.noEvent()
	if err := e.in.Approve(ev.Request, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if p := <-second; string(p) != "ok" {
		t.Fatalf("second = %q", p)
	}
	if s := e.in.Stats(); s.Pending != 0 {
		t.Fatalf("Pending = %d", s.Pending)
	}
}

func TestMaxStreams(t *testing.T) {
	e := newEnv(t, &Options{MaxStreams: 1})
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	c := e.dial(id)
	done := make(chan error, 1)
	go func() { _, _, err := exchange(e.ctx, c, id, code, nil); done <- err }()
	e.next()
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("second stream = %v, want a reset", err)
	}
	eventually(t, "refused stream", func() bool { return e.in.Stats().StreamsRefused == 1 })
	e.in.Revoke(code.ID())
	if err := <-done; !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestEventsBounded(t *testing.T) {
	e := newEnv(t, &Options{MaxEvents: 3})
	for range 5 {
		code, _ := e.create(nil)
		if _, err := e.join(code, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Each join queues Joined and Ended; only the last three events stay.
	if s := e.in.Stats(); s.EventsDropped != 7 {
		t.Fatalf("EventsDropped = %d", s.EventsDropped)
	}
	got := []EventKind{e.next().Kind, e.next().Kind, e.next().Kind}
	if got[0] != Ended || got[1] != Joined || got[2] != Ended {
		t.Fatalf("events = %v", got)
	}
	e.noEvent()
}

func TestRequestedNeverDropped(t *testing.T) {
	e := newEnv(t, &Options{MaxEvents: 1})
	manual, _ := e.create(&CreateOptions{Manual: true, MaxUses: 3})
	done := make(chan error, 3)
	for range 3 {
		go func() { _, err := e.join(manual, nil); done <- err }()
	}
	eventually(t, "pending", func() bool { return e.in.Stats().Pending == 3 })
	for range 3 {
		code, _ := e.create(nil)
		if _, err := e.join(code, nil); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if ev := e.next(); ev.Kind != Requested {
			t.Fatalf("event = %+v", ev)
		}
	}
	if ev := e.next(); ev.Kind != Ended {
		t.Fatalf("event = %+v", ev)
	}
	e.noEvent()
	e.in.Revoke(manual.ID())
	for range 3 {
		<-done
	}
}

func TestLingerErasesSecret(t *testing.T) {
	e := newEnvLinger(t, nil, time.Minute)
	code, _ := e.create(&CreateOptions{Payload: []byte("p")})
	id := generate(t)
	c := e.dial(id)
	if _, _, err := exchange(e.ctx, c, id, code, nil); err != nil {
		t.Fatal(err)
	}
	if got := e.in.live(); len(got) != 1 {
		t.Fatalf("live = %d, want the ended invite to linger", len(got))
	}
	e.clk.add(time.Minute - time.Nanosecond)
	signal(e.in.wake)
	if p, _, err := exchange(e.ctx, c, id, code, nil); err != nil || string(p) != "p" {
		t.Fatalf("retry in the linger time = %q, %v", p, err)
	}
	e.clk.add(time.Nanosecond)
	signal(e.in.wake)
	eventually(t, "erased secret", func() bool { return len(e.in.live()) == 0 })
	raw, err := e.db.Get(inviteKey(code.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, code.c.secret[:]) {
		t.Fatal("the stored record still holds the secret")
	}
	if _, _, err := exchange(e.ctx, c, generate(t), code, nil); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("after linger = %v, want ErrUsedUp", err)
	}
	if l := e.list(); l[0].State != UsedUp || l[0].Used != 1 {
		t.Fatalf("List = %+v", l)
	}
}

func TestOversizedFrameEndsStreamAtOnce(t *testing.T) {
	e := newEnv(t, &Options{Timeout: time.Minute})
	c := e.dial(generate(t))
	for _, open := range []bool{false, true} {
		r := e.raw(c)
		if open {
			r.challenge()
		}
		start := time.Now()
		h := binary.LittleEndian.AppendUint32(nil, uint32(max(smallFrame, maxFrame(e.in.opts.MaxData))+1))
		if _, err := r.st.Write(h); err != nil {
			t.Fatal(err)
		}
		if open {
			if m, err := r.recv(); err != nil || m.typ != msgReceived {
				t.Fatalf("got %+v, %v; want RECEIVED", m, err)
			}
			r.refused(refTooLarge)
		}
		r.reset()
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("an oversized frame header held the stream for %v", d)
		}
	}
}

func TestDenyAfterExpiry(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{TTL: time.Minute, Manual: true})
	done := make(chan error, 1)
	go func() { _, err := e.join(code, nil); done <- err }()
	ev := e.next()
	e.clk.add(time.Minute) // the clock goroutine is not woken: Deny itself must check
	if err := e.in.Deny(ev.Request); !errors.Is(err, ErrExpired) {
		t.Fatalf("Deny = %v, want ErrExpired", err)
	}
	if err := <-done; !errors.Is(err, ErrExpired) {
		t.Fatalf("join = %v, want ErrExpired", err)
	}
	if s := e.in.Stats(); s.Denied != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}
