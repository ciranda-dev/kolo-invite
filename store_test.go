package invite

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"
)

func TestRestartKeepsState(t *testing.T) {
	e := newEnv(t, nil)
	used, _ := e.create(&CreateOptions{MaxUses: 2, TTL: time.Hour, Payload: []byte("p")})
	revoked, _ := e.create(&CreateOptions{Manual: true})
	denied, _ := e.create(&CreateOptions{Manual: true, MaxUses: 5})
	first := generate(t)
	if _, _, err := exchange(e.ctx, e.dial(first), first, used, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Revoke(revoked.ID()); err != nil {
		t.Fatal(err)
	}
	bad := generate(t)
	done := make(chan error, 1)
	go func() { _, _, err := exchange(e.ctx, e.dial(bad), bad, denied, nil); done <- err }()
	var req RequestID
	for req == 0 {
		if ev := e.next(); ev.Kind == Requested {
			req = ev.Request
		}
	}
	if err := e.in.Deny(req); err != nil {
		t.Fatal(err)
	}
	<-done
	before := e.list()

	e.stopFn()
	e.clk.add(30 * time.Minute)
	e.start(nil)
	after := e.list()
	if len(after) != 3 {
		t.Fatalf("List after restart = %+v", after)
	}
	for i := range before {
		b, a := before[i], after[i]
		if a.ID != b.ID || !a.Created.Equal(b.Created) || !a.Expires.Equal(b.Expires) || a.Used != b.Used ||
			a.MaxUses != b.MaxUses || a.Manual != b.Manual || a.State != b.State {
			t.Fatalf("invite %d changed: %+v, was %+v", i, a, b)
		}
	}
	e.noEvent() // ends from before the restart are not reported again

	if p, _, err := exchange(e.ctx, e.dial(first), first, used, nil); err != nil || string(p) != "p" {
		t.Fatalf("stored accept after restart = %q, %v", p, err)
	}
	if _, err := e.join(used, nil); err != nil {
		t.Fatalf("second use = %v", err)
	}
	if _, err := e.join(used, nil); !errors.Is(err, ErrUsedUp) {
		t.Fatalf("third use = %v, want ErrUsedUp", err)
	}
	if _, err := e.join(revoked, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked invite = %v, want ErrRevoked", err)
	}
	if _, _, err := exchange(e.ctx, e.dial(bad), bad, denied, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied joiner = %v, want ErrDenied", err)
	}

	// Expiry survives a restart and is checked against the clock after it.
	exp, _ := e.create(&CreateOptions{TTL: time.Minute})
	e.stopFn()
	e.clk.add(time.Minute)
	e.start(nil)
	if _, err := e.join(exp, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired during the restart = %v, want ErrExpired", err)
	}
}

func TestRestartErasesLingeredSecrets(t *testing.T) {
	e := newEnvLinger(t, nil, time.Minute)
	code, _ := e.create(nil)
	if err := e.in.Revoke(code.ID()); err != nil {
		t.Fatal(err)
	}
	e.stopFn()
	e.clk.add(time.Hour)
	e.start(nil)
	eventually(t, "erased secret", func() bool { return len(e.in.live()) == 0 })
	raw, err := e.db.Get(inviteKey(code.ID()))
	if err != nil || bytes.Contains(raw, code.c.secret[:]) {
		t.Fatalf("record = %x, %v", raw, err)
	}
	if _, err := e.join(code, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("join = %v, want ErrRevoked", err)
	}
	e.stopFn()
	e.start(nil)
	if l := e.list(); len(l) != 1 || l[0].State != Revoked {
		t.Fatalf("List = %+v", l)
	}
}

func TestOpenOtherIdentity(t *testing.T) {
	checkGoroutines(t)
	db := kolostore.NewMemory()
	defer db.Close()
	in, err := Open(db, generate(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Close()
	if _, err := Open(db, generate(t), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Open with another identity = %v, want ErrInvalidArgument", err)
	}
}

func TestOpenRejectsCorrupt(t *testing.T) {
	checkGoroutines(t)
	id := generate(t)
	secret := bytes.Repeat([]byte{3}, secretSize)
	k := mustKeys(secret)
	good := record{secret: secret, created: 10, maxUses: 1}
	mod := func(f func(r *record)) []byte {
		r := good
		f(&r)
		return r.encode()
	}
	joiner := generate(t).PublicKey()
	cases := map[string]map[string][]byte{
		"no meta":          {string(inviteKey(k.id)): good.encode()},
		"bad meta":         {"m": {0, 1, 2}},
		"unknown key":      {"m": encodeMeta(id.PublicKey()), "x": nil},
		"short invite key": {"m": encodeMeta(id.PublicKey()), "i\x01": good.encode()},
		"bad record":       {"m": encodeMeta(id.PublicKey()), string(inviteKey(k.id)): {0, 1}},
		"wrong id":         {"m": encodeMeta(id.PublicKey()), string(inviteKey(ID{1})): good.encode()},
		"short secret": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.secret = secret[:5] })},
		"no secret, not ended": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.secret = nil })},
		"used over max": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.used = 2; r.ended = 11 })},
		"zero max uses": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.maxUses = 0 })},
		"revoked without end": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.revoked = true })},
		"end without reason": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.ended = 11 })},
		"used up without end": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.used = 1 })},
		"expires before created": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.expires = 5 })},
		"manual with payload": {"m": encodeMeta(id.PublicKey()),
			string(inviteKey(k.id)): mod(func(r *record) { r.manual = true; r.payload = []byte{1} })},
		"answer of unknown invite": {"m": encodeMeta(id.PublicKey()),
			string(joinerKey(pAccepted, k.id, joiner)): joined{}.encode()},
		"bad answer": {"m": encodeMeta(id.PublicKey()), string(inviteKey(k.id)): good.encode(),
			string(joinerKey(pAccepted, k.id, joiner)): {1}},
		"bad deny": {"m": encodeMeta(id.PublicKey()), string(inviteKey(k.id)): good.encode(),
			string(joinerKey(pDenied, k.id, joiner)): {0, 0}},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			db := kolostore.NewMemory()
			defer db.Close()
			for k, v := range kv {
				if err := db.Put([]byte(k), v); err != nil {
					t.Fatal(err)
				}
			}
			in, err := Open(db, id, nil)
			if !errors.Is(err, kolostore.ErrCorrupt) {
				if in != nil {
					in.Close()
				}
				t.Fatalf("Open = %v, want ErrCorrupt", err)
			}
		})
	}
	db := kolostore.NewMemory()
	defer db.Close()
	db.Put([]byte("m"), encodeMeta(id.PublicKey()))
	db.Put(inviteKey(k.id), good.encode())
	db.Put(joinerKey(pDenied, k.id, joiner), encodeVersion())
	in, err := Open(db, id, nil)
	if err != nil {
		t.Fatalf("Open of a good store = %v", err)
	}
	in.Close()
}

// faulty is a backend whose writes fail while fail is set.
type faulty struct {
	kolostore.Backend
	fail     atomic.Bool
	failed   atomic.Int32 // writes refused because of fail
	failGet  atomic.Bool
	failScan atomic.Bool
	getOnly  atomic.Int32 // with failGet, only keys starting with this byte fail; 0 means all
	putOnly  atomic.Int32 // with fail, only Put of keys starting with this byte fails; 0 means all
}

func (f *faulty) Get(k []byte) ([]byte, error) {
	if f.failGet.Load() && (f.getOnly.Load() == 0 || k[0] == byte(f.getOnly.Load())) {
		return nil, errDisk
	}
	return f.Backend.Get(k)
}

func (f *faulty) Scan(start, end []byte, reverse bool, limit int, fn func(k, v []byte) bool) error {
	if f.failScan.Load() {
		return errDisk
	}
	return f.Backend.Scan(start, end, reverse, limit, fn)
}

var errDisk = errors.New("disk failed")

func (f *faulty) Put(k, v []byte) error {
	if f.fail.Load() && (f.putOnly.Load() == 0 || k[0] == byte(f.putOnly.Load())) {
		f.failed.Add(1)
		return errDisk
	}
	return f.Backend.Put(k, v)
}

func (f *faulty) NewBatch() kolostore.Batch { return &faultyBatch{f.Backend.NewBatch(), f} }

type faultyBatch struct {
	kolostore.Batch
	f *faulty
}

func (b *faultyBatch) Commit() error {
	if b.f.fail.Load() {
		b.f.failed.Add(1)
		return errDisk
	}
	return b.Batch.Commit()
}

func TestStorageFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.stopFn()
	f := &faulty{Backend: e.db}
	e.db = f
	e.start(nil)
	auto, _ := e.create(nil)
	manual, _ := e.create(&CreateOptions{Manual: true})
	f.fail.Store(true)
	if _, _, err := e.in.Create(nil); !errors.Is(err, errDisk) {
		t.Fatalf("Create = %v", err)
	}
	if _, err := e.join(auto, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("join on a failing disk = %v, want ErrBusy", err)
	}
	if l := e.list(); l[0].Used != 0 {
		t.Fatalf("a failed write counted a use: %+v", l)
	}
	if err := e.in.Revoke(auto.ID()); !errors.Is(err, errDisk) {
		t.Fatalf("Revoke = %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := e.join(manual, nil); done <- err }()
	var ev Event
	for ev.Kind != Requested {
		ev = e.next()
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, errDisk) {
		t.Fatalf("Approve = %v", err)
	}
	if err := e.in.Deny(ev.Request); !errors.Is(err, errDisk) {
		t.Fatalf("Deny = %v", err)
	}
	f.fail.Store(false)
	if err := e.in.Approve(ev.Request, []byte("ok")); err != nil {
		t.Fatalf("Approve after the disk recovered = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := e.join(auto, nil); err != nil {
		t.Fatalf("join after the disk recovered = %v", err)
	}

	// Reads that fail, and a stored answer that does not decode, answer busy.
	other, _ := e.create(&CreateOptions{MaxUses: 5})
	f.failGet.Store(true)
	if _, err := e.join(other, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("join with failing reads = %v, want ErrBusy", err)
	}
	f.failGet.Store(false)
	j := generate(t)
	if err := e.db.Put(joinerKey(pAccepted, other.ID(), j.PublicKey()), []byte{9}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := exchange(e.ctx, e.dial(j), j, other, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("join with a corrupt stored accept = %v, want ErrBusy", err)
	}
	if err := e.db.Delete(joinerKey(pAccepted, other.ID(), j.PublicKey())); err != nil {
		t.Fatal(err)
	}

	// A secret that cannot be erased at the end of the linger time is erased on a later tick.
	if err := e.in.Revoke(other.ID()); err != nil {
		t.Fatal(err)
	}
	f.fail.Store(true)
	before := f.failed.Load()
	e.clk.add(time.Hour)
	signal(e.in.wake)
	eventually(t, "a failed erase", func() bool { return f.failed.Load() > before })
	if len(e.in.live()) == 0 {
		t.Fatal("erased although the write failed")
	}
	f.fail.Store(false)
	signal(e.in.wake)
	eventually(t, "erased secrets", func() bool { return len(e.in.live()) == 0 })

	e.stopFn()
	f.failGet.Store(true)
	if _, err := Open(f, e.id, nil); !errors.Is(err, errDisk) {
		t.Fatalf("Open with failing reads = %v", err)
	}
	f.failGet.Store(false)
	e.start(nil)
}

func TestJoinersKeptAcrossRestart(t *testing.T) {
	e := newEnv(t, &Options{MaxEvents: 1})
	auto, _ := e.create(&CreateOptions{MaxUses: 3, Payload: []byte("p")})
	manual, _ := e.create(&CreateOptions{Manual: true})
	a, b := generate(t), generate(t)
	if _, err := e.joinAs(e.dial(a), a, auto, []byte("Ann")); err != nil {
		t.Fatal(err)
	}
	e.clk.add(time.Second)
	done := make(chan error, 1)
	go func() { _, err := e.joinAs(e.dial(b), b, manual, []byte("Ben")); done <- err }()
	var req Event
	for req.Kind != Requested {
		req = e.next()
	}
	if err := e.in.Approve(req.Request, []byte("q")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Both Joined events carry the joiner's data; MaxEvents 1 keeps only the last event (Ended).
	if s := e.in.Stats(); s.EventsDropped == 0 {
		t.Fatalf("Stats = %+v", s)
	}
	at := e.clk.now()
	e.stopFn()
	e.start(nil)
	for _, c := range []struct {
		code Code
		key  []byte
		data string
	}{{auto, a.PublicKey(), "Ann"}, {manual, b.PublicKey(), "Ben"}} {
		js, err := e.in.Joiners(c.code.ID())
		if err != nil || len(js) != 1 || !bytes.Equal(js[0].Key, c.key) || string(js[0].Data) != c.data ||
			js[0].Joined.After(at) || js[0].Joined.Before(at.Add(-time.Second)) {
			t.Fatalf("Joiners = %+v, %v", js, err)
		}
	}
	if _, err := e.in.Joiners(ID{1}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestJoinedEventsCarryData(t *testing.T) {
	e := newEnv(t, nil)
	auto, _ := e.create(&CreateOptions{Payload: []byte("p")})
	if _, err := e.join(auto, []byte("Ann")); err != nil {
		t.Fatal(err)
	}
	if ev := e.next(); ev.Kind != Joined || string(ev.Data) != "Ann" {
		t.Fatalf("auto Joined = %+v", ev)
	}
	manual, _ := e.create(&CreateOptions{Manual: true})
	go e.join(manual, []byte("Ben"))
	var ev Event
	for ev.Kind != Requested {
		ev = e.next()
	}
	e.in.Approve(ev.Request, nil)
	for ev.Kind != Joined {
		ev = e.next()
	}
	if string(ev.Data) != "Ben" {
		t.Fatalf("manual Joined = %+v", ev)
	}
}

func TestClockSetBackKeepsEnd(t *testing.T) {
	e := newEnvLinger(t, nil, time.Minute)
	code, _ := e.create(&CreateOptions{TTL: time.Minute})
	e.clk.add(time.Minute + time.Second)
	if _, err := e.join(code, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired = %v", err)
	}
	raw, err := e.db.Get(inviteKey(code.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := decodeRecord(code.ID(), raw); r.ended == 0 {
		t.Fatal("the end of an expired invite was not stored")
	}
	// Within the linger time, a clock set back does not reopen the invite.
	e.clk.add(-10 * time.Second)
	if _, err := e.join(code, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("after the clock went back = %v, want ErrExpired", err)
	}
	// After the secret is erased, neither does it, and the refusal stays "expired".
	e.clk.add(5 * time.Minute)
	signal(e.in.wake)
	eventually(t, "erase", func() bool { return len(e.in.live()) == 0 })
	e.clk.add(-time.Hour)
	if _, err := e.join(code, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("after erase and clock back = %v, want ErrExpired", err)
	}
	if l := e.list(); l[0].State != Expired || e.in.Stats().Active != 0 {
		t.Fatalf("List = %+v", l)
	}
	// And across a restart.
	e.stopFn()
	e.start(nil)
	if l := e.list(); l[0].State != Expired {
		t.Fatalf("List after restart = %+v", l)
	}
}

func TestExpiryWhileDownIsStored(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{TTL: time.Minute})
	e.stopFn()
	e.clk.add(2 * time.Minute)
	e.start(nil)
	eventually(t, "stored end", func() bool {
		raw, _ := e.db.Get(inviteKey(code.ID()))
		r, err := decodeRecord(code.ID(), raw)
		return err == nil && r.ended != 0
	})
	e.clk.add(-time.Hour)
	if l := e.list(); l[0].State != Expired {
		t.Fatalf("List = %+v", l)
	}
}

func TestConcurrentApprove(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	res := make(chan error, 2)
	for range 2 {
		go func() { _, err := e.join(code, nil); res <- err }()
	}
	a, b := e.next(), e.next()
	errs := make(chan error, 2)
	go func() { errs <- e.in.Approve(a.Request, []byte("x")) }()
	go func() { errs <- e.in.Approve(b.Request, []byte("y")) }()
	e1, e2 := <-errs, <-errs
	if !(e1 == nil && errors.Is(e2, ErrUsedUp) || e2 == nil && errors.Is(e1, ErrUsedUp)) {
		t.Fatalf("Approve = %v, %v; want one nil and one ErrUsedUp", e1, e2)
	}
	j1, j2 := <-res, <-res
	if !(j1 == nil && errors.Is(j2, ErrUsedUp) || j2 == nil && errors.Is(j1, ErrUsedUp)) {
		t.Fatalf("joins = %v, %v", j1, j2)
	}
	if l := e.list(); l[0].Used != 1 {
		t.Fatalf("Used = %d", l[0].Used)
	}
}
