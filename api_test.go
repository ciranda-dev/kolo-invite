package invite

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"
)

func TestOptionsDefaults(t *testing.T) {
	o, err := (*Options)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	want := Options{Timeout: 30 * time.Second, MaxData: 64 << 10, MaxPending: 1024, MaxPendingPerSource: 16,
		MaxPendingDevices: 4, DevicePendingTTL: 2 * time.Minute, MaxDeviceName: 64, MaxStreams: 8, SourceRate: 60, InviteRate: 600, MaxSources: 4096, MaxEvents: 1024}
	if o != want {
		t.Fatalf("defaults = %+v", o)
	}
	set := Options{Timeout: 1, PendingTTL: 10, MaxData: 2, MaxPending: 3, MaxPendingPerSource: 4, MaxPendingDevices: 10, MaxDeviceName: 1,
		DevicePendingTTL: 11, MaxStreams: 5, SourceRate: 6, InviteRate: 7, MaxSources: 8, MaxEvents: 9}
	if o, _ := set.withDefaults(); o != set {
		t.Fatalf("set values changed: %+v", o)
	}
	for _, bad := range []Options{{Timeout: -1}, {PendingTTL: -1}, {DevicePendingTTL: -1}, {MaxPendingDevices: -1}, {MaxDeviceName: -1}, {MaxDeviceName: 100, MaxData: 50}, {MaxData: -1}, {MaxPending: -1}, {MaxPendingPerSource: -1},
		{MaxStreams: -1}, {SourceRate: -1}, {InviteRate: -1}, {MaxSources: -1}, {MaxEvents: -1}, {MaxData: maxSend + 1}} {
		if _, err := bad.withDefaults(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestOpenArguments(t *testing.T) {
	checkGoroutines(t)
	db := kolostore.NewMemory()
	defer db.Close()
	if _, err := Open(nil, generate(t), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := Open(db, nil, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := Open(db, generate(t), &Options{MaxPending: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestCreateArguments(t *testing.T) {
	e := newEnv(t, nil)
	for name, c := range map[string]struct {
		o    *CreateOptions
		want error
	}{
		"negative TTL":        {&CreateOptions{TTL: -1}, ErrInvalidArgument},
		"negative uses":       {&CreateOptions{MaxUses: -1}, ErrInvalidArgument},
		"payload too large":   {&CreateOptions{Payload: make([]byte, maxSend+1)}, ErrTooLarge},
		"manual with payload": {&CreateOptions{Manual: true, Payload: []byte{1}}, ErrInvalidArgument},
		"TTL too long":        {&CreateOptions{TTL: time.Duration(1<<63 - 1)}, ErrInvalidArgument},
	} {
		if _, _, err := e.in.Create(c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.list()) != 0 {
		t.Fatal("a refused Create stored an invite")
	}
	if _, _, err := e.in.Create(nil); err != nil {
		t.Fatal(err)
	}
	e.clk.add(time.Second)
	code, _ := e.create(&CreateOptions{MaxUses: 1 << 30})
	if l := e.list(); len(l) != 2 || l[1].ID != code.ID() || l[1].MaxUses != 1<<30 {
		t.Fatalf("List is not oldest first: %+v", l)
	}
}

func TestIDCollision(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	e.in.mu.Lock()
	e.in.invites[mustKeys(make([]byte, secretSize)).id] = e.in.invites[code.ID()]
	e.in.mu.Unlock()
	// Create draws a random secret; only the stored map entry matters, so put the zero secret's ID there and
	// replace the random source for one call.
	restore := randRead
	randRead = func(b []byte) error { clear(b); return nil }
	defer func() { randRead = restore }()
	if _, _, err := e.in.Create(nil); !errors.Is(err, ErrIDCollision) {
		t.Fatalf("Create = %v, want ErrIDCollision", err)
	}
}

func TestDataLimits(t *testing.T) {
	e := newEnv(t, &Options{MaxData: 1000})
	code, _ := e.create(&CreateOptions{Manual: true, MaxUses: 2})
	data := bytes.Repeat([]byte{1}, 1000)
	big := bytes.Repeat([]byte{2}, 200_000)
	done := make(chan []byte, 1)
	go func() { p, _ := e.join(code, data); done <- p }()
	ev := e.next()
	if !bytes.Equal(ev.Data, data) {
		t.Fatal("data of MaxData did not arrive")
	}
	if err := e.in.Approve(ev.Request, big); err != nil {
		t.Fatal(err)
	}
	if p := <-done; !bytes.Equal(p, big) {
		t.Fatal("a large payload did not arrive")
	}
	if _, err := e.join(code, append(data, 0)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("data over MaxData = %v, want ErrTooLarge", err)
	}
	if _, err := e.join(code, bytes.Repeat([]byte{3}, 100_000)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("data far over MaxData = %v, want ErrTooLarge", err)
	}
	if s := e.in.Stats(); s.RefusedLarge != 2 {
		t.Fatalf("Stats = %+v", s)
	}

	// The joiner bounds the payload it accepts.
	auto, _ := e.create(&CreateOptions{Payload: big})
	id := generate(t)
	c := e.dial(id)
	if _, err := JoinConn(e.ctx, c, id, auto, &JoinOptions{MaxPayload: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("payload over MaxPayload = %v, want ErrTooLarge", err)
	}
	if p, err := JoinConn(e.ctx, c, id, auto, &JoinOptions{MaxPayload: len(big)}); err != nil || !bytes.Equal(p, big) {
		t.Fatalf("payload of MaxPayload = %v", err)
	}
	if err := e.in.Approve(1, make([]byte, maxSend+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Approve with a payload too large = %v", err)
	}
}

func TestJoinConnArguments(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	id := generate(t)
	c := e.dial(id)
	for name, f := range map[string]func() error{
		"nil conn":    func() error { _, err := JoinConn(e.ctx, nil, id, code, nil); return err },
		"nil id":      func() error { _, err := JoinConn(e.ctx, c, nil, code, nil); return err },
		"zero code":   func() error { _, err := JoinConn(e.ctx, c, id, Code{}, nil); return err },
		"neg payload": func() error { _, err := JoinConn(e.ctx, c, id, code, &JoinOptions{MaxPayload: -1}); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := JoinConn(e.ctx, c, id, code, &JoinOptions{Data: make([]byte, maxSend+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	if _, err := JoinConn(ctx, c, id, code, nil); !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx = %v", err)
	}
}

func TestServeArguments(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.in.Announce(e.ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if err := e.in.ServePeer(e.ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if err := e.in.ServePeer(e.ctx, testPeer{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}

func TestClose(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	received, done := e.joinReceived(e.dial(id), id, code)
	ev := e.next()
	next := make(chan error, 1)
	go func() {
		e.in.Next(e.ctx)
		_, err := e.in.Next(context.Background())
		next <- err
	}()
	<-received
	eventually(t, "Next waiting", func() bool { return blockedIn("(*Inviter).Next") })
	if err := e.in.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.in.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if err := <-next; !errors.Is(err, ErrClosed) {
		t.Fatalf("Next = %v", err)
	}
	if err := <-done; !errors.Is(err, ErrNotAnswered) {
		t.Fatalf("join after Close = %v, want ErrNotAnswered", err)
	}
	_, _, cerr := e.in.Create(nil)
	_, lerr := e.in.List()
	_, jerr := e.in.Joiners(code.ID())
	for name, err := range map[string]error{"Create": cerr, "List": lerr, "Joiners": jerr,
		"Revoke": e.in.Revoke(code.ID()), "Approve": e.in.Approve(ev.Request, nil), "Deny": e.in.Deny(ev.Request),
		"ServePeer": e.in.ServePeer(e.ctx, testPeer{conn: e.dial(generate(t))})} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if s := e.in.Stats(); s.Active != 1 {
		t.Fatalf("Stats after Close = %+v", s)
	}
}

func TestStrings(t *testing.T) {
	for s, want := range map[State]string{Active: "active", Expired: "expired", UsedUp: "used up", Revoked: "revoked",
		State(9): "State(9)"} {
		if s.String() != want {
			t.Errorf("%d: %q", int(s), s.String())
		}
	}
	for k, want := range map[EventKind]string{Requested: "requested", Withdrawn: "withdrawn", Joined: "joined",
		Ended: "ended", EventKind(9): "EventKind(9)"} {
		if k.String() != want {
			t.Errorf("%d: %q", int(k), k.String())
		}
	}
	if (ID{0xab}).String() != "ab000000000000000000000000000000" {
		t.Fatal(ID{0xab}.String())
	}
	var zero Code
	if zero.ID() != (ID{}) || zero.Topic() != [32]byte{} || zero.Matches(generate(t).PublicKey()) {
		t.Fatal("zero Code")
	}
}
