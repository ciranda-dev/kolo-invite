package invite_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	invite "github.com/ciranda-dev/kolo-invite"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func generate(t *testing.T) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// network is a kolo-dht server and an inviter application on one swarm with one event loop, on 127.0.0.1.
type network struct {
	ctx    context.Context
	server netip.AddrPort
	iid    *koloid.Identity
	isw    *koloswarm.Swarm
	in     *invite.Inviter
	group  koloswarm.Topic // another topic the inviter's swarm announces
}

func newSwarm(t *testing.T, ctx context.Context, id *koloid.Identity, server netip.AddrPort, cfg koloswarm.Config) *koloswarm.Swarm {
	t.Helper()
	cfg.LookupInterval = time.Second
	sw, err := koloswarm.New(ctx, "127.0.0.1:0", id, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sw.Close() })
	if err := sw.Bootstrap(ctx, []netip.AddrPort{server}); err != nil {
		t.Fatal(err)
	}
	return sw
}

func newNetwork(t *testing.T, opts *invite.Options, cfg koloswarm.Config) *network {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	server, err := kolodht.New(ctx, "127.0.0.1:0", generate(t), &kolodht.Config{Server: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	n := &network{ctx: ctx, server: server.Addr().(*net.UDPAddr).AddrPort(), iid: generate(t),
		group: koloswarm.Topic{0x67}}
	db := kolostore.NewMemory()
	t.Cleanup(func() { db.Close() })
	if n.in, err = invite.Open(db, n.iid, opts); err != nil {
		t.Fatal(err)
	}
	n.isw = newSwarm(t, ctx, n.iid, n.server, cfg)
	if err := n.isw.Join(ctx, n.group, &koloswarm.JoinOptions{Announce: true}); err != nil {
		t.Fatal(err)
	}
	// The application: Announce, and one event loop that serves invites on every connected peer.
	actx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := n.in.Announce(actx, n.isw); !errors.Is(err, context.Canceled) {
			t.Errorf("Announce = %v", err)
		}
	})
	wg.Go(func() {
		for {
			ev, err := n.isw.Next(actx)
			if err != nil {
				return
			}
			if ev.Kind == koloswarm.Connected {
				wg.Go(func() { n.in.ServePeer(actx, ev.Peer) })
			}
		}
	})
	t.Cleanup(func() {
		stop()
		wg.Wait()
		n.in.Close()
	})
	return n
}

func (n *network) create(t *testing.T, o *invite.CreateOptions) invite.Code {
	t.Helper()
	s, _, err := n.in.Create(o)
	if err != nil {
		t.Fatal(err)
	}
	code, err := invite.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// connect joins topic on sw and returns the connection to the peer that match accepts.
func connect(t *testing.T, ctx context.Context, sw *koloswarm.Swarm, topic koloswarm.Topic, match func(*koloswarm.Peer) bool) koloswarm.Conn {
	t.Helper()
	if err := sw.Join(ctx, topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
		t.Fatal(err)
	}
	for {
		ev, err := sw.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind == koloswarm.Connected && match(ev.Peer) {
			return ev.Peer.Conn()
		}
	}
}

func inviterOf(code invite.Code) func(*koloswarm.Peer) bool {
	return func(p *koloswarm.Peer) bool { return code.Matches(p.PublicKey()) }
}

func TestJoinOverSwarm(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	code := n.create(t, &invite.CreateOptions{Payload: []byte("log id and capability")})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, code.Topic(), inviterOf(code))
	p, err := invite.JoinConn(n.ctx, conn, jid, code, &invite.JoinOptions{Data: []byte("Alice")})
	if err != nil || string(p) != "log id and capability" {
		t.Fatalf("JoinConn = %q, %v", p, err)
	}
	ev, err := n.in.Next(n.ctx)
	if err != nil || ev.Kind != invite.Joined || !ev.Joiner.Equal(jid.PublicKey()) || string(ev.Data) != "Alice" {
		t.Fatalf("event = %+v, %v", ev, err)
	}
	// Asking again on the same connection gets the same accept.
	if p, err := invite.JoinConn(n.ctx, conn, jid, code, nil); err != nil || string(p) != "log id and capability" {
		t.Fatalf("second JoinConn = %q, %v", p, err)
	}
	if s := n.in.Stats(); s.Accepted != 1 || s.Announced != 1 {
		t.Fatalf("Stats = %+v", s)
	}
	jsw.Leave(code.Topic())
}

func TestManualOverSwarm(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	approve := n.create(t, &invite.CreateOptions{Manual: true})
	deny := n.create(t, &invite.CreateOptions{Manual: true})
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		for {
			ev, err := n.in.Next(n.ctx)
			if err != nil {
				return
			}
			if ev.Kind != invite.Requested {
				continue
			}
			if ev.Invite == approve.ID() {
				n.in.Approve(ev.Request, []byte("welcome "+string(ev.Data)))
				continue
			}
			n.in.Deny(ev.Request)
			return
		}
	})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, approve.Topic(), inviterOf(approve))
	if p, err := invite.JoinConn(n.ctx, conn, jid, approve, &invite.JoinOptions{Data: []byte("Bob")}); err != nil || string(p) != "welcome Bob" {
		t.Fatalf("JoinConn = %q, %v", p, err)
	}
	// One connection serves every invite of the inviter.
	if _, err := invite.JoinConn(n.ctx, conn, jid, deny, nil); !errors.Is(err, invite.ErrDenied) {
		t.Fatalf("JoinConn = %v, want ErrDenied", err)
	}
}

func TestExistingContactJoins(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, n.group, func(p *koloswarm.Peer) bool { return p.PublicKey().Equal(n.iid.PublicKey()) })

	// The invite comes later; the joiner uses the connection it already has, without the invite topic.
	code := n.create(t, &invite.CreateOptions{Payload: []byte("p")})
	if !code.Matches(conn.RemotePublicKey()) {
		t.Fatal("the contact is not the inviter")
	}
	if p, err := invite.JoinConn(n.ctx, conn, jid, code, nil); err != nil || string(p) != "p" {
		t.Fatalf("JoinConn by an existing contact = %q, %v", p, err)
	}
}

func TestConcurrentJoinsOneSwarm(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	a := n.create(t, &invite.CreateOptions{Payload: []byte("a")})
	b := n.create(t, &invite.CreateOptions{Payload: []byte("b")})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	if err := jsw.Join(n.ctx, b.Topic(), &koloswarm.JoinOptions{Lookup: true}); err != nil {
		t.Fatal(err)
	}
	conn := connect(t, n.ctx, jsw, a.Topic(), inviterOf(a))
	var wg sync.WaitGroup
	got := make([][]byte, 2)
	errs := make([]error, 2)
	for i, code := range []invite.Code{a, b} {
		wg.Go(func() { got[i], errs[i] = invite.JoinConn(n.ctx, conn, jid, code, nil) })
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || string(got[0]) != "a" || string(got[1]) != "b" {
		t.Fatalf("concurrent JoinConn = %q %q, %v %v", got[0], got[1], errs[0], errs[1])
	}
}

func TestIdleTopicSquatterClosed(t *testing.T) {
	n := newNetwork(t, &invite.Options{Timeout: time.Second}, koloswarm.Config{MaxPeers: 2, MaxInbound: 1})
	code := n.create(t, &invite.CreateOptions{Payload: []byte("p")})

	// A peer that knows only the topic, as a DHT node can, connects and stays idle.
	squatter := newSwarm(t, n.ctx, generate(t), n.server, koloswarm.Config{})
	sconn := connect(t, n.ctx, squatter, code.Topic(), inviterOf(code))
	select {
	case <-sconn.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the idle squatter still holds its connection")
	}
	squatter.Leave(code.Topic())

	// The single inbound slot is free again for a real joiner.
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, code.Topic(), inviterOf(code))
	if p, err := invite.JoinConn(n.ctx, conn, jid, code, nil); err != nil || string(p) != "p" {
		t.Fatalf("JoinConn = %q, %v", p, err)
	}
	if s := n.in.Stats(); s.IdleClosed == 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestOneLoopKeepsOtherTopics(t *testing.T) {
	n := newNetwork(t, &invite.Options{Timeout: 500 * time.Millisecond}, koloswarm.Config{})
	n.create(t, nil)
	// A peer of the application's other topic shares one connection with the invite service and is never closed
	// for being idle.
	member := newSwarm(t, n.ctx, generate(t), n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, member, n.group, func(p *koloswarm.Peer) bool { return p.PublicKey().Equal(n.iid.PublicKey()) })
	select {
	case <-conn.Context().Done():
		t.Fatal("the invite side closed a connection of another topic")
	case <-time.After(3 * time.Second):
	}
	if s := n.in.Stats(); s.IdleClosed != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestAnnounceRules(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	n.create(t, nil)
	invite.Eventually(t, "announced", func() bool { return n.in.Stats().Announced == 1 })
	if err := n.in.Announce(n.ctx, n.isw); !errors.Is(err, invite.ErrBusy) {
		t.Fatalf("second Announce = %v, want ErrBusy", err)
	}
	other := newSwarm(t, n.ctx, generate(t), n.server, koloswarm.Config{})
	if err := n.in.Announce(n.ctx, other); !errors.Is(err, invite.ErrInvalidArgument) {
		t.Fatalf("Announce on another identity's swarm = %v, want ErrInvalidArgument", err)
	}

	// Announce returns ErrClosed when the Inviter closes, and ServePeer ends then too.
	db := kolostore.NewMemory()
	defer db.Close()
	iid := generate(t)
	in, err := invite.Open(db, iid, nil)
	if err != nil {
		t.Fatal(err)
	}
	sw := newSwarm(t, n.ctx, iid, n.server, koloswarm.Config{})
	done := make(chan error, 1)
	go func() { done <- in.Announce(n.ctx, sw) }()
	invite.Eventually(t, "Announce running", func() bool { return invite.BlockedIn("(*Inviter).Announce") })
	in.Close()
	if err := <-done; !errors.Is(err, invite.ErrClosed) {
		t.Fatalf("Announce after Close = %v, want ErrClosed", err)
	}
	if err := in.Announce(n.ctx, sw); !errors.Is(err, invite.ErrClosed) {
		t.Fatalf("Announce on a closed Inviter = %v, want ErrClosed", err)
	}
}

func TestInvitesWaitForATopic(t *testing.T) {
	// The group topic takes the swarm's only place at first; invites wait for it.
	n := newNetwork(t, nil, koloswarm.Config{MaxTopics: 2})
	first := n.create(t, nil)
	second := n.create(t, &invite.CreateOptions{Payload: []byte("second")})
	invite.Eventually(t, "announced", func() bool { return n.in.Stats().Announced == 1 })
	// The first invite holds the other place; leaving the group topic makes room for the second.
	n.isw.Leave(n.group)
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, second.Topic(), inviterOf(second))
	if p, err := invite.JoinConn(n.ctx, conn, jid, second, nil); err != nil || string(p) != "second" {
		t.Fatalf("JoinConn = %q, %v", p, err)
	}
	if first.Topic() == second.Topic() {
		t.Fatal("two invites share a topic")
	}
}

func TestJoinNotAnswered(t *testing.T) {
	n := newNetwork(t, nil, koloswarm.Config{})
	code := n.create(t, &invite.CreateOptions{Manual: true})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, code.Topic(), inviterOf(code))
	ctx, cancel := context.WithCancel(n.ctx)
	received := make(chan struct{})
	go func() {
		ev, err := n.in.Next(n.ctx)
		if err == nil && ev.Kind == invite.Requested {
			<-received
			cancel()
		}
	}()
	var opts invite.JoinOptions
	invite.OnReceived(&opts, func() { close(received) })
	if _, err := invite.JoinConn(ctx, conn, jid, code, &opts); !errors.Is(err, invite.ErrNotAnswered) ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("JoinConn = %v, want ErrNotAnswered", err)
	}
}

func TestJoinerMovesToGroup(t *testing.T) {
	n := newNetwork(t, &invite.Options{Timeout: time.Second}, koloswarm.Config{})
	code := n.create(t, &invite.CreateOptions{Payload: []byte("p")})
	jid := generate(t)
	jsw := newSwarm(t, n.ctx, jid, n.server, koloswarm.Config{})
	conn := connect(t, n.ctx, jsw, code.Topic(), inviterOf(code))
	if _, err := invite.JoinConn(n.ctx, conn, jid, code, nil); err != nil {
		t.Fatal(err)
	}
	// Leaving the invite topic first closes the invite-only connection at once.
	jsw.Leave(code.Topic())
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Leave kept the invite-only connection")
	}
	// The connection for the group topic is a new one, and the inviter sees the group topic on it.
	gconn := connect(t, n.ctx, jsw, n.group, func(p *koloswarm.Peer) bool { return p.PublicKey().Equal(n.iid.PublicKey()) })
	select {
	case <-gconn.Context().Done():
		t.Fatal("the group connection was closed")
	case <-time.After(3 * time.Second):
	}
	if s := n.in.Stats(); s.IdleClosed != 0 {
		t.Fatalf("Stats = %+v", s)
	}
}
