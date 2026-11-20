package invite

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func TestDecodersRejectOtherVersions(t *testing.T) {
	secret := make([]byte, secretSize)
	id := mustKeys(secret).id
	rec := (&record{secret: secret, created: 1, maxUses: 1}).encode()
	req := request{auth: make([]byte, 32), joiner: make([]byte, 32), answerKey: make([]byte, 32), sig: make([]byte, 64)}
	other := func(b []byte) []byte { b = append([]byte(nil), b...); b[0] = 2; return b }
	if _, err := decodeRecord(id, other(rec)); err == nil {
		t.Error("record")
	}
	if _, err := decodeJoined(other(joined{}.encode())); err == nil {
		t.Error("joined")
	}
	if err := decodeDenied(other(encodeVersion())); err == nil {
		t.Error("deny")
	}
	if _, err := decodeMeta(other(encodeMeta(make([]byte, 32)))); err == nil {
		t.Error("meta")
	}
	if _, err := decodeRequest(other(req.plaintext())); !errors.Is(err, ErrInvalid) {
		t.Error("request")
	}
	if _, err := decodeAnswer(other(answer{kind: kindDenied}.encode())); !errors.Is(err, ErrProtocol) {
		t.Error("answer")
	}
	if _, err := decodeMsg(other(msg{typ: msgOpen}.encode())); !errors.Is(err, ErrProtocol) {
		t.Error("message")
	}
	bad := msg{typ: msgRefused, code: refBusy}.encode()
	bad[len(bad)-1] = 1
	if _, err := decodeMsg(bad); !errors.Is(err, ErrProtocol) {
		t.Error("refusal with non-zero padding")
	}
	pt := req.plaintext()
	pt[len(pt)-1] = 1
	if _, err := decodeRequest(pt); !errors.Is(err, ErrInvalid) {
		t.Error("request with non-zero padding")
	}
	if _, err := decodeRequest(pt[:len(pt)-1]); !errors.Is(err, ErrInvalid) {
		t.Error("request with short padding")
	}
}

func TestLowOrderKeysRefused(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(nil)
	id := generate(t)
	c := e.dial(id)
	// An answer key of zeros (a low-order X25519 point) fails before a use is counted.
	r := e.raw(c)
	nonce := r.challenge()
	r.send(sealRequest(t, code, e.id.PublicKey(), nonce, request{auth: code.c.k.auth[:], joiner: id.PublicKey(),
		answerKey: make([]byte, encSize)}, id))
	r.refused(refInvalid)
	// A zero encapsulated key does not decapsulate.
	r = e.raw(c)
	req := e.request(code, id, nil, r.challenge())
	req.enc = make([]byte, encSize)
	r.send(req)
	r.refused(refInvalid)
	if l := e.list(); l[0].Used != 0 {
		t.Fatalf("Used = %d", l[0].Used)
	}
}

func TestTruncatedFrame(t *testing.T) {
	e := newEnv(t, nil)
	r := e.raw(e.dial(generate(t)))
	r.challenge()
	r.st.Write([]byte{10, 0, 0, 0, 1, 2})
	r.st.Close()
	r.reset()
}

func TestPayloadJustOverMaxPayload(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Payload: make([]byte, 1100)})
	id := generate(t)
	if _, err := JoinConn(e.ctx, e.dial(id), id, code, &JoinOptions{MaxPayload: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("JoinConn = %v, want ErrTooLarge", err)
	}
}

func TestListBeforeExpiryIsHandled(t *testing.T) {
	e := newEnv(t, nil)
	_, info := e.create(&CreateOptions{TTL: time.Minute})
	e.clk.add(time.Minute)
	if l := e.list(); l[0].State != Expired || !l[0].Ended.Equal(info.Expires) {
		t.Fatalf("List = %+v", l)
	}
}

func TestNextContext(t *testing.T) {
	e := newEnv(t, nil)
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	if _, err := e.in.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := e.in.Next(context.Background()); done <- err }()
	eventually(t, "Next waiting", func() bool { return blockedIn("(*Inviter).Next") })
	e.in.Close()
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestGoneRequestsBounded(t *testing.T) {
	e := newEnv(t, &Options{MaxPending: 1})
	var reqs []RequestID
	for range 2 {
		code, _ := e.create(&CreateOptions{Manual: true})
		done := make(chan error, 1)
		go func() { _, err := e.join(code, nil); done <- err }()
		var ev Event
		for ev.Kind != Requested {
			ev = e.next()
		}
		reqs = append(reqs, ev.Request)
		e.in.Revoke(code.ID())
		<-done
	}
	if err := e.in.Approve(reqs[0], nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest gone request = %v, want ErrNotFound past MaxPending", err)
	}
	if err := e.in.Approve(reqs[1], nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("latest gone request = %v, want ErrRevoked", err)
	}
}

func TestUnsavedEndRetried(t *testing.T) {
	e := newEnv(t, nil)
	e.stopFn()
	f := &faulty{Backend: e.db}
	e.db = f
	e.start(nil)
	code, _ := e.create(&CreateOptions{TTL: time.Minute})
	f.fail.Store(true)
	e.clk.add(time.Minute)
	if _, err := e.join(code, nil); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	before := f.failed.Load()
	signal(e.in.wake)
	eventually(t, "a failed save", func() bool { return f.failed.Load() > before })
	raw, _ := f.Backend.Get(inviteKey(code.ID()))
	if r, _ := decodeRecord(code.ID(), raw); r.ended != 0 {
		t.Fatal("stored while writes fail")
	}
	f.fail.Store(false)
	signal(e.in.wake)
	eventually(t, "stored end", func() bool {
		raw, _ := f.Backend.Get(inviteKey(code.ID()))
		r, _ := decodeRecord(code.ID(), raw)
		return r.ended != 0
	})
}

func TestStorageReadFailures(t *testing.T) {
	e := newEnv(t, nil)
	e.stopFn()
	f := &faulty{Backend: e.db}
	e.db = f
	e.start(nil)
	code, _ := e.create(&CreateOptions{MaxUses: 5})
	if _, err := e.join(code, nil); err != nil {
		t.Fatal(err)
	}
	// A failing read of the stored deny answers busy.
	f.getOnly.Store(int32(pDenied))
	f.failGet.Store(true)
	if _, err := e.join(code, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("join = %v, want ErrBusy", err)
	}
	f.failGet.Store(false)
	// Joiners reports a failing scan and a corrupt stored accept.
	f.failScan.Store(true)
	if _, err := e.in.Joiners(code.ID()); !errors.Is(err, errDisk) {
		t.Fatalf("Joiners = %v", err)
	}
	f.failScan.Store(false)
	e.db.Put(joinerKey(pAccepted, code.ID(), make([]byte, 32)), []byte{9})
	if _, err := e.in.Joiners(code.ID()); !errors.Is(err, kolostore.ErrCorrupt) {
		t.Fatalf("Joiners = %v", err)
	}
	e.stopFn()
	// Open reports a failing scan and a failing first write.
	f.failScan.Store(true)
	if _, err := Open(f, e.id, nil); !errors.Is(err, errDisk) || !strings.HasPrefix(err.Error(), "invite: store: ") {
		t.Fatalf("Open = %v", err)
	}
	f.failScan.Store(false)
	f.getOnly.Store(0)
	f.failGet.Store(true)
	if _, err := Open(f, e.id, nil); !errors.Is(err, errDisk) || !strings.HasPrefix(err.Error(), "invite: store: ") {
		t.Fatalf("Open with a failing read = %v", err)
	}
	f.failGet.Store(false)
	empty := &faulty{Backend: kolostore.NewMemory()}
	defer empty.Close()
	empty.failScan.Store(true)
	if _, err := Open(empty, e.id, nil); !errors.Is(err, errDisk) || !strings.HasPrefix(err.Error(), "invite: store: ") {
		t.Fatalf("Open of an empty store = %v", err)
	}
	empty.failScan.Store(false)
	empty.fail.Store(true)
	if _, err := Open(empty, e.id, nil); !errors.Is(err, errDisk) || !strings.HasPrefix(err.Error(), "invite: store: ") {
		t.Fatalf("Open of an empty store = %v", err)
	}
	f.Delete(joinerKey(pAccepted, code.ID(), make([]byte, 32)))
	e.start(nil)
}

func TestServePeerEnds(t *testing.T) {
	e := newEnv(t, nil)
	code, _ := e.create(&CreateOptions{Manual: true})
	ln, err := newListener(e)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 2)
	ctx, cancel := context.WithCancel(e.ctx)
	go func() {
		c, err := ln.Accept(e.ctx)
		if err != nil {
			served <- err
			return
		}
		served <- e.in.ServePeer(ctx, testPeer{conn: c, addr: netip.MustParseAddrPort("10.9.9.9:1")})
	}()
	id := generate(t)
	c := dialListener(t, e, ln, id)
	received, done := e.joinReceived(c, id, code)
	e.next()
	<-received
	cancel() // the pending request is withdrawn when ServePeer's context ends
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Fatalf("ServePeer = %v", err)
	}
	if err := <-done; !errors.Is(err, ErrNotAnswered) {
		t.Fatalf("join = %v", err)
	}
	if w := e.next(); w.Kind != Withdrawn {
		t.Fatalf("event = %+v", w)
	}

	// ServePeer returns nil when the connection ends, and ErrClosed when the Inviter closes.
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept(e.ctx)
		close(accepted)
		if err != nil {
			served <- err
			return
		}
		served <- e.in.ServePeer(e.ctx, testPeer{conn: c})
	}()
	pc := dialListener(t, e, ln, generate(t))
	<-accepted
	pc.Close()
	if err := <-served; err != nil {
		t.Fatalf("ServePeer after the peer closed = %v", err)
	}
	go func() {
		c, err := ln.Accept(e.ctx)
		if err != nil {
			served <- err
			return
		}
		served <- e.in.ServePeer(e.ctx, testPeer{conn: c, topics: []koloswarm.Topic{{1}}})
	}()
	dialListener(t, e, ln, generate(t))
	eventually(t, "ServePeer running", func() bool { return blockedIn("(*Inviter).ServePeer") })
	e.in.Close()
	if err := <-served; !errors.Is(err, ErrClosed) {
		t.Fatalf("ServePeer after Close = %v", err)
	}
}

// TestAnnounceLeavesAndRetries runs Announce on a swarm of one topic with a short linger time.
func TestAnnounceLeavesAndRetries(t *testing.T) {
	e := newEnvLinger(t, nil, 300*time.Millisecond)
	ctx := e.ctx
	server, err := kolodht.New(ctx, "127.0.0.1:0", generate(t), &kolodht.Config{Server: true})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	sw, err := koloswarm.New(ctx, "127.0.0.1:0", e.id, &koloswarm.Config{MaxTopics: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	if err := sw.Bootstrap(ctx, []netip.AddrPort{server.Addr().(*net.UDPAddr).AddrPort()}); err != nil {
		t.Fatal(err)
	}
	first, _ := e.create(nil)
	e.clk.add(time.Second)
	e.create(nil)
	actx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.in.Announce(actx, sw) }()
	eventually(t, "first announced", func() bool { return e.in.Stats().Announced == 1 })
	time.Sleep(3500 * time.Millisecond) // the second invite fails to join at 0s, 1s and 3s
	if err := e.in.Revoke(first.ID()); err != nil {
		t.Fatal(err)
	}
	e.clk.add(time.Second)
	signal(e.in.wake)
	// The first topic is left after its linger time and the second takes its place.
	eventually(t, "second announced", func() bool { return len(e.in.live()) == 1 && e.in.Stats().Announced == 1 })
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Announce = %v", err)
	}
	if e.in.Stats().Announced != 0 {
		t.Fatal("Announced after Announce returned")
	}
}

func TestPrefixEnd(t *testing.T) {
	for in, want := range map[string]string{"a\x01": "a\x02", "a\xff": "b", "a\x01\xff\xff": "a\x02"} {
		if got := string(prefixEnd([]byte(in))); got != want {
			t.Errorf("prefixEnd(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdleRuleSparesRunningStreams(t *testing.T) {
	e := newEnv(t, &Options{Timeout: 200 * time.Millisecond})
	e.topics = nil // every connection shares only invite topics
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	c := e.dial(id)
	done := make(chan []byte, 1)
	go func() { p, _ := e.joinAs(c, id, code, nil); done <- p }()
	ev := e.next()
	time.Sleep(time.Second) // five times Timeout with the request pending
	if err := e.in.Approve(ev.Request, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if p := <-done; string(p) != "ok" {
		t.Fatal("a connection with a pending request was closed for being idle")
	}
	// Once nothing runs, the connection is closed after Timeout.
	select {
	case <-c.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("an idle invite-only connection stayed open")
	}
	if s := e.in.Stats(); s.IdleClosed != 1 {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestReadFrameAllocatesWhatArrives(t *testing.T) {
	const declared = 1 << 30
	r, w := io.Pipe()
	defer r.Close()
	go func() {
		w.Write(binary.LittleEndian.AppendUint32(nil, declared))
		w.Write([]byte("short"))
		w.CloseWithError(io.EOF)
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readFrame(r, declared)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readFrame = %v, want ErrUnexpectedEOF", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("a header and 5 bytes allocated %d bytes", got)
	}

	for name, c := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":       {nil, io.EOF},
		"header only": {[]byte{3, 0, 0, 0}, io.EOF},
		"cut body":    {[]byte{3, 0, 0, 0, 1}, io.ErrUnexpectedEOF},
		"too long":    {[]byte{9, 0, 0, 0}, errFrame},
	} {
		if _, err := readFrame(bytes.NewReader(c.in), 8); !errors.Is(err, c.want) {
			t.Errorf("%s: readFrame = %v, want %v", name, err, c.want)
		}
	}
	if b, err := readFrame(bytes.NewReader([]byte{3, 0, 0, 0, 1, 2, 3, 4}), 8); err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Errorf("readFrame = %v, %v", b, err)
	}
	if b, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 8); err != nil || len(b) != 0 {
		t.Errorf("empty frame = %v, %v", b, err)
	}
}

func TestPendingTTLWithdraws(t *testing.T) {
	e := newEnv(t, &Options{PendingTTL: 300 * time.Millisecond})
	code, _ := e.create(&CreateOptions{Manual: true})
	id := generate(t)
	received, done := e.joinReceived(e.dial(id), id, code)
	ev := e.next()
	<-received
	if w := e.next(); w.Kind != Withdrawn || w.Request != ev.Request {
		t.Fatalf("event = %+v, want Withdrawn", w)
	}
	if err := <-done; !errors.Is(err, ErrNotAnswered) {
		t.Fatalf("join = %v, want ErrNotAnswered", err)
	}
	if s := e.in.Stats(); s.Pending != 0 {
		t.Fatalf("Pending = %d", s.Pending)
	}
	if err := e.in.Approve(ev.Request, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Approve = %v, want ErrNotFound", err)
	}
	// A request decided before the TTL is not withdrawn.
	e2 := newEnv(t, &Options{PendingTTL: time.Hour})
	code2, _ := e2.create(&CreateOptions{Manual: true})
	go func() { e2.in.Approve(e2.next().Request, []byte("ok")) }()
	if p, err := e2.join(code2, nil); err != nil || string(p) != "ok" {
		t.Fatalf("join = %q, %v", p, err)
	}
}
