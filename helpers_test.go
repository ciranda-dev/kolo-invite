package invite

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/hpke"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// checkGoroutines fails the test if goroutines started after it are still running after the cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func testCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func generate(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// clock is a settable clock for the inviter.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_800_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is an inviter on a memory backend with a fake clock, serving kolo-secure connections on loopback.
type env struct {
	t      *testing.T
	ctx    context.Context
	id     *koloid.Identity
	db     kolostore.Backend
	clk    *clock
	in     *Inviter
	ln     *kolosecure.Listener
	src    func(c *kolosecure.Conn) string // source name per connection; nil means its remote IP
	srcMu  sync.Mutex
	linger time.Duration
	topics []koloswarm.Topic // what every connection shares, for the idle rule
	// stopFn stops the inviter and its listener, for a restart with start.
	stopFn func()
}

func newEnv(t *testing.T, opts *Options) *env { return newEnvLinger(t, opts, Linger) }

func newEnvLinger(t *testing.T, opts *Options, linger time.Duration) *env {
	t.Helper()
	return newEnvAs(t, generate(t), opts, linger)
}

// newEnvAs is newEnvLinger for an inviter with the given identity.
func newEnvAs(t *testing.T, id *koloid.Identity, opts *Options, linger time.Duration) *env {
	t.Helper()
	checkGoroutines(t)
	e := &env{t: t, ctx: testCtx(t), id: id, db: kolostore.NewMemory(), clk: newClock(), linger: linger,
		topics: []koloswarm.Topic{{0xee}}}
	t.Cleanup(func() { e.db.Close() })
	e.start(opts)
	return e
}

// start opens the inviter on e.db and serves connections until the test ends or stop is called.
func (e *env) start(opts *Options) {
	t := e.t
	in, err := open(e.db, e.id, opts, e.clk.now, e.linger)
	if err != nil {
		t.Fatal(err)
	}
	e.in = in
	ln, err := kolosecure.Listen(e.ctx, "127.0.0.1:0", e.id, &kolosecure.Config{MaxPending: 1000,
		Transport: &kolotransport.Config{MaxConns: 1000, MaxConnsPerIP: 1000, MaxIncomingStreams: 128}})
	if err != nil {
		t.Fatal(err)
	}
	e.ln = ln
	ctx, cancel := context.WithCancel(e.ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			src := c.RemoteAddr().(*net.UDPAddr).AddrPort().Addr().String()
			e.srcMu.Lock()
			if e.src != nil {
				src = e.src(c)
			}
			e.srcMu.Unlock()
			wg.Go(func() {
				defer c.Close()
				in.serveConn(ctx, c, src, func() []koloswarm.Topic { return e.topics })
			})
		}
	})
	var once sync.Once
	e.stopFn = func() { once.Do(func() { e.stop(cancel, &wg) }) }
	t.Cleanup(e.stopFn)
}

func (e *env) stop(cancel context.CancelFunc, wg *sync.WaitGroup) {
	cancel()
	e.ln.Close()
	e.in.Close()
	wg.Wait()
}

// dial returns a connection of joiner to the inviter.
func (e *env) dial(joiner *koloid.Identity) *kolosecure.Conn {
	e.t.Helper()
	c, err := kolosecure.Dial(e.ctx, e.ln.Addr().String(), joiner, e.id.PublicKey(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

func (e *env) create(o *CreateOptions) (Code, Info) {
	e.t.Helper()
	s, info, err := e.in.Create(o)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := Parse(s)
	if err != nil {
		e.t.Fatal(err)
	}
	return c, info
}

// join runs one exchange of a new joiner on a new connection.
func (e *env) join(code Code, data []byte) ([]byte, error) {
	e.t.Helper()
	id := generate(e.t)
	return e.joinAs(e.dial(id), id, code, data)
}

func (e *env) joinAs(c *kolosecure.Conn, id *koloid.Identity, code Code, data []byte) ([]byte, error) {
	return JoinConn(e.ctx, c, id, code, &JoinOptions{Data: data})
}

func (e *env) list() []Info {
	e.t.Helper()
	l, err := e.in.List()
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

// request seals a request of id for code under nonce.
func (e *env) request(code Code, id *koloid.Identity, data, nonce []byte) msg {
	req, _, err := newRequest(code, e.id.PublicKey(), id, data, nonce)
	if err != nil {
		e.t.Fatal(err)
	}
	return req.msg
}

// next returns the next event or fails after a few seconds.
func (e *env) next() Event {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	ev, err := e.in.Next(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return ev
}

// noEvent fails if an event is queued.
func (e *env) noEvent() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, 50*time.Millisecond)
	defer cancel()
	if ev, err := e.in.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		e.t.Fatalf("unexpected event %+v, %v", ev, err)
	}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// raw is a hand-driven joiner stream for crafted messages.
type raw struct {
	t  *testing.T
	st *kolotransport.Stream
}

func (e *env) raw(c koloswarm.Conn) *raw {
	e.t.Helper()
	st, err := c.OpenStream(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(10 * time.Second))
	e.t.Cleanup(func() { st.CancelRead(0); st.CancelWrite(0) })
	return &raw{t: e.t, st: st}
}

func (r *raw) send(m msg) {
	r.t.Helper()
	if err := writeFrame(r.st, m.encode()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *raw) sendBytes(b []byte) {
	r.t.Helper()
	if err := writeFrame(r.st, b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *raw) recv() (msg, error) { return readMsg(r.st, maxFrame(1<<20)) }

// challenge sends OPEN and returns the inviter's nonce.
func (r *raw) challenge() []byte {
	r.t.Helper()
	r.send(msg{typ: msgOpen})
	m, err := r.recv()
	if err != nil || m.typ != msgChallenge {
		r.t.Fatalf("challenge: %+v, %v", m, err)
	}
	return m.nonce
}

// refused reads the next message, after RECEIVED, and checks it is REFUSED with code.
func (r *raw) refused(code uint64) {
	r.t.Helper()
	m, err := r.recv()
	if err == nil && m.typ == msgReceived {
		m, err = r.recv()
	}
	if err != nil || m.typ != msgRefused || m.code != code {
		r.t.Fatalf("got %+v, %v; want refused %d", m, err, code)
	}
}

// reset reads until the inviter ends the stream without a message.
func (r *raw) reset() {
	r.t.Helper()
	if m, err := r.recv(); err == nil {
		r.t.Fatalf("got %+v, want the stream to end", m)
	}
}

type testConn = kolosecure.Conn

func answerKey(t *testing.T) []byte {
	t.Helper()
	k, err := kem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// sealRequest seals r for code and inviter under nonce with signer's signature, whatever key r names.
func sealRequest(t *testing.T, code Code, inviter []byte, nonce []byte, r request, signer *koloid.Identity) msg {
	t.Helper()
	enc, s, err := hpke.NewSender(code.c.k.hpke.PublicKey(), kdf, aead, requestInfo(inviter, code.c.k.id, nonce))
	if err != nil {
		t.Fatal(err)
	}
	r.sig, err = signer.Sign(ctxRequest, requestTranscript(inviter, code.c.k.id, nonce, enc, r.signed()))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(nil, r.plaintext())
	if err != nil {
		t.Fatal(err)
	}
	return msg{typ: msgRequest, id: code.c.k.id, enc: enc, sealed: sealed}
}

// exchange runs JoinConn once; the middle result is always false.
func exchange(ctx context.Context, c koloswarm.Conn, id *koloid.Identity, code Code, data []byte) ([]byte, bool, error) {
	p, err := JoinConn(ctx, c, id, code, &JoinOptions{Data: data})
	return p, false, err
}

// testPeer is a Peer over a plain connection.
type testPeer struct {
	conn   koloswarm.Conn
	addr   netip.AddrPort
	topics []koloswarm.Topic
}

func (p testPeer) Conn() koloswarm.Conn { return p.conn }
func (p testPeer) Addr() netip.AddrPort { return p.addr }
func (p testPeer) PublicKey() ed25519.PublicKey {
	if p.conn == nil {
		return nil
	}
	return p.conn.RemotePublicKey()
}
func (p testPeer) Topics() []koloswarm.Topic { return p.topics }

// answer reads past RECEIVED to the next message.
func (r *raw) answer() (msg, error) {
	m, err := r.recv()
	if err == nil && m.typ == msgReceived {
		m, err = r.recv()
	}
	return m, err
}

func newListener(e *env) (*kolosecure.Listener, error) {
	return kolosecure.Listen(e.ctx, "127.0.0.1:0", e.id, nil)
}

func dialListener(t *testing.T, e *env, ln *kolosecure.Listener, id *koloid.Identity) *kolosecure.Conn {
	t.Helper()
	c, err := kolosecure.Dial(e.ctx, ln.Addr().String(), id, e.id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// joinReceived joins as id on c in the background; got is closed once the joiner has read the inviter's RECEIVED,
// and done gets the result.
func (e *env) joinReceived(c koloswarm.Conn, id *koloid.Identity, code Code) (got <-chan struct{}, done <-chan error) {
	g, d := make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := JoinConn(e.ctx, c, id, code, &JoinOptions{received: func() { close(g) }})
		d <- err
	}()
	return g, d
}

// blockedIn reports whether a goroutine is inside the function whose stack name contains fn.
func blockedIn(fn string) bool {
	for _, stack := range goroutines() {
		if strings.Contains(stack, fn) {
			return true
		}
	}
	return false
}

// mustKeys is derive for a test: the secrets here are valid.
func mustKeys(secret []byte) keys {
	k, err := derive(secret)
	if err != nil {
		panic(err)
	}
	return k
}
