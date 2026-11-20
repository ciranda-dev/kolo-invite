package invite

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Peer is a connected peer as kolo-swarm reports it in a Connected event; *koloswarm.Peer satisfies it.
type Peer interface {
	Conn() koloswarm.Conn
	Addr() netip.AddrPort
	PublicKey() ed25519.PublicKey
	Topics() []koloswarm.Topic
}

// Announce keeps sw joined, announce only, to the topics of the live invites, oldest first, until ctx ends or the
// Inviter is closed, then leaves them. It never reads sw's events. sw must be opened with the Inviter's identity.
// A topic sw cannot join (MaxTopics, a network error) is tried again with backoff from 1s to 1 minute. One Announce
// runs at a time; another returns ErrBusy.
func (in *Inviter) Announce(ctx context.Context, sw *koloswarm.Swarm) error {
	if sw == nil || !sw.PublicKey().Equal(in.pub) {
		return fmt.Errorf("%w: nil swarm or a swarm of another identity", ErrInvalidArgument)
	}
	in.mu.Lock()
	switch {
	case in.closed:
		in.mu.Unlock()
		return ErrClosed
	case in.announcing:
		in.mu.Unlock()
		return fmt.Errorf("%w: Announce already running", ErrBusy)
	}
	in.announcing = true
	in.mu.Unlock()
	defer func() {
		in.mu.Lock()
		in.announcing = false
		in.mu.Unlock()
	}()
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(in.life, cancel)
	defer stop()
	in.announce(actx, sw)
	if in.isClosed() {
		return ErrClosed
	}
	return ctx.Err()
}

func (in *Inviter) isClosed() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.closed
}

func (in *Inviter) announce(ctx context.Context, sw *koloswarm.Swarm) {
	type retry struct {
		at    time.Time
		delay time.Duration
	}
	joined := map[koloswarm.Topic]bool{}
	retries := map[koloswarm.Topic]*retry{}
	defer func() {
		for t := range joined {
			sw.Leave(t)
		}
		in.announced.Store(0)
	}()
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		want := in.live()
		set := map[koloswarm.Topic]bool{}
		for _, w := range want {
			set[w] = true
		}
		left := false
		for tp := range joined {
			if !set[tp] {
				sw.Leave(tp)
				delete(joined, tp)
				left = true
			}
		}
		for tp := range retries {
			if !set[tp] || left {
				delete(retries, tp)
			}
		}
		wait := time.Hour
		for _, tp := range want {
			if joined[tp] {
				continue
			}
			r := retries[tp]
			if r != nil && time.Now().Before(r.at) {
				wait = min(wait, time.Until(r.at))
				continue
			}
			if sw.Join(ctx, tp, &koloswarm.JoinOptions{Announce: true}) == nil {
				joined[tp] = true
				delete(retries, tp)
				continue
			}
			if r == nil {
				r = &retry{delay: time.Second}
				retries[tp] = r
			} else {
				r.delay = min(2*r.delay, time.Minute)
			}
			r.at = time.Now().Add(r.delay)
			wait = min(wait, r.delay)
		}
		in.announced.Store(int64(len(joined)))
		t.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-in.reconcile:
		case <-t.C:
		}
	}
}

// ServePeer answers the invite requests p sends until its connection ends (nil), ctx ends (its error) or the
// Inviter is closed (ErrClosed). It must be the only caller of AcceptStream on p's connection. A peer whose shared
// topics are all invite topics, and that has had no stream for Timeout, is disconnected: knowing a topic is not
// enough to hold a connection.
func (in *Inviter) ServePeer(ctx context.Context, p Peer) error {
	if p == nil || p.Conn() == nil {
		return fmt.Errorf("%w: nil peer or connection", ErrInvalidArgument)
	}
	if in.isClosed() {
		return ErrClosed
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(in.life, cancel)
	defer stop()
	in.serveConn(sctx, p.Conn(), source(p.Addr(), p.PublicKey()), p.Topics)
	switch {
	case in.isClosed():
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return nil
}

// source names where a request comes from: the remote IPv4 address, or the remote key without one.
func source(addr netip.AddrPort, key ed25519.PublicKey) string {
	if addr.IsValid() {
		return addr.Addr().String()
	}
	return "key " + hex.EncodeToString(key)
}

// serveConn answers the streams the peer opens on conn, at most MaxStreams at once, and closes conn when topics
// are all invite topics and no stream ran for Timeout.
func (in *Inviter) serveConn(ctx context.Context, conn koloswarm.Conn, src string, topics func() []koloswarm.Topic) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(conn.Context(), cancel)
	defer stop()
	var active atomic.Int64
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		t := time.NewTicker(max(in.opts.Timeout/4, time.Millisecond))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			idle := time.Duration(time.Now().UnixNano() - last.Load())
			if active.Load() == 0 && idle >= in.opts.Timeout && in.inviteTopics(topics()) {
				in.st.idle.Add(1)
				conn.CloseWithError(0, "invite: idle")
				return
			}
		}
	})
	sem := make(chan struct{}, in.opts.MaxStreams)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			active.Add(1)
			wg.Go(func() {
				defer func() {
					last.Store(time.Now().UnixNano())
					active.Add(-1)
					<-sem
				}()
				in.handle(ctx, st, src)
			})
		default:
			in.st.streams.Add(1)
			st.CancelRead(0)
			st.CancelWrite(0)
		}
	}
}

func (in *Inviter) handle(ctx context.Context, st *kolotransport.Stream, src string) {
	defer st.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()
	st.SetDeadline(time.Now().Add(in.opts.Timeout))
	m, err := readMsg(st, smallFrame)
	if err != nil || m.typ != msgOpen {
		st.CancelWrite(0)
		return
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		st.CancelWrite(0)
		return
	}
	writeFrame(st, msg{typ: msgChallenge, nonce: nonce}.encode()) // a failed write shows in the next read

	m, err = readMsg(st, maxFrame(in.opts.MaxData))
	if errors.Is(err, errFrame) {
		// RECEIVED first, so a refusal for size has the same frames as every other refusal.
		writeFrame(st, msg{typ: msgReceived}.encode())
		in.refuse(st, refTooLarge)
		return
	}
	if err != nil || m.typ != msgRequest {
		st.CancelWrite(0)
		return
	}
	in.st.requests.Add(1)
	writeFrame(st, msg{typ: msgReceived}.encode()) // a joiner that left gets its stored answer when it asks again
	d, p, ch, code := in.process(m, nonce, src)
	if code != 0 {
		in.refuse(st, code)
		return
	}
	if p != nil {
		if d.answer, err = in.wait(ctx, st, p, ch); err != nil {
			st.CancelWrite(0)
			return
		}
	}
	sealed, err := hpke.Seal(d.to, kdf, aead, answerInfo(in.pub, m.id, nonce, d.joiner), d.answer.encode())
	if err != nil {
		st.CancelWrite(0) // the answer key passed a trial NewSender in openRequest, so this does not happen; the joiner asks again
		return
	}
	st.SetWriteDeadline(time.Now().Add(in.opts.Timeout))
	if writeFrame(st, msg{typ: msgAnswer, sealed: sealed}.encode()) == nil {
		st.Close()
	}
}

func readMsg(st *kolotransport.Stream, max int) (msg, error) {
	b, err := readFrame(st, max)
	if err != nil {
		return msg{}, err
	}
	return decodeMsg(b)
}

func (in *Inviter) refuse(st *kolotransport.Stream, code uint64) {
	switch code {
	case refInvalid:
		in.st.invalid.Add(1)
	case refLimited:
		in.st.limited.Add(1)
	case refBusy:
		in.st.busy.Add(1)
	case refTooLarge:
		in.st.large.Add(1)
	default:
		in.st.ended.Add(1)
	}
	if writeFrame(st, msg{typ: msgRefused, code: code}.encode()) == nil {
		st.Close()
	}
}

// decided is an answer and where to seal it.
type decided struct {
	answer answer
	to     hpke.PublicKey
	joiner ed25519.PublicKey
}

// process checks a request and decides it: an answer, a pending request to wait for, or a refusal code.
func (in *Inviter) process(m msg, nonce []byte, src string) (decided, *pending, chan answer, uint64) {
	in.mu.Lock()
	now := in.now().UnixNano()
	if !in.allowSourceLocked(src, now) {
		in.mu.Unlock()
		return decided{}, nil, nil, refLimited
	}
	v := in.invites[m.id]
	if v == nil {
		in.mu.Unlock()
		return decided{}, nil, nil, refInvalid
	}
	if v.rec.secret == nil {
		s := v.state(now)
		in.mu.Unlock()
		return decided{}, nil, nil, refExpired + uint64(s-Expired)
	}
	if !v.bucket.take(now, in.opts.InviteRate) {
		in.mu.Unlock()
		return decided{}, nil, nil, refLimited
	}
	k, device := v.k, v.rec.device
	in.mu.Unlock()

	r, to, ok := openRequest(k, in.pub, m, nonce)
	if !ok {
		return decided{}, nil, nil, refInvalid
	}
	if len(r.data) > in.opts.MaxData {
		return decided{}, nil, nil, refTooLarge
	}
	if device {
		if _, err := decodeLinkData(r.data, in.opts.MaxDeviceName); err != nil {
			return decided{}, nil, nil, refInvalid
		}
	}
	d := decided{to: to, joiner: r.joiner}
	in.mu.Lock()
	defer in.mu.Unlock()
	now = in.now().UnixNano()
	stored, err := in.db.Get(joinerKey(pAccepted, v.id, r.joiner))
	if err == nil {
		j, err := decodeJoined(stored)
		if err != nil {
			return d, nil, nil, refBusy
		}
		d.answer = answer{kind: kindAccepted, payload: j.payload}
		return d, nil, nil, 0
	}
	if !errors.Is(err, kolostore.ErrNotFound) {
		return d, nil, nil, refBusy
	}
	switch _, err := in.db.Get(joinerKey(pDenied, v.id, r.joiner)); {
	case err == nil:
		d.answer.kind = kindDenied
		return d, nil, nil, 0
	case !errors.Is(err, kolostore.ErrNotFound):
		return d, nil, nil, refBusy
	}
	if s := v.state(now); s != Active {
		in.endLocked(v, now)
		in.st.ended.Add(1)
		d.answer.kind = stateKind(s)
		return d, nil, nil, 0
	}
	if !v.rec.manual {
		if err := in.acceptLocked(v, r.joiner, v.rec.payload, r.data, now); err != nil {
			return d, nil, nil, refBusy
		}
		d.answer = answer{kind: kindAccepted, payload: v.rec.payload}
		in.pushLocked(Event{Kind: Joined, Invite: v.id, Joiner: r.joiner, Data: r.data})
		if v.state(now) != Active {
			in.endLocked(v, now)
		}
		return d, nil, nil, 0
	}
	key := string(v.id[:]) + string(r.joiner)
	if p := in.byJoiner[key]; p != nil {
		p.answer <- answer{}
		p.answer = make(chan answer, 1)
		if in.perSrc[p.source]--; in.perSrc[p.source] <= 0 {
			delete(in.perSrc, p.source)
		}
		p.source = src
		p.data = r.data // the new request's name is the one an approver sees
		in.perSrc[src]++
		return d, p, p.answer, 0
	}
	if len(in.pending) >= in.opts.MaxPending || in.perSrc[src] >= in.opts.MaxPendingPerSource ||
		(device && in.pendingDevicesLocked() >= in.opts.MaxPendingDevices) {
		return d, nil, nil, refBusy
	}
	in.nextReq++
	p := &pending{id: in.nextReq, inv: v, joiner: r.joiner, data: r.data, source: src, device: device, answer: make(chan answer, 1)}
	if device {
		p.deadline = time.Now().Add(in.opts.DevicePendingTTL)
	}
	in.pending[p.id] = p
	in.byJoiner[key] = p
	in.perSrc[src]++
	in.pushLocked(Event{Kind: Requested, Invite: v.id, Request: p.id, Joiner: r.joiner, Data: r.data})
	return d, p, p.answer, 0
}

// openRequest decrypts and verifies a request with the invite's keys, and checks that an answer can be sealed to
// its answer key before anything is decided.
func openRequest(k keys, inviter ed25519.PublicKey, m msg, nonce []byte) (request, hpke.PublicKey, bool) {
	rcp, err := hpke.NewRecipient(m.enc, k.hpke, kdf, aead, requestInfo(inviter, m.id, nonce))
	if err != nil {
		return request{}, nil, false
	}
	pt, err := rcp.Open(nil, m.sealed)
	if err != nil {
		return request{}, nil, false
	}
	r, err := decodeRequest(pt)
	if err != nil || subtle.ConstantTimeCompare(r.auth, k.auth[:]) != 1 ||
		!koloid.Verify(r.joiner, ctxRequest, requestTranscript(inviter, m.id, nonce, m.enc, r.signed()), r.sig) {
		return request{}, nil, false
	}
	to, err := kem.NewPublicKey(r.answerKey)
	if err == nil {
		_, _, err = hpke.NewSender(to, kdf, aead, nil) // a low-order key fails here, not after a use is counted
	}
	if err != nil {
		return request{}, nil, false
	}
	return r, to, true
}

var errLeft = errors.New("invite: joiner left")

// wait waits for the answer to a pending request, the joiner leaving, or the end.
func (in *Inviter) wait(ctx context.Context, st *kolotransport.Stream, p *pending, ch chan answer) (answer, error) {
	st.SetDeadline(time.Time{})
	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(in.life, cancel)()
	go func() {
		var b [1]byte
		st.Read(b[:]) // the joiner sends nothing more: any return means it left
		cancel()
	}()
	defer st.CancelRead(0)
	var ttl <-chan time.Time
	d := in.opts.PendingTTL
	if p.device {
		// the deadline of the first arrival: a joiner that asks again does not restart it
		in.mu.Lock()
		d = max(time.Until(p.deadline), time.Nanosecond)
		in.mu.Unlock()
	}
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		ttl = t.C
	}
	var a answer
	select {
	case a = <-ch:
	case <-stop.Done():
		a, _ = in.withdraw(p, ch)
	case <-ttl:
		var withdrew bool
		if a, withdrew = in.withdraw(p, ch); withdrew && p.device {
			in.burn(p.inv)
		}
	}
	if a.kind == 0 {
		return answer{}, errLeft
	}
	return a, nil
}

// withdraw removes p unless it was answered, ended or taken over (each sent to ch under the lock), and returns what ch holds
// and whether it removed p.
func (in *Inviter) withdraw(p *pending, ch chan answer) (answer, bool) {
	in.mu.Lock()
	withdrew := in.pending[p.id] == p && p.answer == ch
	if withdrew {
		in.withdrawLocked(p)
		ch <- answer{}
	}
	in.mu.Unlock()
	return <-ch, withdrew
}
