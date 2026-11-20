package invite

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

// Linger is how long an ended invite stays announced and still answers (stored accepts, denies, its state); then
// its secret is erased.
const Linger = 5 * time.Minute

// maxSend is the largest payload or join data a frame carries: its length is a uint32.
const maxSend = 1 << 30

// randRead fills secrets; a variable so a test can force an ID collision.
var randRead = func(b []byte) error { _, err := rand.Read(b); return err }

// Options sets the safety bounds of an Inviter. A zero field takes its default; a negative one is
// ErrInvalidArgument.
type Options struct {
	// Timeout bounds the messages of a stream until its request is decided, the write of each answer, and how long
	// a connection that shares only invite topics may stay without a stream. Default 30s.
	Timeout time.Duration
	// PendingTTL withdraws a request that waited this long for Approve or Deny, as if its joiner had left; the joiner
	// may ask again. Zero means a request waits until it is decided, the joiner leaves or the invite ends.
	PendingTTL time.Duration
	// MaxData caps the join data the Inviter receives in one request, in bytes. Default 64 KiB.
	MaxData int
	// MaxPending caps the requests waiting for Approve or Deny, all invites. Default 1024.
	MaxPending int
	// MaxPendingPerSource caps the pending requests from one source. Default 16.
	MaxPendingPerSource int
	// MaxPendingDevices caps the requests waiting for ApproveDevice, Approve or Deny on link-a-device invites, all invites
	// together; the next one is refused with ErrBusy. Default 4: one new device and a few retries.
	MaxPendingDevices int
	// DevicePendingTTL is how long a link-a-device request waits for a person; then it is withdrawn and the invite is
	// revoked, so the code is burned. Default 2 minutes.
	DevicePendingTTL time.Duration
	// MaxDeviceName caps the device name of a link-a-device request, in bytes. Default DefaultMaxDeviceName, range 1 to MaxData.
	MaxDeviceName int
	// MaxStreams caps the streams handled at once on one connection. Default 8.
	MaxStreams int
	// SourceRate caps the requests per minute from one source, in a bucket of that size. Default 60.
	SourceRate int
	// InviteRate caps the requests per minute for one invite, in a bucket of that size. Default 600.
	InviteRate int
	// MaxSources caps the sources the rate limiter tracks; a new source past it is rate limited. Default 4096.
	MaxSources int
	// MaxEvents caps the queued Joined, Withdrawn and Ended events; past it the oldest is dropped. Default 1024.
	MaxEvents int
}

func (o *Options) withDefaults() (Options, error) {
	var r Options
	if o != nil {
		r = *o
	}
	if r.Timeout < 0 || r.PendingTTL < 0 || r.DevicePendingTTL < 0 {
		return r, fmt.Errorf("%w: negative Timeout, PendingTTL or DevicePendingTTL", ErrInvalidArgument)
	}
	if r.Timeout == 0 {
		r.Timeout = 30 * time.Second
	}
	if r.DevicePendingTTL == 0 {
		r.DevicePendingTTL = defaultDevicePendingTTL
	}
	ints := []struct {
		p *int
		d int
	}{{&r.MaxData, 64 << 10}, {&r.MaxPending, 1024}, {&r.MaxPendingPerSource, 16}, {&r.MaxPendingDevices, 4}, {&r.MaxDeviceName, DefaultMaxDeviceName}, {&r.MaxStreams, 8},
		{&r.SourceRate, 60}, {&r.InviteRate, 600}, {&r.MaxSources, 4096}, {&r.MaxEvents, 1024}}
	for _, f := range ints {
		if *f.p < 0 {
			return r, fmt.Errorf("%w: negative bound in Options", ErrInvalidArgument)
		}
		if *f.p == 0 {
			*f.p = f.d
		}
	}
	if r.MaxData > maxSend {
		return r, fmt.Errorf("%w: MaxData over 1 GiB", ErrInvalidArgument)
	}
	if r.MaxDeviceName > r.MaxData {
		return r, fmt.Errorf("%w: MaxDeviceName over MaxData", ErrInvalidArgument)
	}
	return r, nil
}

// CreateOptions describes a new invite.
type CreateOptions struct {
	// TTL is how long the invite can be used, on the inviter's clock; zero means it never expires.
	TTL time.Duration
	// MaxUses is how many joiners can be accepted; zero means 1 (single use).
	MaxUses int
	// Manual makes each request wait for Approve or Deny; otherwise requests within the invite rules are accepted.
	Manual bool
	// Payload is what an auto-approved joiner receives, at most 1 GiB; it must be empty with Manual.
	Payload []byte
}

// State is the state of an invite.
type State int

// The invite states.
const (
	// Active means the invite can be used.
	Active State = iota + 1
	// Expired means the invite's TTL is over on the inviter's clock.
	Expired
	// UsedUp means the invite accepted MaxUses joiners.
	UsedUp
	// Revoked means Revoke ended the invite.
	Revoked
)

// String returns the state's name.
func (s State) String() string {
	switch s {
	case Active:
		return "active"
	case Expired:
		return "expired"
	case UsedUp:
		return "used up"
	case Revoked:
		return "revoked"
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// Info describes an invite.
type Info struct {
	ID      ID
	Created time.Time
	// Expires is the end of the TTL, zero for none.
	Expires time.Time
	// Ended is when the invite stopped being usable, zero while Active.
	Ended   time.Time
	MaxUses int
	Used    int
	Manual  bool
	// Device is set for a link-a-device invite made by CreateDevice.
	Device bool
	State  State
}

// Joiner is a joiner an invite accepted, as stored.
type Joiner struct {
	Key    ed25519.PublicKey
	Data   []byte
	Joined time.Time
}

// RequestID identifies a pending request for Approve and Deny; it stays the same when the joiner asks again.
type RequestID uint64

// EventKind says what an Event reports.
type EventKind int

// The event kinds.
const (
	// Requested means Joiner asks to join through a Manual invite, with its Data; answer with Approve or Deny.
	// Requested events are never dropped.
	Requested EventKind = iota + 1
	// Withdrawn means a request reported by Requested left before Approve or Deny: the joiner left or the invite ended.
	Withdrawn
	// Joined means Joiner was accepted, with its Data; Request is set for a Manual invite.
	Joined
	// Ended means the invite reached State: expired, used up or revoked.
	Ended
)

// String returns the kind's name.
func (k EventKind) String() string {
	switch k {
	case Requested:
		return "requested"
	case Withdrawn:
		return "withdrawn"
	case Joined:
		return "joined"
	case Ended:
		return "ended"
	}
	return fmt.Sprintf("EventKind(%d)", int(k))
}

// Event is one thing that happened to the invites; which fields are set depends on Kind.
type Event struct {
	Kind    EventKind
	Invite  ID
	Request RequestID
	Joiner  ed25519.PublicKey
	Data    []byte
	State   State
}

// Stats are an Inviter's gauges and totals; the totals only grow.
type Stats struct {
	Active    int // invites that can be used
	Ended     int // invites that ended, lingering ones included
	Announced int // invite topics Announce has joined on the swarm
	Pending   int // requests waiting for Approve or Deny

	Requests       uint64 // requests received
	Accepted       uint64 // joiners accepted, each counted once
	Denied         uint64 // Deny calls that answered a request
	RefusedInvalid uint64 // requests that did not authenticate
	RefusedLimited uint64 // requests refused by a rate limit
	RefusedBusy    uint64 // requests refused for MaxPending, MaxPendingPerSource or a storage error
	RefusedEnded   uint64 // requests answered expired, used up or revoked
	RefusedLarge   uint64 // requests over MaxData
	StreamsRefused uint64 // streams reset past MaxStreams
	IdleClosed     uint64 // connections closed for sharing only invite topics without a stream for Timeout
	EventsDropped  uint64 // events dropped past MaxEvents
}

// Inviter creates invites and answers the requests that use them. It is safe for concurrent use.
type Inviter struct {
	pub    ed25519.PublicKey
	db     kolostore.Backend
	opts   Options
	now    func() time.Time
	linger time.Duration

	mu         sync.Mutex
	invites    map[ID]*inv
	pending    map[RequestID]*pending
	byJoiner   map[string]*pending // ID ‖ joiner key
	perSrc     map[string]int
	sources    map[string]*bucket
	gone       map[RequestID]State // requests answered because their invite ended, at most MaxPending
	goneOrder  []RequestID
	nextReq    RequestID
	events     []Event
	others     int // events in the queue that are not Requested
	announcing bool
	closed     bool

	life      context.Context // ends at Close
	endLife   context.CancelFunc
	evc       chan struct{}
	wake      chan struct{}
	reconcile chan struct{}
	done      chan struct{}
	wg        sync.WaitGroup

	announced atomic.Int64
	st        struct {
		requests, accepted, denied, invalid, limited, busy, ended, large, streams, idle, dropped atomic.Uint64
	}
}

type inv struct {
	id       ID
	rec      *record
	k        keys // valid while rec.secret is set
	bucket   bucket
	notified bool // the end was reported
	unsaved  bool // rec.ended is not stored yet
}

type pending struct {
	id     RequestID
	inv    *inv
	joiner ed25519.PublicKey
	data   []byte
	source string
	device bool // the invite is a link-a-device invite
	// deadline is when a device request is withdrawn and its code burned, whatever the retakes; the zero time for other requests
	deadline time.Time
	answer   chan answer // replaced when the joiner asks again; the old one gets a zero answer
}

// Open loads the invites stored in db, a kolo-store backend used for nothing else, for the inviter id. It does not
// close db. The backend holds the secrets and payloads of live invites in clear: keep it private.
func Open(db kolostore.Backend, id *koloid.Identity, opts *Options) (*Inviter, error) {
	return open(db, id, opts, time.Now, Linger)
}

func open(db kolostore.Backend, id *koloid.Identity, opts *Options, now func() time.Time, linger time.Duration) (*Inviter, error) {
	if db == nil || id == nil || id.PublicKey() == nil {
		return nil, fmt.Errorf("%w: nil backend or identity", ErrInvalidArgument)
	}
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	in := &Inviter{pub: id.PublicKey(), db: db, opts: o, now: now, linger: linger,
		invites: map[ID]*inv{}, pending: map[RequestID]*pending{}, byJoiner: map[string]*pending{},
		perSrc: map[string]int{}, sources: map[string]*bucket{}, gone: map[RequestID]State{},
		evc: make(chan struct{}, 1), wake: make(chan struct{}, 1), reconcile: make(chan struct{}, 1), done: make(chan struct{})}
	recs, err := load(db, in.pub)
	if err != nil {
		return nil, err
	}
	in.life, in.endLife = context.WithCancel(context.Background())
	t := now().UnixNano()
	for id, r := range recs {
		v := &inv{id: id, rec: r}
		if r.secret != nil {
			if v.k, err = derive(r.secret); err != nil {
				return nil, fmt.Errorf("invite: %w", err)
			}
		}
		v.notified = v.state(t) != Active
		v.unsaved = r.ended == 0 && v.notified
		if v.unsaved {
			r.ended = r.expires
		}
		in.invites[id] = v
	}
	in.wg.Go(in.clock)
	return in, nil
}

// Close stops the Inviter: Announce and ServePeer return ErrClosed and pending requests are left unanswered. Later
// calls return ErrClosed, except Stats. It does not close the backend. A second Close returns nil.
func (in *Inviter) Close() error {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return nil
	}
	in.closed = true
	close(in.done)
	in.endLife()
	in.mu.Unlock()
	in.wg.Wait()
	return nil
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func storeErr(err error) error { return fmt.Errorf("invite: store: %w", err) }

// state returns v's state; an end once set is final, so a clock set back never reopens an invite.
func (v *inv) state(now int64) State {
	r := v.rec
	switch {
	case r.revoked:
		return Revoked
	case r.used >= r.maxUses:
		return UsedUp
	case r.ended != 0 || r.expires != 0 && now >= r.expires:
		return Expired
	}
	return Active
}

func (v *inv) info(now int64) Info {
	r := v.rec
	i := Info{ID: v.id, Created: time.Unix(0, r.created), MaxUses: int(r.maxUses), Used: int(r.used),
		Manual: r.manual, Device: r.device, State: v.state(now)}
	if r.expires != 0 {
		i.Expires = time.Unix(0, r.expires)
	}
	if r.ended != 0 {
		i.Ended = time.Unix(0, r.ended)
	} else if i.State == Expired {
		i.Ended = i.Expires
	}
	return i
}

// Create makes a new invite, stores it, and returns its code and its Info. The code is the invite's secret: give it
// only to the joiner.
func (in *Inviter) Create(opts *CreateOptions) (string, Info, error) {
	var o CreateOptions
	if opts != nil {
		o = *opts
	}
	return in.create(o, false)
}

func (in *Inviter) create(o CreateOptions, device bool) (string, Info, error) {
	switch {
	case o.TTL < 0 || o.MaxUses < 0:
		return "", Info{}, fmt.Errorf("%w: negative TTL or MaxUses", ErrInvalidArgument)
	case len(o.Payload) > maxSend:
		return "", Info{}, fmt.Errorf("%w: payload over 1 GiB", ErrTooLarge)
	case o.Manual && len(o.Payload) != 0:
		return "", Info{}, fmt.Errorf("%w: a Manual invite takes its payload in Approve", ErrInvalidArgument)
	}
	if o.MaxUses == 0 {
		o.MaxUses = 1
	}
	secret := make([]byte, secretSize)
	if err := randRead(secret); err != nil {
		return "", Info{}, fmt.Errorf("invite: %w", err)
	}
	k, err := derive(secret)
	if err != nil {
		return "", Info{}, fmt.Errorf("invite: %w", err)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return "", Info{}, ErrClosed
	}
	if in.invites[k.id] != nil {
		return "", Info{}, ErrIDCollision
	}
	now := in.now().UnixNano()
	r := &record{secret: secret, created: now, maxUses: uint64(o.MaxUses), manual: o.Manual,
		payload: bytes.Clone(o.Payload), device: device}
	if o.TTL > 0 {
		if o.TTL > time.Duration(math.MaxInt64-now) {
			return "", Info{}, fmt.Errorf("%w: TTL too long", ErrInvalidArgument)
		}
		r.expires = now + int64(o.TTL)
	}
	if err := in.db.Put(inviteKey(k.id), r.encode()); err != nil {
		return "", Info{}, storeErr(err)
	}
	v := &inv{id: k.id, rec: r, k: k}
	in.invites[k.id] = v
	signal(in.wake)
	signal(in.reconcile)
	return encodeCode(in.pub, secret), v.info(now), nil
}

// Revoke ends an active invite now; pending requests are answered revoked. An invite that already ended is left as
// it is.
func (in *Inviter) Revoke(id ID) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return ErrClosed
	}
	v := in.invites[id]
	if v == nil {
		return ErrNotFound
	}
	return in.revokeLocked(v)
}

// burnLocked ends v at once in memory; a failed write of the end is retried by the clock, like an expiry that was not stored.
func (in *Inviter) burnLocked(v *inv) {
	now := in.now().UnixNano()
	if v.state(now) != Active {
		in.endLocked(v, now)
		return
	}
	r := *v.rec
	r.revoked, r.ended = true, now
	v.rec = &r
	v.unsaved = in.db.Put(inviteKey(v.id), r.encode()) != nil
	in.endLocked(v, now)
}

// revokeLocked ends v now unless it already ended, and stores the end.
func (in *Inviter) revokeLocked(v *inv) error {
	now := in.now().UnixNano()
	if v.state(now) != Active {
		in.endLocked(v, now)
		return nil
	}
	r := *v.rec
	r.revoked, r.ended = true, now
	if err := in.db.Put(inviteKey(v.id), r.encode()); err != nil {
		return storeErr(err)
	}
	v.rec = &r
	in.endLocked(v, now)
	return nil
}

// List returns every stored invite, ended ones included, oldest first.
func (in *Inviter) List() ([]Info, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return nil, ErrClosed
	}
	now := in.now().UnixNano()
	out := make([]Info, 0, len(in.invites))
	for _, v := range in.invites {
		out = append(out, v.info(now))
	}
	slices.SortFunc(out, func(a, b Info) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return out, nil
}

// Joiners returns the joiners the invite accepted, from the store, in key order.
func (in *Inviter) Joiners(id ID) ([]Joiner, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return nil, ErrClosed
	}
	if in.invites[id] == nil {
		return nil, ErrNotFound
	}
	start := append([]byte{pAccepted}, id[:]...)
	end := prefixEnd(start)
	var out []Joiner
	var bad error
	err := in.db.Scan(start, end, false, 0, func(k, v []byte) bool {
		var j joined
		if j, bad = decodeJoined(v); bad != nil {
			return false
		}
		out = append(out, Joiner{Key: ed25519.PublicKey(bytes.Clone(k[len(start):])), Data: j.data, Joined: time.Unix(0, j.at)})
		return true
	})
	if err != nil {
		return nil, storeErr(err)
	}
	return out, bad
}

// prefixEnd returns the first key after every key that starts with p; p starts with a byte below 0xff.
func prefixEnd(p []byte) []byte {
	e := bytes.Clone(p)
	i := len(e) - 1
	for e[i]++; e[i] == 0; e[i]++ {
		i--
	}
	return e[:i+1]
}

// Approve accepts a pending request and sends payload (at most 1 GiB) to the joiner. It returns ErrExpired,
// ErrUsedUp or ErrRevoked if the invite ended, also when that ended the request, and ErrNotFound if the joiner left.
func (in *Inviter) Approve(req RequestID, payload []byte) error {
	if len(payload) > maxSend {
		return fmt.Errorf("%w: payload over 1 GiB", ErrTooLarge)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	p, err := in.pendingLocked(req)
	if err != nil {
		return err
	}
	if p.inv.rec.device {
		return fmt.Errorf("%w: a link-a-device request is approved with ApproveDevice or ApproveApprover", ErrInvalidArgument)
	}
	return in.approveLocked(p, payload)
}

// approveLocked accepts the pending request p with payload.
func (in *Inviter) approveLocked(p *pending, payload []byte) error {
	now := in.now().UnixNano()
	if s := p.inv.state(now); s != Active {
		in.endLocked(p.inv, now)
		return stateErr(s)
	}
	if err := in.acceptLocked(p.inv, p.joiner, payload, p.data, now); err != nil {
		return err
	}
	in.dropLocked(p)
	p.answer <- answer{kind: kindAccepted, payload: bytes.Clone(payload)}
	in.pushLocked(Event{Kind: Joined, Invite: p.inv.id, Request: p.id, Joiner: p.joiner, Data: p.data})
	if p.inv.state(now) != Active {
		in.endLocked(p.inv, now)
	}
	return nil
}

// Deny refuses a pending request; the joiner gets ErrDenied, now and whenever it asks again with this invite. Like
// Approve, it checks the invite's state first and returns the same errors. A refusal of a link-a-device request also
// burns its code, in memory at once; a failed store write of that end is retried by the clock and is not an error here, and
// one that is still failing when the process stops is lost (the invite then lives on until its TTL).
func (in *Inviter) Deny(req RequestID) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	p, err := in.pendingLocked(req)
	if err != nil {
		return err
	}
	if s := p.inv.state(in.now().UnixNano()); s != Active {
		in.endLocked(p.inv, in.now().UnixNano())
		return stateErr(s)
	}
	if err := in.db.Put(joinerKey(pDenied, p.inv.id, p.joiner), encodeVersion()); err != nil {
		if p.inv.rec.device {
			// the refusal could not be stored, but the code is burned: a refused device request never stays open
			in.burnLocked(p.inv)
		}
		return storeErr(err)
	}
	in.dropLocked(p)
	p.answer <- answer{kind: kindDenied}
	in.st.denied.Add(1)
	if p.inv.rec.device {
		in.burnLocked(p.inv)
	}
	return nil
}

// pendingLocked returns the pending request req, or why it is gone.
func (in *Inviter) pendingLocked(req RequestID) (*pending, error) {
	if in.closed {
		return nil, ErrClosed
	}
	if p := in.pending[req]; p != nil {
		return p, nil
	}
	if s, ok := in.gone[req]; ok {
		return nil, stateErr(s)
	}
	return nil, ErrNotFound
}

// Next returns the next event, waiting until there is one, ctx ends or the Inviter is closed.
func (in *Inviter) Next(ctx context.Context) (Event, error) {
	for {
		in.mu.Lock()
		if in.closed {
			in.mu.Unlock()
			return Event{}, ErrClosed
		}
		if len(in.events) > 0 {
			e := in.events[0]
			in.events = slices.Delete(in.events, 0, 1)
			if e.Kind != Requested {
				in.others--
			}
			if len(in.events) > 0 {
				signal(in.evc)
			}
			in.mu.Unlock()
			return e, nil
		}
		in.mu.Unlock()
		select {
		case <-in.evc:
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-in.done:
		}
	}
}

// Stats returns the Inviter's gauges and totals; it is safe to call at any time, also after Close.
func (in *Inviter) Stats() Stats {
	in.mu.Lock()
	now := in.now().UnixNano()
	s := Stats{Pending: len(in.pending), Announced: int(in.announced.Load())}
	for _, v := range in.invites {
		if v.state(now) == Active {
			s.Active++
		} else {
			s.Ended++
		}
	}
	in.mu.Unlock()
	s.Requests = in.st.requests.Load()
	s.Accepted = in.st.accepted.Load()
	s.Denied = in.st.denied.Load()
	s.RefusedInvalid = in.st.invalid.Load()
	s.RefusedLimited = in.st.limited.Load()
	s.RefusedBusy = in.st.busy.Load()
	s.RefusedEnded = in.st.ended.Load()
	s.RefusedLarge = in.st.large.Load()
	s.StreamsRefused = in.st.streams.Load()
	s.IdleClosed = in.st.idle.Load()
	s.EventsDropped = in.st.dropped.Load()
	return s
}

func stateErr(s State) error {
	return [...]error{Expired: ErrExpired, UsedUp: ErrUsedUp, Revoked: ErrRevoked}[s]
}

func stateKind(s State) uint64 { return kindExpired + uint64(s-Expired) }

// acceptLocked durably counts a use of v by joiner and stores who joined with what, in one batch.
func (in *Inviter) acceptLocked(v *inv, joiner ed25519.PublicKey, payload, data []byte, now int64) error {
	r := *v.rec
	r.used++
	if r.used == r.maxUses {
		r.ended = now
	}
	b := in.db.NewBatch()
	b.Put(inviteKey(v.id), r.encode())
	b.Put(joinerKey(pAccepted, v.id, joiner), joined{payload: payload, data: data, at: now}.encode())
	if err := b.Commit(); err != nil {
		return storeErr(err)
	}
	v.rec = &r
	in.st.accepted.Add(1)
	return nil
}

// endLocked makes the end of v final, reports it once, answers its pending requests with its state, and updates the
// timers. An expiry is stored here; if that write fails, the clock retries it.
func (in *Inviter) endLocked(v *inv, now int64) {
	if v.notified {
		return
	}
	v.notified = true
	s := v.state(now)
	if v.rec.ended == 0 {
		r := *v.rec
		r.ended = r.expires
		v.rec = &r
		v.unsaved = in.db.Put(inviteKey(v.id), r.encode()) != nil
	}
	for _, p := range in.pending {
		if p.inv == v {
			in.withdrawLocked(p)
			in.goneLocked(p.id, s)
			p.answer <- answer{kind: stateKind(s)}
		}
	}
	in.pushLocked(Event{Kind: Ended, Invite: v.id, State: s})
	signal(in.wake)
	signal(in.reconcile)
}

// goneLocked remembers why request id ended, for Approve and Deny, keeping the last MaxPending.
func (in *Inviter) goneLocked(id RequestID, s State) {
	if len(in.goneOrder) >= in.opts.MaxPending {
		delete(in.gone, in.goneOrder[0])
		in.goneOrder = slices.Delete(in.goneOrder, 0, 1)
	}
	in.gone[id] = s
	in.goneOrder = append(in.goneOrder, id)
}

func (in *Inviter) dropLocked(p *pending) {
	delete(in.pending, p.id)
	delete(in.byJoiner, string(p.inv.id[:])+string(p.joiner))
	if in.perSrc[p.source]--; in.perSrc[p.source] <= 0 {
		delete(in.perSrc, p.source)
	}
	in.events = slices.DeleteFunc(in.events, func(e Event) bool { return e.Kind == Requested && e.Request == p.id })
}

// withdrawLocked removes p without an answer from the inviter: Withdrawn is reported if Requested was read.
func (in *Inviter) withdrawLocked(p *pending) {
	n := len(in.events)
	in.dropLocked(p)
	if len(in.events) == n {
		in.pushLocked(Event{Kind: Withdrawn, Invite: p.inv.id, Request: p.id, Joiner: p.joiner})
	}
}

func (in *Inviter) pushLocked(e Event) {
	if e.Kind != Requested {
		if in.others >= in.opts.MaxEvents {
			i := slices.IndexFunc(in.events, func(e Event) bool { return e.Kind != Requested })
			in.events = slices.Delete(in.events, i, i+1)
			in.others--
			in.st.dropped.Add(1)
		}
		in.others++
	}
	in.events = append(in.events, e)
	signal(in.evc)
}

// clock ends invites at their expiry and erases their secrets when the linger time is over.
func (in *Inviter) clock() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		in.mu.Lock()
		next := in.tickLocked()
		in.mu.Unlock()
		t.Reset(time.Duration(max(next-in.now().UnixNano(), 0)))
		select {
		case <-t.C:
		case <-in.wake:
		case <-in.done:
			return
		}
	}
}

// tickLocked handles the invites whose expiry or linger end has come, retries unsaved ends, and returns the next
// such time.
func (in *Inviter) tickLocked() int64 {
	now := in.now().UnixNano()
	next := now + int64(time.Hour)
	retry := func() { next = min(next, now+int64(time.Minute)) }
	for _, v := range in.invites {
		if v.state(now) != Active {
			in.endLocked(v, now)
		} else if v.rec.expires != 0 {
			next = min(next, v.rec.expires)
		}
		if v.unsaved {
			if in.db.Put(inviteKey(v.id), v.rec.encode()) != nil {
				retry()
				continue
			}
			v.unsaved = false
		}
		if v.rec.secret == nil || v.rec.ended == 0 {
			continue
		}
		if until := v.rec.ended + int64(in.linger); now < until {
			next = min(next, until)
			continue
		}
		r := *v.rec
		r.secret = nil
		if in.db.Put(inviteKey(v.id), r.encode()) != nil {
			retry()
			continue
		}
		clear(v.rec.secret)
		v.rec = &r
		v.k = keys{}
		signal(in.reconcile)
	}
	return next
}

// live returns the topics of the invites that still have their secret, oldest first.
func (in *Inviter) live() []koloswarm.Topic {
	in.mu.Lock()
	defer in.mu.Unlock()
	vs := make([]*inv, 0, len(in.invites))
	for _, v := range in.invites {
		if v.rec.secret != nil {
			vs = append(vs, v)
		}
	}
	slices.SortFunc(vs, func(a, b *inv) int {
		if c := cmp.Compare(a.rec.created, b.rec.created); c != 0 {
			return c
		}
		return bytes.Compare(a.id[:], b.id[:])
	})
	out := make([]koloswarm.Topic, len(vs))
	for i, v := range vs {
		out[i] = v.k.topic
	}
	return out
}

// inviteTopics reports whether every topic in ts is the topic of one of the invites that still have their secret.
func (in *Inviter) inviteTopics(ts []koloswarm.Topic) bool {
	live := in.live()
	for _, t := range ts {
		if !slices.Contains(live, t) {
			return false
		}
	}
	return true
}
