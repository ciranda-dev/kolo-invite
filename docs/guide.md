# Guide

The full API of kolo-invite, its errors, how expiry works and why it is built this way. Bounds are in [limits.md](limits.md); the threat model is in [security.md](security.md); the formats are in [protocol.md](protocol.md).

## API

Inviter:

- `Open(db, id, opts) (*Inviter, error)` loads the invites stored in `db`, a
  `kolostore.Backend` used for nothing else (for example
  `kolostore.OpenPebble(dir)`), for the inviter `id`. The store records the
  inviter's public key; opening it with another identity is
  `ErrInvalidArgument`. Open does not close `db`.
- `Create(opts) (code string, Info, error)` makes and stores a new invite.
  `CreateOptions`:
  - `TTL`: how long the invite can be used, on the inviter's clock; zero
    means it never expires.
  - `MaxUses`: how many joiners can be accepted; zero means 1 (single
    use). No upper bound.
  - `Manual`: each request waits for `Approve` or `Deny`, until the
    joiner leaves or `Options.PendingTTL` (default none) withdraws it;
    otherwise requests within the invite rules are accepted at once.
  - `Payload`: what an auto-approved joiner receives, at most 1 GiB (the
    frame format); must be empty with `Manual`. For a payload per joiner,
    use `Manual` and call `Approve` from code on `Requested` events.

  The code is the invite's secret: give it only to the joiner.
- `Revoke(id)` ends an active invite now; its pending requests are answered
  revoked. An invite that already ended keeps its state; an unknown ID is
  `ErrNotFound`.
- `List() ([]Info, error)` returns every stored invite, ended ones
  included, oldest first: `ID`, `Created`, `Expires` (zero for none),
  `Ended` (zero while active), `MaxUses`, `Used`, `Manual`, `State`
  (`Active`, `Expired`, `UsedUp`, `Revoked`).
- `Joiners(id) ([]Joiner, error)` returns, from the store, every joiner the
  invite accepted: its `Key`, the `Data` it sent and when it `Joined`. This
  is the durable record; events can be dropped and do not survive a
  restart.
- `Approve(req, payload)` accepts a pending request and sends `payload`.
  `Deny(req)` refuses it: the joiner gets `ErrDenied`, now and every time it
  asks again with this invite. Both check the invite's state first, and
  return `ErrExpired`, `ErrUsedUp` or
  `ErrRevoked` when the invite ended, also when that is what ended the
  request (for example the other of two pending requests on a single-use
  invite after the first was approved; the last `MaxPending` such requests
  are remembered), and `ErrNotFound` when the joiner left.
- `Next(ctx) (Event, error)` returns the next event:
  - `Requested`: `Joiner` (its kolo-id key) asks to join through a manual
    invite, with its `Data`; answer with `Approve` or `Deny` and the
    `Request` ID. Never dropped.
  - `Withdrawn`: a request reported by `Requested` left before an answer:
    the joiner gave up or the invite ended. A request that leaves before its
    `Requested` event is read is removed from the queue instead, with no
    event.
  - `Joined`: `Joiner` was accepted, with its `Data` (`Request` is set for
    a manual invite).
  - `Ended`: the invite reached `State`: expired, used up or revoked.
- `Announce(ctx, sw)` keeps the swarm `sw` joined, announce only, to the
  topics of the live invites (active, or ended less than `Linger` ago),
  oldest first, until `ctx` ends (its error) or the Inviter is closed
  (`ErrClosed`), then leaves them. It never reads `sw`'s events, so the
  application keeps its own loop. `sw` must be opened with the inviter's
  identity. One Announce runs at a time; another is `ErrBusy`. Announce
  joins a topic for every live invite, oldest first. If the swarm sets
  kolo-swarm's `MaxTopics` (no cap by default), Announce takes every free
  topic, so join the application's own topics before starting it, or size
  `MaxTopics` for both (see [limits.md](limits.md)).
- `ServePeer(ctx, p)` answers the invite requests of one connected peer
  until its connection ends (nil), `ctx` ends (its error) or the Inviter is
  closed (`ErrClosed`). `p` is a `Peer`: `*koloswarm.Peer` from a
  `Connected` event satisfies it. ServePeer must be the only caller of
  `AcceptStream` on that connection, as with kolo-sync's `Serve`: an
  application that runs another stream protocol with the same peer decides
  per connection which one serves it. A peer whose shared topics are all
  invite topics, and that has had no stream for `Timeout`, is disconnected
  (checked every `Timeout`/4, so between `Timeout` and 1.25 × `Timeout`),
  so knowing a topic (as a DHT node can) is not enough to hold a slot of the
  swarm. Connections that share any other topic, as the inviter's swarm
  sees them (`Peer.Topics()`), are never closed by it. kolo-swarm does not
  tell the other side when a peer joins a topic later on an existing
  connection, so a joiner that joins the group topic while it still holds
  its invite connection is seen on it with the invite topic only, and is
  closed after `Timeout`; see JoinConn below.
- `Stats() Stats` returns gauges (`Active`, `Ended`, `Announced`, `Pending`)
  and totals (`Requests`, `Accepted`, `Denied`, `RefusedInvalid`,
  `RefusedLimited`, `RefusedBusy`, `RefusedEnded`, `RefusedLarge`,
  `StreamsRefused`, `IdleClosed`, `EventsDropped`). No IDs, keys or
  addresses: an application that exports them as metrics keeps fixed
  labels. Stats works also after Close.
- `Close()` stops the Inviter: `Announce` and `ServePeer` return
  `ErrClosed`, pending requests get no answer (their joiners see
  `ErrNotAnswered`), and every later call except `Stats` returns
  `ErrClosed`. A second Close returns nil.

Joiner:

- `Parse(s) (Code, error)` reads an invite code, all in lower case or all
  in upper case, without trimming. `Code.ID()` is the invite ID,
  `Code.Topic()` its kolo-swarm topic, and `Code.Matches(key)` reports
  whether a kolo-id key is the inviter's. A `Code` keeps its secret behind
  a pointer and prints only its ID, also inside other values.
- `JoinConn(ctx, conn, id, code, opts) ([]byte, error)` asks the inviter,
  on `conn`, to let `id` join, and returns the payload of the accept. `conn`
  must be a connection to the inviter (`code.Matches(conn.RemotePublicKey())`,
  checked) on which the inviter runs `ServePeer`. Get it from a
  `Connected` event after joining `code.Topic()` with `Lookup` on the
  application's swarm, or use a connection the application already has
  with the inviter: it need not be for the invite topic, but the inviter's
  application must run `ServePeer`, and no other stream protocol, on that
  connection. After joining, leave `code.Topic()` before joining the
  group's topic: kolo-swarm then closes the invite-only connection at once,
  and the group topic comes with a new connection whose hello carries it,
  so the inviter sees that topic (tested in `TestJoinerMovesToGroup`). `JoinOptions.Data` is sent with the request (for example a
  display name); `JoinOptions.MaxPayload` bounds the payload it accepts.
  JoinConn opens one stream, so calls may run at once on one connection.
  It waits for the answer as long as `ctx` allows: a manual invite waits for
  a person, so give `ctx` a deadline or cancel it. Asking again after a lost
  connection is safe: an accepted joiner gets the same payload and uses
  nothing.

## Link a device

A device invite lets a person add a new device to their identity. It uses [kolo-id](https://github.com/ciranda-dev/kolo-id) certificates: an approver device (a device whose certificate has the approver flag) certifies the key of the new device, and the person key, derived from the 24 words, never lives on a device.

Inviter, on an approver device (its identity is the `Open` identity):

- `CreateDevice(opts)` makes a `Manual` invite with one use. `DeviceOptions.TTL` is how long the code lasts: default `DefaultDeviceTTL` (5 minutes), any positive value; a code is short-lived by default because a code seen over a shoulder should be dead soon. `Info.Device` is true. The code has the usual format and is shown to the new device only.
- On a `Requested` event, `PendingLink(req)` returns the new device's key and the `Name` it chose. It does not return the fingerprint. The new device shows 12 digits (`DeviceFingerprint`, for example `423 583 296 902`) and the person TYPES them into `MatchDevice(typed)`, which finds the pending device request with those digits (spaces ignored, constant time) and returns a `DeviceMatch`, or `ErrFingerprint`. The approve calls take a `DeviceMatch` and nothing else. An application must not compute the fingerprint itself and fill it in (`DeviceFingerprint` is for the new device), and must not show it on the approver's screen to be clicked instead of typed: either one loses the barrier, which holds only while the person types what the new device shows. A match names the request as it was when matched: if the same key asks again with another name, the match no longer applies (`ErrNotFound`) and the person types the digits again. Two requests with the same name are told apart by their digits.
- `ApproveDevice(match, &DeviceApproval{Signer, Cert, Serial, ExpiresAt})` links the device as an ordinary device. `Signer` is the identity of this device, `Cert` its approver certificate, `Serial` the serial of the new certificate (at least 1, chosen by the caller; kolo-id keeps no state). An expired approver certificate, or an ordinary one (kolo-id refuses it as a parent), is `ErrNotApprover`.
- `ApproveApprover(match, &ApproverApproval{Person, ExpectPerson, FirstDevice, Serial, ExpiresAt})` links the device as an approver. `Person` is a function that derives the person key from the 24 words the person typed on this device (`koloid.Phrase.Person`). It is called only after the match is checked, without the inviter's lock, and the key it returns is used once and cleared before `ApproveApprover` returns, on success and on every error: derive it again to retry. Exactly one of `ExpectPerson` (the person this device already belongs to; another key, such as a mistyped phrase with a valid checksum or someone else's words, is `ErrPersonMismatch` and signs nothing) and `FirstDevice` (this device has no person yet) is required: neither is `ErrPersonRequired`, because without a person to compare, a wrong phrase could not be told. kolo-invite never sees the words.
- `Deny(req)` on a device request refuses it and also burns the code. A request nobody answers within `Options.DevicePendingTTL` (default 2 minutes) is withdrawn and burns the code too. A joiner that cancels (its context ends) withdraws its request and does not burn it, and neither does a joiner that asks again: it takes over its pending request, without restarting its deadline (the first arrival's `DevicePendingTTL` stands), and the approver sees the name of the new request. A failed store write of the end is retried by the clock; the code is burned in memory at once, also when the refusal itself could not be stored (`Deny` then returns the store error). A burn whose write is still failing when the process stops is lost: the invite lives on until its TTL. `Approve` on a device invite is `ErrInvalidArgument`.
- `Options.MaxPendingDevices` (default 4) caps the pending requests of device invites, all invites together; the next request is `ErrBusy`. `Options.MaxDeviceName` (default 64 bytes) caps the name.

New device:

```go
fp, err := invite.DeviceFingerprint(code, conn.RemotePublicKey(), id.PublicKey()) // show these digits for the person to type
link, err := invite.JoinDevice(ctx, conn, id, code, &invite.DeviceJoinOptions{Name: "Maria's phone", Person: personKey})
// link.Person is the person key to pin; link.Cert is the finished certificate of id's key.
```

`DeviceJoinOptions` needs exactly one of `Person` (the person key the device expects) and `FirstDevice` (`ErrPersonRequired` otherwise). `MaxName` (default 64) and `MaxPayload` (default 4096, an answer is under 600 bytes) are its bounds. `JoinDevice` checks the answer before it accepts it: the certificate names this device key, chains to the person key the answer names (and to `Person` when set), has valid signatures and was signed by the inviter or by the person key itself. Anything else is `ErrProtocol`. `link.Cert.Approver()` is true only for `ApproveApprover`. Persist the certificate with `koloid.SaveCert` and present it to groups (see kolo-braid's `devices` package).

A name is 1 to `MaxDeviceName` bytes of UTF-8 made of letters, numbers, marks, punctuation, symbols and single ordinary spaces between them (no leading, trailing or double space, no control, format or invisible character), so it cannot be blank or hide characters on the approver's screen: control, format, variation-selector and other default-ignorable characters are refused. Look-alike letters of other scripts remain possible, which is why the person compares digits and not names.

Typing the words on the new device instead: after an ordinary link, the person types the 24 words on the new device, which derives the person key, checks that it equals `link.Person`, signs a new approver certificate for its own key with `OfferDeviceCert(..., Approver: true)` and accepts it with `AcceptDeviceCert`. Nothing travels and kolo-invite is not involved; the same rule holds: the words are typed on a device of the person and nowhere else.

The accepted certificate is not sent back to the approver. The device presents it where it is used (kolo-braid's roster), which is also where an approver finds the exact certificate it may later revoke.

## Errors

Joiner answers:

| Error | Meaning |
|---|---|
| `ErrDenied` | the inviter called `Deny` on this joiner's request |
| `ErrExpired` | the TTL is over on the inviter's clock |
| `ErrUsedUp` | the invite accepted `MaxUses` joiners |
| `ErrRevoked` | the inviter revoked the invite |
| `ErrInvalid` | the inviter could not authenticate the request: it does not know the invite (another inviter's code, or a forged one), or the request does not decrypt or verify |
| `ErrRateLimited` | refused under a rate limit; try again later |
| `ErrBusy` | too many pending requests (`MaxPending`), too many from this source (`MaxPendingPerSource`), or the inviter's storage failed; try again later |
| `ErrTooLarge` | data over the inviter's `MaxData` (refused by the inviter), data over 1 GiB (refused by JoinConn before sending), or a payload over `MaxPayload` |
| `ErrProtocol` | the inviter sent a malformed, unexpected or undecryptable message, or the peer is not the inviter |
| `ErrUnreachable` | the stream or connection failed, or `ctx` ended, before the inviter received the request; wraps the cause |
| `ErrNotAnswered` | the inviter received the request, but the connection failed or `ctx` ended before its answer; wraps the cause |
| `ErrInvalidCode` | `Parse`: wrong prefix or version, mixed case, bad base32, wrong length or checksum |
| `ErrInvalidArgument` | nil connection, identity or code, or a negative `MaxPayload` |
| `ErrNotApprover` | `ApproveDevice`: the certificate is not an unexpired approver certificate of the signer |
| `ErrFingerprint` | `MatchDevice`: no pending device request has the typed digits |
| `ErrPersonRequired` | `ApproveApprover`, `JoinDevice`: neither the expected person nor `FirstDevice` was given |
| `ErrPersonMismatch` | `ApproveApprover`: the person key is not `ExpectPerson` |

A deny always reaches the joiner as `ErrDenied`, never as a timeout.

Inviter: `ErrInvalidArgument` (nil arguments, bad options, a swarm of
another identity, a store of another inviter), `ErrTooLarge` (a payload
over 1 GiB), `ErrNotFound`, `ErrClosed`, `ErrBusy` (Announce already
running), `ErrExpired`, `ErrUsedUp`, `ErrRevoked`, `ErrIDCollision` (a new
invite got the 128-bit ID of a stored one, which does not happen in
practice), and backend errors, reads and writes alike (Open's included),
wrapped as `invite: store: ...`; after a failed write nothing changes.
Open, and `Joiners` for a stored joiner record, return an error wrapping
`kolostore.ErrCorrupt` for stored data that does not decode or check out.

## Expiry and clock skew

Expiry is an absolute time set at `Create` (now + `TTL`) and checked only
against the inviter's own clock, at every decision: when a request comes in,
at `Approve`, and by a timer at the expiry time that answers pending
requests. The joiner sends no time and its clock never counts, so there is
no skew between peers and no leeway: an invite is usable while the
inviter's now is before the expiry. An `Approve` after the expiry is
`ErrExpired` even if the request came in before. Once the inviter sees that
an invite expired, it stores the end, and an end is final: a clock set back
afterwards never reopens the invite. A clock set back before the expiry was
seen extends the invite by as much, and one set forward ends it early.

## Design

- No PAKE: a PAKE protects a low-entropy shared secret (a few digits or
  words) from offline guessing. The code carries 256 random bits, so HPKE to
  a key derived from the secret, an auth value inside the ciphertext, the
  pinned inviter key and a fresh challenge give confidentiality, proof of
  the invite, inviter authentication and freshness.
- The inviter is the only authority: there is no server, so it enforces
  expiry, uses, revocation and denies itself, on its own clock and disk.
- Per connection, like kolo-sync: the swarm's single event loop belongs to
  the application, so an existing contact joins on the connection it
  already has, and several joins share one connection.
- Decisions run in this order: a stored accept for this joiner (sent again,
  no use), a stored deny, the invite's state, then manual (pending) or
  accept. A second request from a joiner that is pending takes over its
  pending request and keeps its `Request` ID.
- Uses are counted at accept, not at request, so pending requests that are
  never approved hold no use. When the last use goes, the other pending
  requests of the invite are answered used up.
