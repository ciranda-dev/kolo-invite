# Limits

Every bound and default in kolo-invite, and what it protects. The calls are in [guide.md](guide.md).

`Options`; a zero field takes its default, a negative one is
`ErrInvalidArgument`.

| Option | Default | What it bounds |
|---|---|---|
| `Timeout` | 30s | the messages of a stream until its request is decided, the write of each answer, and how long a peer that shares only invite topics may stay without a stream |
| `PendingTTL` | none | how long a `Manual` request waits for `Approve` or `Deny` before it is withdrawn like a joiner that left; zero means no limit |
| `MaxData` | 64 KiB | join data in one request (at most 1 GiB, keep it small); more is `ErrTooLarge`, refused from the frame length before the frame is read |
| `MaxPending` | 1024 | requests waiting for `Approve` or `Deny`, all invites; past it requests get `ErrBusy` |
| `MaxPendingPerSource` | 16 | pending requests from one source |
| `MaxPendingDevices` | 4 | pending requests of link-a-device invites, all invites together; one new device and a few retries; past it requests get `ErrBusy` |
| `MaxDeviceName` | 64 | the bytes of a device name in a link-a-device request; a longer one is refused as invalid |
| `DevicePendingTTL` | 2 minutes | how long a link-a-device request waits for a person before it is withdrawn and its invite is revoked (the code is burned) |
| `MaxStreams` | 8 | streams handled at once on one connection; more are reset |
| `SourceRate` | 60 | requests per minute from one source, in a bucket of that size |
| `InviteRate` | 600 | requests per minute for one invite, in a bucket of that size |
| `MaxSources` | 4096 | sources the rate limiter tracks; a full bucket is forgotten, and a new source when none can be is rate limited |
| `MaxEvents` | 1024 | queued `Joined`, `Withdrawn` and `Ended` events; past it the oldest is dropped and counted in `Stats.EventsDropped` |

Link a device (the bounds are safety bounds against flooding and large input; the timings are defaults, not bounds): `MaxPendingDevices` (default 4) caps the pending requests of device invites, `MaxDeviceName` (default 64 bytes, range 1 to `MaxData`) caps a device name, and on the new device `DeviceJoinOptions.MaxName` (64) and `MaxPayload` (4096, an answer is under 600 bytes) cap what it sends and accepts. `DevicePendingTTL` (default 2 minutes) is how long one request waits for a person and `DeviceOptions.TTL` (default 5 minutes) how long a code lasts; any positive TTL is allowed. An offer is at most 450 bytes (kolo-id's bound).

`JoinOptions.MaxPayload` (default 1 MiB) bounds the payload a joiner
accepts. `Linger` (5 minutes) is a constant, not a bound: how long an
ended invite stays announced and still answers. Frame lengths are a uint32,
so payloads and join data are at most 1 GiB; OPEN and CHALLENGE frames are
at most 64 bytes; every other frame is at most
max(512, Padmé(n + 256)) + 256 bytes, where n is `MaxData` (requests, on
the inviter) or `MaxPayload` (answers, on the joiner), checked from its
length before its body is read. A frame is read into a buffer that grows
with the bytes that arrive, so a peer that sends only a header makes the
inviter allocate nothing for the declared length. A peer that sends the
whole body can still make one stream hold up to `MaxData` bytes, so the
worst case is `MaxStreams` times `MaxData` per connection: join data is a
name or a key, not a file, and the default 64 KiB is enough for it.

A source is the connection's remote IPv4 address, or its remote key when
the connection has none. Queued `Requested` events are never dropped and
never more than the pending requests, so the event queue holds at most
`MaxPending + MaxEvents` events. Pending requests live only while their
joiner waits on its stream: a joiner that leaves withdraws its request, and
nothing about pending requests survives a restart. Without `PendingTTL` a
`Manual` request waits for a person; a holder of a code can then keep
requests pending until `MaxPending` is full, so an application that exposes
`Manual` invites widely should set `PendingTTL` (for example to an hour).

One lock guards the inviter's state, and `Create`, `Revoke`, each accepted
joiner and the clock tick hold it across their synced write. This is by
design: a use is counted in the same durable batch as the accept, under the
lock, before the answer is sent, so two requests can never take the last
use. Requests are rate limited before they reach the lock, so throughput is
bounded by the disk's sync latency, not by peers.

`Announce` joins the topic of every live invite, oldest first, together
with the application's own. kolo-swarm has no topic cap by default
(`MaxTopics` 0), so every live invite is announced. If the application sets
`MaxTopics`, a `Join` past it fails at once with `ErrInvalidArgument`;
Announce does not wait inside `Join` but tries that topic again with
backoff from 1s to 1 minute, and a topic that fails for another reason (a
network error) is retried the same way. `Stats.Announced` shows how many
are announced. An invite counted in `Stats.Active` but not announced cannot
be found by joiners (only reached on a connection they already have). With a
`MaxTopics` cap, Announce takes every free topic, so an application `Join`
after it can fail with that error: join the application's topics first, or
set `MaxTopics` to the application's topics plus the invites it keeps live.
Old invites that never expire and are never used keep their topics, and with
a cap newer invites wait behind them: give invites a `TTL`, or `Revoke` the
ones no longer needed. A joiner's swarm looks a
topic up once when it joins it and then every `LookupInterval` (kolo-swarm
default 10 minutes) plus up to a fifth of it at random, so a joiner that
starts before the inviter is online waits up to that long (about 12
minutes by default); a shorter `LookupInterval` helps.

Storage grows only with what the application does, never with peer input:
one record per invite created (about 100 bytes plus its payload), one
record per accepted joiner (its payload and data), one marker per `Deny`.
Records of ended invites are kept, since `List` and `Joiners` read them;
there is no expiry of records.
