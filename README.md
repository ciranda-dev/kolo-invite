# kolo-invite

Pairing and joining for Kolo: an existing member creates an invite, someone else uses it to join, and the inviter accepts, approves or denies.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-invite seals the join request and its answer with [HPKE (RFC 9180)](https://www.rfc-editor.org/info/rfc9180) and derives every public value from the invite secret with [HKDF (RFC 5869)](https://www.rfc-editor.org/info/rfc5869), so the secret itself never travels.

An invite is a short code (92 characters) that carries a 128-bit fingerprint of the inviter's [kolo-id](https://github.com/ciranda-dev/kolo-id) key and a 256-bit secret, never an address. The joiner finds the inviter on a [kolo-swarm](https://github.com/ciranda-dev/kolo-swarm) topic derived one-way from the secret, or uses a connection it already has, and sends a join request encrypted with HPKE (RFC 9180) and signed with its kolo-id key.

The inviter answers with an encrypted accept that carries what the joiner needs (for example a log ID and a capability), or an explicit deny, expired, used up or revoked answer. It enforces expiry on its own clock, counts uses atomically, and keeps its invites and who joined in a [kolo-store](https://github.com/ciranda-dev/kolo-store) backend, so a restart keeps expiry, uses left, revocations and joiners.

A device invite links a new device to a person: the new device shows 12 digits, the person types them on the approving device, and an approver device signs a [kolo-id](https://github.com/ciranda-dev/kolo-id) certificate for the new device's key and returns it inside the sealed answer. The 24 words are never carried by an invite.

The API works per connection, like kolo-sync: the application keeps its one swarm and its one event loop, runs `Announce` next to it, and calls `ServePeer` (inviter) or `JoinConn` (joiner) on the peers its loop sees.

## Install

```sh
go get github.com/ciranda-dev/kolo-invite
```

It needs Go 1.26 or later (`crypto/hpke`) and builds without cgo.

## Quick start

The inviter keeps its invites in the directory given as argument, creates an invite that needs approval, and approves the joiner's request, all on loopback with an in-process kolo-dht server. Run it with a temporary directory, such as `go run ./examples/basic "$(mktemp -d)"`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	invite "github.com/ciranda-dev/kolo-invite"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func identity() *koloid.Identity {
	id, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	return id
}

func swarm(ctx context.Context, id *koloid.Identity, server netip.AddrPort) *koloswarm.Swarm {
	sw, err := koloswarm.New(ctx, "127.0.0.1:0", id, &koloswarm.Config{LookupInterval: 5 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	if err := sw.Bootstrap(ctx, []netip.AddrPort{server}); err != nil {
		log.Fatal(err)
	}
	return sw
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: basic DIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := kolodht.New(ctx, "127.0.0.1:0", identity(), &kolodht.Config{Server: true})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	saddr := server.Addr().(*net.UDPAddr).AddrPort()

	// The inviter: its invites live in DIR. Its application announces them on its swarm and, in its event loop,
	// serves invite requests on every connected peer.
	alice := identity()
	db, err := kolostore.OpenPebble(filepath.Join(os.Args[1], "invites"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	in, err := invite.Open(db, alice, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()
	asw := swarm(ctx, alice, saddr)
	defer asw.Close()
	go in.Announce(ctx, asw)
	go func() {
		for {
			ev, err := asw.Next(ctx)
			if err != nil {
				return
			}
			if ev.Kind == koloswarm.Connected {
				go in.ServePeer(ctx, ev.Peer)
			}
		}
	}()
	go func() {
		for {
			ev, err := in.Next(ctx)
			if err != nil {
				return
			}
			if ev.Kind == invite.Requested {
				fmt.Printf("request from %q (%x)\n", ev.Data, ev.Joiner[:8])
				if err := in.Approve(ev.Request, []byte("log 42, read capability")); err != nil {
					log.Print(err)
				}
			}
		}
	}()

	s, info, err := in.Create(&invite.CreateOptions{TTL: time.Hour, Manual: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("invite %s, %d characters, expires %s\n", info.ID, len(s), info.Expires.UTC().Format(time.RFC3339))

	// The joiner got the code out of band. It looks the invite topic up and joins on the inviter's connection.
	bob := identity()
	bsw := swarm(ctx, bob, saddr)
	defer bsw.Close()
	code, err := invite.Parse(s)
	if err != nil {
		log.Fatal(err)
	}
	if err := bsw.Join(ctx, code.Topic(), &koloswarm.JoinOptions{Lookup: true}); err != nil {
		log.Fatal(err)
	}
	defer bsw.Leave(code.Topic())
	for {
		ev, err := bsw.Next(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if ev.Kind != koloswarm.Connected || !code.Matches(ev.Peer.PublicKey()) {
			continue
		}
		payload, err := invite.JoinConn(ctx, ev.Peer.Conn(), bob, code, &invite.JoinOptions{Data: []byte("Bob")})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("bob joined: %s\n", payload)
		break
	}
	joiners, err := in.Joiners(info.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("joiners: %d, the first sent %q\n", len(joiners), joiners[0].Data)
}
```

```text
invite b694a8554209d88e056e724d5c6b5348, 92 characters, expires 2026-11-15T06:13:16Z
request from "Bob" (5ac43ba36e1cbde6)
bob joined: log 42, read capability
joiners: 1, the first sent "Bob"
```

The ID, the time and the key prefix differ on each run. A real deployment bootstraps from a few public kolo-dht servers, such as kolo-node.

## API

| Symbol | What it does |
|---|---|
| `Open(db, id, opts)` | Load the invites stored in a `kolostore.Backend`, for the inviter `id` |
| `Create(opts)` | Make an invite; `CreateOptions` sets `TTL`, `MaxUses`, `Manual` and `Payload` |
| `Revoke`, `List`, `Joiners` | End an invite now, list every invite, and read who an invite accepted |
| `Approve`, `Deny`, `Next` | Answer a pending request and read the `Requested`, `Withdrawn`, `Joined` and `Ended` events |
| `Announce(ctx, sw)` | Keep the live invites announced on the application's kolo-swarm swarm |
| `ServePeer(ctx, p)` | Answer the invite requests of one connected peer |
| `Parse`, `Code` | Read an invite code: its ID, its swarm topic and whether a key is the inviter's |
| `JoinConn(ctx, conn, id, code, opts)` | Join on a connection to the inviter and return the accept's payload |
| `CreateDevice`, `PendingLink`, `MatchDevice` | Make a link-a-device invite, read the name and key of a pending request, and match the digits the person typed from the new device's screen |
| `ApproveDevice`, `ApproveApprover` | Link the matched device as an ordinary device (an approver signs), or as an approver (the person key, derived by a function from words typed on this device, signs once and is cleared) |
| `DeviceFingerprint`, `JoinDevice` | On the new device: the 12 digits to show, and the join that returns the finished certificate |
| `Stats` | Gauges and totals without IDs, keys or addresses |

Errors are sentinels for `errors.Is`: `ErrDenied`, `ErrExpired`, `ErrUsedUp`, `ErrRevoked`, `ErrInvalid`, `ErrInvalidCode`, `ErrRateLimited`, `ErrBusy`, `ErrTooLarge`, `ErrProtocol`, `ErrUnreachable`, `ErrNotAnswered`, `ErrNotFound`, `ErrClosed`, `ErrIDCollision`, `ErrInvalidArgument`, and for device invites `ErrNotApprover`, `ErrFingerprint`, `ErrPersonMismatch` and `ErrPersonRequired`.

## Security notes

The code is the invite's secret: share it only with the joiner, prefer single use, a short `TTL` or `Manual`, and `Revoke` a code that leaked. The inviter's backend holds the secrets and payloads of live invites in clear, so keep it private. The inviter must be online for anyone to join. What an invite protects and what DHT nodes still learn is in [docs/security.md](docs/security.md).

## More

- [Guide](docs/guide.md): every call, errors, expiry, link a device and design notes.
- [examples/linkdevice](examples/linkdevice/main.go): links a phone and a tablet to a person on loopback, in memory.
- [Limits](docs/limits.md): options, defaults, frame sizes, topics and storage.
- [Security](docs/security.md): what an invite protects and what it leaks.
- [Protocol](docs/protocol.md): the code, stream and storage formats, and the standards followed.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
