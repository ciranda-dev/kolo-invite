// Command basic runs a kolo-dht server, an inviter and a joiner on loopback: the inviter keeps its invites in the
// directory given as argument, creates an invite that needs approval, and approves the joiner's request.
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
