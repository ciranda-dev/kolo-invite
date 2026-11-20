// Command linkdevice links two new devices to a person on loopback, in memory: a phone as an ordinary device, approved by
// the laptop, and a tablet as an approver, approved by the laptop after the person types the 24 words on it.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	invite "github.com/ciranda-dev/kolo-invite"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// peer is what ServePeer needs to know about a connection.
type peer struct{ conn *kolosecure.Conn }

func (p peer) Conn() koloswarm.Conn         { return p.conn }
func (p peer) PublicKey() ed25519.PublicKey { return p.conn.RemotePublicKey() }
func (p peer) Addr() netip.AddrPort {
	return p.conn.RemoteAddr().(*net.UDPAddr).AddrPort()
}
func (p peer) Topics() []koloswarm.Topic { return nil }

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The person creates a phrase on the laptop, and the person key certifies the laptop as an approver. The key is
	// derived only here and then cleared: it is never stored.
	phrase, err := koloid.GeneratePhrase()
	check(err)
	words := phrase.Words()
	person, err := phrase.Person()
	check(err)
	phrase.Clear()
	personKey := person.PublicKey()
	laptop, err := koloid.Generate()
	check(err)
	offer, err := person.OfferDeviceCert(laptop.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	check(err)
	laptopCert, err := laptop.AcceptDeviceCert(offer, personKey)
	check(err)
	person.Clear()

	// The laptop is the inviter. Its application serves every connection it accepts.
	db := kolostore.NewMemory()
	defer db.Close()
	in, err := invite.Open(db, laptop, nil)
	check(err)
	defer in.Close()
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", laptop, nil)
	check(err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go in.ServePeer(ctx, peer{c})
		}
	}()

	// Link the phone: an ordinary device. The code goes to the phone out of band.
	phone, err := koloid.Generate()
	check(err)
	code := newCode(in)
	conn, err := kolosecure.Dial(ctx, ln.Addr().String(), phone, laptop.PublicKey(), nil)
	check(err)
	defer conn.Close()
	shown, err := invite.DeviceFingerprint(code, laptop.PublicKey(), phone.PublicKey())
	check(err)
	fmt.Println("the phone shows:", shown)
	done := make(chan *invite.DeviceLink, 1)
	go func() {
		link, err := invite.JoinDevice(ctx, conn, phone, code, &invite.DeviceJoinOptions{Name: "Maria's phone", Person: personKey})
		check(err)
		done <- link
	}()
	req := nextRequest(ctx, in)
	fmt.Printf("the laptop shows the request of %q and asks for the digits the phone shows\n", req.Name)
	// The person types the digits the phone shows; only what matches a pending request can be approved.
	match, err := in.MatchDevice(shown)
	check(err)
	check(in.ApproveDevice(match, &invite.DeviceApproval{Signer: laptop, Cert: laptopCert, Serial: 1}))
	link := <-done
	fmt.Println("phone is an ordinary device of the person:", link.Person.Equal(personKey) && !link.Cert.Approver())

	// Link the tablet as an approver: the person types the 24 words on the laptop, which derives the person key, signs
	// and clears it at once. The words never leave the laptop.
	tablet, err := koloid.Generate()
	check(err)
	code = newCode(in)
	conn2, err := kolosecure.Dial(ctx, ln.Addr().String(), tablet, laptop.PublicKey(), nil)
	check(err)
	defer conn2.Close()
	shown, err = invite.DeviceFingerprint(code, laptop.PublicKey(), tablet.PublicKey())
	check(err)
	go func() {
		link, err := invite.JoinDevice(ctx, conn2, tablet, code, &invite.DeviceJoinOptions{Name: "Maria's tablet", Person: personKey})
		check(err)
		done <- link
	}()
	req = nextRequest(ctx, in)
	match, err = in.MatchDevice(shown)
	check(err)
	derive := func() (*koloid.Identity, error) {
		typed, err := koloid.ParseWords(words)
		if err != nil {
			return nil, err
		}
		defer typed.Clear()
		return typed.Person()
	}
	check(in.ApproveApprover(match, &invite.ApproverApproval{Person: derive, ExpectPerson: laptopCert.Person(), Serial: 2}))
	link = <-done
	fmt.Println("tablet is an approver of the person:", link.Person.Equal(personKey) && link.Cert.Approver())
}

func newCode(in *invite.Inviter) invite.Code {
	s, _, err := in.CreateDevice(nil)
	check(err)
	code, err := invite.Parse(s)
	check(err)
	return code
}

// nextRequest waits for the next request of a link-a-device invite and returns what an approver shows.
func nextRequest(ctx context.Context, in *invite.Inviter) invite.LinkRequest {
	for {
		ev, err := in.Next(ctx)
		check(err)
		if ev.Kind == invite.Requested {
			req, err := in.PendingLink(ev.Request)
			check(err)
			return req
		}
	}
}
