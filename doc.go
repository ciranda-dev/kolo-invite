// Package invite pairs new members with an existing one: an inviter creates an invite, a joiner uses it, and the
// inviter accepts, approves or denies.
//
// An invite code is a short string that carries a fingerprint of the inviter's kolo-id key and a 256-bit secret,
// never an address. The joiner finds the inviter on a kolo-swarm topic derived one-way from the secret, or uses a
// connection it already has, sends a request sealed with HPKE (RFC 9180) to a key derived from the secret and
// signed with its kolo-id key, and gets a sealed accept with a payload, or an explicit deny, expired, used up or
// revoked answer. The inviter enforces expiry on its own clock, counts uses atomically and durably, and keeps its
// invites and joiners in a kolo-store backend. Like kolo-sync, it works per connection: the application keeps its
// swarm and event loop, runs Announce, and calls ServePeer or JoinConn on its peers.
//
// Experimental: the API may change before v1.0.0.
package invite
