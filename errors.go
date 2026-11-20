package invite

import "errors"

var (
	// ErrInvalidArgument means a nil identity, backend, swarm, peer or connection, bad Options or CreateOptions, a
	// swarm of another identity, or a store of another inviter.
	ErrInvalidArgument = errors.New("invite: invalid argument")
	// ErrInvalidCode means a string that is not an invite code: wrong prefix or version, mixed case, bad base32,
	// wrong length or checksum.
	ErrInvalidCode = errors.New("invite: invalid invite code")
	// ErrNotFound means no invite or no pending request with that ID.
	ErrNotFound = errors.New("invite: not found")
	// ErrClosed means the Inviter is closed.
	ErrClosed = errors.New("invite: closed")
	// ErrDenied means the inviter denied the request.
	ErrDenied = errors.New("invite: denied")
	// ErrExpired means the invite expired on the inviter's clock.
	ErrExpired = errors.New("invite: expired")
	// ErrUsedUp means the invite has no uses left.
	ErrUsedUp = errors.New("invite: used up")
	// ErrRevoked means the inviter revoked the invite.
	ErrRevoked = errors.New("invite: revoked")
	// ErrInvalid means the inviter could not authenticate the request: it does not know the invite, or the request
	// does not decrypt or verify.
	ErrInvalid = errors.New("invite: request refused as invalid")
	// ErrRateLimited means the inviter refused the request under its rate limits; try again later.
	ErrRateLimited = errors.New("invite: rate limited")
	// ErrBusy means the inviter could not take the request now (too many pending requests in all or from this
	// source, or its storage failed), or Announce is already running.
	ErrBusy = errors.New("invite: busy")
	// ErrTooLarge means join data over the inviter's MaxData, a payload over the joiner's MaxPayload, or a payload
	// too large to send.
	ErrTooLarge = errors.New("invite: too large")
	// ErrProtocol means a malformed, truncated or unexpected message, another protocol version, or a peer that is
	// not the inviter.
	ErrProtocol = errors.New("invite: protocol error")
	// ErrUnreachable means the stream or connection failed, or ctx ended, before the inviter received the request.
	ErrUnreachable = errors.New("invite: inviter unreachable")
	// ErrNotAnswered means the inviter received the request, but the connection failed or ctx ended before its answer.
	ErrNotAnswered = errors.New("invite: request not answered")
	// ErrNotApprover means the certificate that ApproveDevice was given is not an unexpired approver certificate, or the
	// signer is not an approver; only an approver may link a device.
	ErrNotApprover = errors.New("invite: signer is not an approver")
	// ErrFingerprint means MatchDevice found no pending link-a-device request with the typed fingerprint.
	ErrFingerprint = errors.New("invite: fingerprint does not match")
	// ErrPersonMismatch means the person key given to ApproveApprover is not the one the approving device belongs to.
	ErrPersonMismatch = errors.New("invite: person key is not the expected one")
	// ErrPersonRequired means ApproveApprover or JoinDevice was given neither the person it expects nor FirstDevice.
	ErrPersonRequired = errors.New("invite: expected person or FirstDevice required")
	// ErrIDCollision means a new invite got the 128-bit ID of a stored one; it does not happen in practice.
	ErrIDCollision = errors.New("invite: invite ID collision")
)
