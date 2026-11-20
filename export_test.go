package invite

// BlockedIn and OnReceived let the external tests wait for a condition instead of sleeping.
func BlockedIn(fn string) bool { return blockedIn(fn) }

// OnReceived makes JoinConn call f once it has read the inviter's RECEIVED.
func OnReceived(o *JoinOptions, f func()) { o.received = f }

// Eventually waits for f to be true.
var Eventually = eventually
