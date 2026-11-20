package invite

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	kolostore "github.com/ciranda-dev/kolo-store"
)

// Key prefixes on the backend.
const (
	pMeta     = 'm' // inviter key
	pInvite   = 'i' // 'i' ‖ ID: invite record
	pAccepted = 'a' // 'a' ‖ ID ‖ joiner: stored accept
	pDenied   = 'd' // 'd' ‖ ID ‖ joiner: stored deny
)

func corrupt(what string, err error) error {
	if err != nil {
		return fmt.Errorf("invite: %w: %s: %w", kolostore.ErrCorrupt, what, err)
	}
	return fmt.Errorf("invite: %w: %s", kolostore.ErrCorrupt, what)
}

func inviteKey(id ID) []byte { return append([]byte{pInvite}, id[:]...) }

func joinerKey(p byte, id ID, joiner ed25519.PublicKey) []byte {
	b := append([]byte{p}, id[:]...)
	return append(b, joiner...)
}

// recordVersion is the version of an invite record with the device flag; an invite that is no device invite is written as
// version 0.
const recordVersion = 1

// record is the stored state of one invite; times are Unix nanoseconds, 0 for none.
type record struct {
	secret  []byte // nil once erased
	created int64
	expires int64
	ended   int64
	maxUses uint64
	used    uint64
	manual  bool
	revoked bool
	payload []byte
	device  bool // a link-a-device invite
}

func (r *record) encode() []byte {
	var e kolocodec.Encoder
	if r.device {
		e.PutUvarint(recordVersion)
	} else {
		e.PutUvarint(version)
	}
	e.PutBytes(r.secret)
	e.PutVarint(r.created)
	e.PutVarint(r.expires)
	e.PutVarint(r.ended)
	e.PutUvarint(r.maxUses)
	e.PutUvarint(r.used)
	e.PutBool(r.manual)
	e.PutBool(r.revoked)
	e.PutBytes(r.payload)
	if r.device {
		e.PutBool(true)
	}
	return e.Bytes()
}

// decodeRecord reads an invite record and checks it against id.
func decodeRecord(id ID, b []byte) (*record, error) {
	d := kolocodec.NewDecoder(b)
	r := &record{}
	v, err := d.Uvarint()
	if err == nil && v != version && v != recordVersion {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		r.secret, err = d.Bytes(secretSize)
	}
	for _, p := range []*int64{&r.created, &r.expires, &r.ended} {
		if err == nil {
			*p, err = d.Varint()
		}
	}
	if err == nil {
		r.maxUses, err = d.UvarintMax(math.MaxInt)
	}
	if err == nil {
		r.used, err = d.UvarintMax(math.MaxInt)
	}
	if err == nil {
		r.manual, err = d.Bool()
	}
	if err == nil {
		r.revoked, err = d.Bool()
	}
	if err == nil {
		r.payload, err = d.Bytes(len(b))
	}
	if err == nil && v == recordVersion {
		r.device, err = d.Bool()
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return nil, corrupt("invite record", err)
	}
	switch {
	case len(r.secret) != 0 && len(r.secret) != secretSize:
		return nil, corrupt("invite secret length", nil)
	case len(r.secret) == 0 && r.ended == 0:
		return nil, corrupt("invite without secret has not ended", nil)
	case r.created <= 0 || r.expires < 0 || r.ended < 0 || r.maxUses < 1 || r.used > r.maxUses:
		return nil, corrupt("invite fields out of range", nil)
	case r.expires != 0 && r.expires <= r.created:
		return nil, corrupt("invite expires before it was created", nil)
	case (r.revoked || r.used == r.maxUses) && r.ended == 0:
		return nil, corrupt("ended invite without an end time", nil)
	case r.ended != 0 && !r.revoked && r.used < r.maxUses && (r.expires == 0 || r.ended != r.expires):
		return nil, corrupt("end time without a reason", nil)
	case r.manual && len(r.payload) != 0:
		return nil, corrupt("manual invite with a payload", nil)
	case v == recordVersion && !r.device:
		return nil, corrupt("version 1 record without the device flag", nil)
	case r.device && (!r.manual || r.maxUses != 1):
		return nil, corrupt("device invite that is not manual and single use", nil)
	}
	if len(r.secret) == 0 {
		r.secret = nil
		return r, nil
	}
	k, err := derive(r.secret)
	if err != nil {
		return nil, corrupt("invite secret", err)
	}
	if k.id != id {
		return nil, corrupt("invite secret does not match its ID", nil)
	}
	return r, nil
}

// joined is the stored accept of one joiner.
type joined struct {
	payload []byte
	data    []byte
	at      int64 // Unix nanoseconds
}

func (j joined) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutBytes(j.payload)
	e.PutBytes(j.data)
	e.PutVarint(j.at)
	return e.Bytes()
}

func decodeJoined(b []byte) (joined, error) {
	d := kolocodec.NewDecoder(b)
	var j joined
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		j.payload, err = d.Bytes(len(b))
	}
	if err == nil {
		j.data, err = d.Bytes(len(b))
	}
	if err == nil {
		j.at, err = d.Varint()
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return joined{}, corrupt("stored accept", err)
	}
	return j, nil
}

func encodeVersion() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	return e.Bytes()
}

func decodeDenied(b []byte) error {
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return corrupt("stored deny", err)
	}
	return nil
}

func encodeMeta(inviter ed25519.PublicKey) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(version)
	e.PutFixed(inviter)
	return e.Bytes()
}

func decodeMeta(b []byte) (ed25519.PublicKey, error) {
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err == nil && v != version {
		err = fmt.Errorf("version %d", v)
	}
	var k []byte
	if err == nil {
		k, err = d.Fixed(ed25519.PublicKeySize)
	}
	if err == nil {
		err = d.Done()
	}
	if err != nil {
		return nil, corrupt("inviter key", err)
	}
	return k, nil
}

// load reads every key of db, checks it and returns the invites; inviter is checked against or written to the
// meta key.
func load(db kolostore.Backend, inviter ed25519.PublicKey) (map[ID]*record, error) {
	meta, err := db.Get([]byte{pMeta})
	switch {
	case errors.Is(err, kolostore.ErrNotFound):
		empty := true
		if err := db.Scan(nil, nil, false, 1, func(_, _ []byte) bool { empty = false; return false }); err != nil {
			return nil, storeErr(err)
		}
		if !empty {
			return nil, corrupt("data without an inviter key", nil)
		}
		if err := db.Put([]byte{pMeta}, encodeMeta(inviter)); err != nil {
			return nil, storeErr(err)
		}
		return map[ID]*record{}, nil
	case err != nil:
		return nil, storeErr(err)
	}
	k, err := decodeMeta(meta)
	if err != nil {
		return nil, err
	}
	if !k.Equal(inviter) {
		return nil, fmt.Errorf("%w: the store belongs to another inviter", ErrInvalidArgument)
	}
	recs := map[ID]*record{}
	var answers [][]byte
	var bad error
	err = db.Scan(nil, nil, false, 0, func(key, value []byte) bool {
		var id ID
		switch {
		case len(key) == 1 && key[0] == pMeta:
		case len(key) == 1+len(id) && key[0] == pInvite:
			copy(id[:], key[1:])
			recs[id], bad = decodeRecord(id, value)
		case len(key) == 1+len(id)+ed25519.PublicKeySize && key[0] == pAccepted:
			_, bad = decodeJoined(value)
			answers = append(answers, key)
		case len(key) == 1+len(id)+ed25519.PublicKeySize && key[0] == pDenied:
			bad = decodeDenied(value)
			answers = append(answers, key)
		default:
			bad = corrupt("unknown key", nil)
		}
		return bad == nil
	})
	if err != nil {
		return nil, storeErr(err)
	}
	if bad != nil {
		return nil, bad
	}
	for _, key := range answers {
		var id ID
		copy(id[:], key[1:])
		if recs[id] == nil {
			return nil, corrupt("answer of an unknown invite", nil)
		}
	}
	return recs, nil
}
