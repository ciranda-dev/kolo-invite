# Protocol

The formats of kolo-invite and the standards it follows. The calls that use them are in [guide.md](guide.md); the threat model is in [security.md](security.md).

## Formats

Invite code: `koloinv0` followed by RFC 4648 base32 without padding, in
lower case, of

    fingerprint (16) ‖ secret (32) ‖ checksum (4)

where fingerprint is the first 16 bytes of
SHA-256(`kolo-invite/fingerprint/v0` ‖ inviter key) and checksum the first
4 bytes of SHA-256(`koloinv0` ‖ fingerprint ‖ secret): 92 characters. The
`0` is the format version. The whole code in upper case is accepted too
(QR alphanumeric mode); mixed case, padding, spaces and non-zero unused
bits in the last character are not, so a code has one spelling per case.
The checksum catches copy errors (a wrong code passes with probability
2^-32); it is not a security check.

Derived from the secret with HKDF-SHA256, empty salt, the label as info:
invite ID (`kolo-invite/id/v0`, 16 bytes), rendezvous topic
(`kolo-invite/topic/v0`, 32), auth value (`kolo-invite/auth/v0`, 32), and
the HPKE key seed (`kolo-invite/hpke/v0`, 32) for DeriveKeyPair.

HPKE: base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
ChaCha20-Poly1305.

Stream messages (the joiner opens a bidirectional stream per request):
uint32 little-endian length ‖ body; every body is kolo-codec canonical and
starts with uvarint version 0 and uvarint type.

    1 OPEN       joiner → inviter
    2 CHALLENGE  inviter → joiner   nonce (32)
    3 REQUEST    joiner → inviter   invite ID (16) ‖ enc (32) ‖ bytes(ciphertext)
    4 RECEIVED   inviter → joiner   (after every REQUEST, before the decision or refusal)
    5 ANSWER     inviter → joiner   bytes(enc ‖ ciphertext)
    6 REFUSED    inviter → joiner   uvarint code ‖ 561 zero bytes

The request plaintext, sealed to the invite's HPKE key with info
`kolo-invite/request/v0` ‖ inviter key ‖ invite ID ‖ nonce:

    uvarint 0 ‖ auth (32) ‖ joiner key (32) ‖ answer key (32) ‖ bytes(data) ‖ signature (64) ‖ zero padding

The signature is Ed25519ctx (RFC 8032) by the joiner key with context
`kolo-invite/request/v0` over inviter key ‖ invite ID ‖ nonce ‖ enc ‖ the
plaintext before the signature. The answer plaintext, sealed to the answer
key with info `kolo-invite/answer/v0` ‖ inviter key ‖ invite ID ‖ nonce ‖
joiner key:

    uvarint 0 ‖ uvarint kind ‖ bytes(payload), payload for kind 1 only ‖ zero padding

Both plaintexts are padded with zeros to max(512, Padmé(length)). Answer
kinds: 1 accepted, 2 denied, 3 expired, 4 used up, 5 revoked. Refusal
codes: 1 invalid, 2 rate limited, 3 busy, 4 expired, 5 used up, 6 revoked
(the last three for an ended invite whose secret was erased), 7 too large.
The joiner keeps its side of the stream open until the answer; closing or
resetting it withdraws a pending request. Trailing bytes, other versions or
types end the stream.

On the backend (keys, then values, all kolo-codec):

    "m"                     uvarint 0 ‖ inviter key (32)
    "i" ‖ ID                uvarint 0 or 1 ‖ bytes(secret, 0 or 32) ‖ varint created ‖ varint expires ‖ varint ended ‖
                            uvarint max uses ‖ uvarint used ‖ bool manual ‖ bool revoked ‖ bytes(payload) ‖ [bool device, version 1]
    "a" ‖ ID ‖ joiner key   uvarint 0 ‖ bytes(payload) ‖ bytes(data) ‖ varint joined
    "d" ‖ ID ‖ joiner key   uvarint 0

Times are Unix nanoseconds, 0 for none; an expired invite stores its expiry
as its end. The invite record of a link-a-device invite is version 1 and ends with the
`device` flag; every other invite record is version 0, without it, so a store
with no device invite stays readable by older versions. A version 1 record is a device record: one without the flag is not read. A device invite is
manual and single use. There is no JSON form.

## Link a device

A device invite uses the same stream messages. The request `data` and the
accepted payload are typed, kolo-codec canonical:

    request data    uvarint 0 ‖ string(name), 1 to MaxDeviceName bytes of UTF-8: letters, numbers, marks, punctuation,
                    symbols and single spaces between them
    accepted payload  uvarint 0 ‖ person key (32) ‖ bytes(kolo-id CertOffer, at most 450 bytes)

The new device's key is the joiner key, proved by the request signature. The
inviter refuses a request whose data does not decode (`ErrInvalid`, before a
pending slot is taken). The fingerprint both screens show is

    n = BE64(HKDF-SHA256(ikm = invite secret, salt = none,
                         info = "kolo-invite/link-fingerprint/v0" ‖ inviter key ‖ device key, L = 8)) mod 10^12

written as 12 digits in four groups of three. The offer is signed by the
approver (a kolo-id certificate with a parent) or by the person key (an
approver certificate) under kolo-id's own contexts; this library adds no
signature and no cryptography of its own.

## References

- [RFC 9180, Hybrid Public Key Encryption](https://www.rfc-editor.org/info/rfc9180)
  (Informational, February 2022): base mode with the X25519 suite for the request and the
  answer, and DeriveKeyPair from 32 bytes of secret (section 4 asks for
  Nsk = 32 bytes of entropy). Differences: no PSK or Auth mode (the Go
  standard library has base mode only), so proof of the invite is an auth
  value inside the ciphertext; replay protection, which HPKE leaves to the
  application (section 9.7.3), is the inviter's challenge; the answer uses a
  second HPKE operation to a key the joiner sends instead of the exporter
  of section 9.8.
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/info/rfc5869)
  (Informational, May 2010): the
  derived ID, topic, auth value and HPKE seed, with one label each.
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032)
  (Informational, January 2017), Ed25519ctx, through kolo-id: the request signature, under its own context.
- [RFC 4648, The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/info/rfc4648)
  (Proposed Standard, October 2006), base32: the
  code. Difference: no padding, and lower case is the written form.
- Nikitin et al., [Reducing Metadata Leakage from Encrypted Files and Communication with PURBs](https://doi.org/10.2478/popets-2019-0056),
  PETS 2019: Padmé
  lengths for the sealed plaintexts, with a 512-byte floor.
- W3C TAG, [Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/)
  (First Public Working Draft, 18 February 2014): an unguessable secret that expires and can be revoked. Difference: the
  secret never travels to a server; only derived values reach the network.
