# Security

What an invite protects, what it does not, and what the network and the inviter's store learn.

## Notes

- The code holds a fingerprint of the inviter's key and the secret. Anyone
  who sees it can try to join: share it only with the joiner, prefer single
  use, a short TTL or `Manual`, and `Revoke` a code that leaked. `Joiners`
  and the `Joined` events show who used it, with the data they sent.
- The fingerprint is the first 16 bytes of SHA-256 of a label and the
  inviter's key. The joiner talks only to a peer whose authenticated
  kolo-secure key matches it, and then binds the full key into the HPKE
  context and the signature. Posing as the inviter needs a second preimage
  of a 128-bit value for this one key (about 2^128 work); collisions do not
  help, since the target key is fixed. kolo-dht records are also signed by
  the key that announces them.
- The secret has 256 bits: it is the HPKE key seed (RFC 9180 section 4 asks
  for Nsk = 32 bytes of entropy) and the root of the topic, the ID and the
  auth value. Guessing it offline is out of reach, so no PAKE is used.
- The network never sees the secret: the DHT sees a one-way topic, and the
  request travels sealed with HPKE inside a kolo-secure connection.
- What DHT nodes still learn: the servers that store a topic see the key
  and address of the inviter that announces it and of every peer that looks
  it up, so they can link a joiner's address to the inviter's key at the
  time of the join, and see how long the invite stays announced. They cannot
  tell which invite it is, read the request, or answer it. Using a
  connection the joiner already has avoids the lookup.
- Traffic analysis: requests and answers are padded inside HPKE to Padmé
  lengths with a floor of 512 bytes, and every refusal is padded to the
  size of the smallest answer, so a deny, a refusal and an accept with a
  payload of up to 508 bytes give frames of one size. The inviter
  always sends RECEIVED before deciding or refusing, manual or not, also
  for a request refused for its size. Larger payloads and
  data show their Padmé bucket (at most about 12% above their size), and
  the time to an answer still shows a manual decision.
- Replay: every stream starts with a fresh 32-byte challenge from the
  inviter, bound into the HPKE context and the signature; a captured request
  fails on any other stream, and a stream takes one request.
- Uses are counted in one durable kolo-store batch before the answer is
  sent, under one lock: concurrent joins never exceed `MaxUses`. A joiner
  that asks again after being accepted gets the same payload and uses
  nothing. A deny is stored the same way.
- A low-order answer key or encapsulated key is refused before anything is
  decided or counted.
- Unknown invites and requests that fail to decrypt or verify get the same
  `ErrInvalid` answer; IDs and topics come from a 256-bit secret and cannot
  be enumerated.
- Requests are rate limited per source and per invite before any HPKE or
  signature work. A holder of a `Manual` code can still fill `MaxPending`
  with many keys from many addresses; the inviter sees it in `Requested`
  events and can `Deny` or `Revoke`, and `Options.PendingTTL` withdraws
  requests that wait too long.
- After an invite ends it lingers for `Linger`, then its secret is erased
  from the store and the topic is left. Erasing is best effort, as on any
  disk: Pebble drops old bytes when it compacts, and backups or snapshots
  keep them. Until then, the store holds the secrets of live invites: keep
  it private (`kolostore.OpenPebble` creates its directory 0700). After the
  linger time, a joiner whose accept was lost can no longer get it again.
- The inviter must be online for anyone to join: there is no server that
  holds invites for it.
- Answers are sealed to a key the joiner makes for each request and are
  not signed: they come from the inviter's key on a pinned connection.

## Link a device

- The code of a device invite is the weak point: someone who sees it can send a request before the real device. The approving person must TYPE the 12 digits the new device shows into `MatchDevice`; the approve calls take only the `DeviceMatch` it returns, and `PendingLink` shows no digits. An application that shows the digits on the approving screen to be clicked, or that computes them itself, loses this barrier. A person who types digits from a screen they did not compare with the new device certifies whatever device asked first.
- The fingerprint is HKDF-SHA256 (RFC 5869) over the invite secret, bound to the inviter's key and the device key, 8 bytes read as a number modulo 10^12. 12 digits are 39.9 bits. On the machine this was measured on, generating an Ed25519 key and hashing it takes 9.9 microseconds, 101 000 keys a second on one core: finding a key with a chosen 6-digit fingerprint (2^20) takes 10 seconds, so 6 digits would not protect; 2^40 keys is about 127 core-days, and finishing inside the 2 minutes a request may wait would need about 90 000 such cores. The figures are measured and extrapolated.
- A refused request, or one nobody answers within `Options.DevicePendingTTL`, burns the code, in memory at once even when the disk fails; a code lasts `DefaultDeviceTTL` unless the caller chooses another. Someone who holds a code can fill `Options.MaxPendingDevices` with requests and block the real device; the approver sees every request and can `Revoke` the code and start again.
- Only an approver device links a device: the signing identity must be the inviter's key and carry an unexpired approver certificate, and kolo-id refuses an ordinary device as a signer. A stolen ordinary device cannot link anything. A stolen approver can link devices until it is revoked: see kolo-id's security notes.
- An approver by invite needs the 24 words typed on a device of the person. The words are never carried by an invite or any message: `ApproveApprover` calls a function that derives the key, signs once and clears it, and the library has no code that can name a phrase. The person this device belongs to must be given (`ExpectPerson`), or the call says it is a first device (`FirstDevice`): a mistyped phrase with a valid checksum is a different person, and only a key to compare with tells.
- The new device checks what it is given: a certificate for another device key, for another person than the one it pinned, signed by a third key, or with a bad signature is `ErrProtocol`. The new device pins the person it expects (`Person`) or says it has none (`FirstDevice`). The person key in the answer is trusted because the person typed the fingerprint of this device into the device that sent it.
- The answer is sealed to a key the new device made for the request, inside the authenticated connection to the inviter. It holds only public data (the person key and the signed offer).
- Names are shown on the approver's screen, so a name is limited to letters, numbers, marks, punctuation, symbols and single spaces, and refuses blank, invisible, default-ignorable, control and format characters. A name can still imitate another with look-alike letters: the digits, not the name, identify the request.
- Nothing secret is logged: the library has no logger and prints nothing; `Code` prints its ID only. No cryptographic error is ignored.
