# MCSession wire protocol — reverse-engineered spec (capture-derived)

Status: **v0.1** (2026-08-17). Derived from controlled captures between two
`mcpeer` processes on macOS 26 (Single Mac, loopback-LAN path) for three
scenarios: plaintext, plaintext+discoveryInfo, encryption-required.
All byte offsets are 0-based; integers big-endian unless noted.

Ground truth: `caps/{plain-none,plain-info,required}/`; tools: `analyze_mc.py`,
`decode_mc.py`, `dump_udp.py`.

---

## Architecture

MC sessions are TWO phases:

1. **TCP handshake** — short-lived connection. Browser (inviter) dials the
   advertiser's mDNS-advertised TCP port. Carries identity/accept handshake
   (binary plists). **Closes** once the session is established.
2. **UDP session channel** — the app-data transport. Two UDP ports per peer
   (e.g. 16401/16402), bound on all interfaces. Carries hello/identity
   exchange, then data messages + acknowledgements. Reliability is app-level
   (seq/ack counters), NOT TCP.

Discovery (mDNS) is separate and already solved (see README): `_<type>._tcp`,
TXT `_d`=displayName, host=UUID, port=TCP listener.

---

## Phase 1 — TCP handshake

Every message: 2-byte opcode, then fixed body. Message framing on the wire:
messages are simply concatenated (no top-level length header); each message
has an internal length field where variable.

### 0x07d0 — hello (peer token + display name)

Two per side. First: `07d0 00 01 00000000 <4B randA> 00000000` (16B).
Second carries the identity; layout (BRW side, len=40):

```
07d0 0000 00000000 0018 <4B randB> 00000000 00000006 00 12 <name+B> 00
     ^op  ^flags ^u32   ^len  ^u32      ^u32      ^u32    ^00 ^len ^18B ^00
```
ADV side is 42B with `001a` and 20-byte name. Random 13-char token + `+` +
displayName, NUL terminated (`3pk9768r60b68+ALICE\0`).
The OTHER side echoes the first mark (randA) in its second 07d0 with flags 0001.

### 0x0898 — capabilities/counter exchange (16B)

`0898 <2B counter/flags> 00000000 <4B randC> 00000001` — one per side.

### 0x0834 — payload/ack messages

Two sub-forms:
- **ack (16B):** `0834 0001 00000000 <4B echoedID> 0000000n` (counter n)
- **payload:** `0834 0000 00000000 <4B len> <4B id> 0000000n <payload>`
  where `len` = payload bytes (message total = 16 + len), payload begins
  with `bplist00` (NSKeyedArchiver).

### Handshake plist payloads (NSKeyedArchiver dicts)

**Invite (BRW→ADV, MessageID 1):**
```
MCNearbyServiceInviteIDKey: 1
MCNearbyServiceRecipientPeerIDKey: <NSData= 4B? + peer-8B-token + len + displayName>
MCNearbyServiceMessageIDKey: 1
MCNearbyServiceSenderPeerIDKey: <NSData= 4B? + self-8B-token + len + displayName>
```

**Connection/data (ADV→BRW, MessageID 2; echoed BRW→ADV, MessageID 3):**
```
MCNearbyServiceConnectionDataKey: <NSData 89B TLV blob — addresses + tokens>
MCNearbyServiceInviteIDKey: 1
MCNearbyServiceAcceptInviteKey: true   (ADV side only)
MCNearbyServiceRecipientPeerIDKey / SenderPeerIDKey: as above
MCNearbyServiceMessageIDKey: N
```

The 89B ConnectionData blob (both directions identical first 31 bytes):
```
80020059 12da 01 a8c0 fe80 000000000000001c 78b065b483f72cfe
8000000000000000 0cefd5fffe9005c3 61 <8B token> <4B?+2B?+token> ...
```

**Full segment decode** (verified against every captured blob; segment
grammar first published by evilsocket's 2022 mpcfw research, confirmed
byte-for-byte here):

```
0x80 | flags(1B) | len(1B)          header; flags 0x02 on encrypted .optional
                                      app pairs, 0x00 on others (a capability
                                      field, NOT the plane selector — a 0x00
                                      blob still runs DTLS; the plane is the
                                      app's encryptionPreference)
count(1B) ip4-reversed(4B)           e.g. 12 + c00002da reversed = 192.0.2.218
v6-addr-1(16B) v6-addr-2(16B)       two fe80 link-locals (en0, awdl0)
— then per-interface segments (16B each):
0x61|0x6a | peer-id-trunc-4B | random-4B | iface(0x5A=IPv4, 0x0A=IPv6)
           | pad(2B) | port(2BE)
```
- The **IPv4 segment's random-4B** is that peer's STUN username token:
  every STUN USERNAME = `[destination token]:[source token]` with 6-byte
  separators (see d0xx-tls.md R84).
- Address families: 01=IPv4 byte-swapped octets; fe80 IPv6 link-locals;
  MAC-derived L2 address; the peer 8-byte tokens.

**8-byte peer token** = the stable per-peer ID used by UDP (e.g. ALICE's
`294cb86b 41380245`; appears byte-reversed `45023841 6bb84c29` when sent by
the other side; also rendered as ASCII hex `394CB86B`/`41380245` in c102).

After the ConnectionData exchange: `0834 0001 ...` acks; TCP FIN/close.

---

## Confirmed invariants (multi-run, 2026-08-17)

Tested across dozens of fresh advertiser processes + 3 capture scenarios:

- Advertiser's TCP burst `[16B 07d0 hello (0cca7e2c), 42B name-hello, 16B
  0898 caps (2dc347ff)]` — **byte-identical every run**. `0cca7e2c` /
  `2dc347ff` are constants, not session randoms.
- mDNS SRV host UUID is **constant per machine** (`7f3e1546-…-9fec010a93c6`),
  not per process. Advertised addresses include `fe80::1c78:b065:b483:f72c`
  which matches the ConnectionData blob contents.
- Session UDP ports are the **fixed pair 16401/16402** in every connected
  session (both hosts bind 16401+16402 on all interfaces; data flows
  16401↔16402). No port negotiation on the wire.
- Plaintext sessions (`MCSession(peer:)`, nil identity) transmit the whole
  handshake and payloads **unencrypted**: everything above is directly
  readable and reproducible.

Per-session variable fields (to be pinned by second-capture diff):
the peer-identity NSData tokens inside the invite/connection plists, the
0834 message ids/counters, and the UDP hello randoms/counters.

## Phase 2 — UDP session channel

Two local ports per peer (16401/16402 in single-host capture; real
deployments negotiate ports via the ConnectionData blob). Datagrams:

### hello/ack family (0xxx / 01xx)

`0001 003c <4B sessionID> <4B seq> <4B ack> <4B ?advertised> 00060014 <8B tokA> 00000000 0001 <8B tokB> 00000000 0000 80010004 00000006 80030004 000003f2 80040004 <4B> ...`
- len field = datagram total − 20 (observed 0x3c/0x44/0x48/0xa0 ↔ 80/88/92/180B).
- sessionID (4B, e.g. 2112a442) is constant per session.
- 8001/8003/8004/8005/8008/8009/800a/800b = embedded TLVs (type 0x80nn, len
  field + value) carrying addresses/ids (e.g. `80010004 00000006`,
  `80040004 073b4707`).
- `0101` variants are acks (len smaller).

### identity exchange (c1xx)

- **Checksum:** every `c1xx` packet carries **CRC-16/ARC at bytes 6–7
  (big-endian), computed over the packet with that field zeroed** — verified
  20/20 samples across captures (claim first published by evilsocket/mpcfw
  2022; confirmed here). Mirrors the TCP layer's CRC32-at-bytes-8-11 rule.
- `c101 0022 0000 <2B csum@6> <8B tokA> <8B tokB> 0546f801 00100b 02000080 00000000 00000002` (34B)
- `c102 002b 0000 <2B> <8B tokA> <8B tokB> 0001 <8B> 0001 08 <asciihex tokA> 0001 <8B> 000000 38` — carries tokens as ASCII hex strings.
- `c103` = variant of c102.
- `c104 0012 0000 <2B> <8B tokA> <8B tokB> 0000` (18B) — done.

### data + ack (c105)

Data (69B = 4+2+2+8+2+2+8+4+4+2+33):
```
c105 0045 0000 <2B seqN> <8B tokA> 0500 <2B flags> <8B tokB-rev> 00000000
     <4B counter> 0001 <payload>
```
- `0045` = datagram length (69), `002c` for acks (44B).
- tokA = sender's 8B token, tokB-rev = peer token byte-reversed.
- counter (4B) increments per message in a direction (02 00 00 04 → 06 00 00
  04 for ack, 0a 01 00 08, 0e 02 00 0c, 12 03 00 10 …): low nibble = seq.
- embedded frame header `0001` precedes each app payload;
  payload arrives byte-exact (verified: 33B pattern intact at offset 36).

Ack (44B): same header, `070b <4B ackSeq>` instead of `0500…`, counter field,
then 8 zero bytes (no payload).

---

## Open questions (drive next via differential testing)

1. Exact semantics of 4B/2B sub-fields in hello/identity (seq, flags, adv).
2. Whether seq/counter layout is per-direction and whether start values are
   ever non-zero.
3. c101/c103 extra bytes meaning; whether the identity exchange can be
   simplified (echo peer values).
4. Whether the UDP endpoints are learnable solely from the ConnectionData
   blob for cross-Mac/Android deployments (ports differ per platform).
5. Advertiser vs browser TCP role: browser always connects first; confirm the
   responder can be the Android side in both roles.

## Unknown: the invite-acceptance gate (experiments completed 2026-08-17)

All TCP-phase elements verified, but a real `MCNearbyServiceAdvertiser`
REJECTS every synthetic invite (resets the connection; `didReceiveInvitation
FromPeer` never fires). Evidence so far:

- ADV replies to ANY TCP client with the constant 16B hello; its 42B
  name-hello + caps follow later; the connection is reset upon an invite it
  does not accept. ADV's reply sequence (caps/ack 73e2f9bb/connection-plist)
  fires only after a VALID invite.
- Rejection identical across: session-A templates, session-B (caps2)
  templates, ordinal mirrored from the ADV's own caps (learnable; patched
  into caps+invite header+InviteID), ordinals 1..5, LAN-IP vs loopback dial.
- `MCNearbyServiceInviteIDKey` = machine-global session ordinal (captures:
  1 → 2; each fresh advertiser process starts at 1).
- Peer-identity NSData tokens in the plists are per-process random, echoed by
  the responder, and NOT derivable from mDNS (TXT `_d` only, verified on the
  wire) or from the hello burst (base64/base32/md5/sha1/sha256 all fail
  against the two known (token→identity) pairs).
- Working hypothesis: the accept path verifies the invite's recipient
  identity against a per-process MCPeerID-derived value that a synthetic
  client cannot obtain pre-invite.

Next steps considered: test against the user's real macOS app deployment
(its parameters may differ — passcode/identity/negotiation), continue RE with
runtime instrumentation of MCNearbyServiceAdvertiser (dyld/lldb on the
private framework), or use a same-LAN bridge route that sidesteps this gate
(Android ⇄ small macOS MC companion ⇄ the app).

## Verified against the LIVE app stack (multipeer-cli = SecondSee's channel)

SecondSee ships `clients/publishers/swift/macos/Sources/multipeer-cli` — a
headless runner of the exact `MultipeerChannel` its iOS/macOS apps use
(`secondsee-mpc`, nil identity, `.optional` encryption, advertise+browse).
Test results against it:

1. **Discovery**: its browser finds our foreign mDNS advertiser (peerFound),
   but its session layer does NOT dial foreign advertisers (client-side gate).
2. **Invite acceptance — SOLVED**: the accepted initiator sequence is
   `hello1` → read ADV burst → fire `echo16 + caps + invite` in ONE write →
   **stay quiet**. The advertiser then sends `ack 73e2f9bb` + the 400B
   connection-data plist (deterministic constants every run; identity tokens
   are NOT validated). Pushing our own ack/echo early causes a RST.
3. **UDP identity exchange — CONFIRMED OPEN**: the advertiser answers the
   `0001/0101/c101–c104` hello/identity stream on ports 16401/16402 (LAN
   addr) with its own identical constant sequence on every datagram.
4. **OPEN: finalize-to-connected.** The session still never reports
   `connected` on the app-stack peer. The remaining unknown is the exact
   post-identity exchange (likely c105 data + acks with correct counters +
   the stream/RTM sync) that flips MC's state machine to connected.

Next experiment prepared: `sudo ./tools/capture-cli-pair.sh` captures a REAL
CLI↔CLI pair that DOES connect — diffing its UDP stream against our
synthetic client pinpoints the finalize bytes.

## FINAL: two data planes, selected by encryptionPreference (2026-08-17)

The CLI↔CLI connect-path capture (`caps-cli/`, two `multipeer-cli` processes
= SecondSee's own `MultipeerChannel`, `.optional` encryption) settles it:

- **`.none` sessions** (mcpeer pairs, caps/caps2): data plane = `c1xx`
  family, **plaintext**, fully mapped (this spec). 24 datagrams, no d0xx.
- **`.optional` sessions** (SecondSee's default): data plane = **`d0xx feff`
  family over UDP** with a **TLS-like handshake** — the first d0xx datagram
  embeds a TLS cipher-suite list (`c0 19 c0 18` = ChaCha20-Poly1305 AES,
  `006d/003a/006c/0034` AEAD suites, 0x0100/0x0023 TLS extensions), then
  encrypted records. 47 datagrams, 20 of which carry the JSON ping/pong
  envelopes inside TLS records (so `.optional` DOES encrypt app data even
  with nil identity — contradicting the naive reading of the docs).

Implication for Android interop with SecondSee's channel:
- **Fast path**: set `MultipeerChannel` encryption to `.none` for the text
  channel (one line in the app), and the already-mapped `c1xx` client
  completes to `connected` + JSON ping/pong. Everything up to that point
  (discovery, TCP accept, UDP identity) already validates against the app
  stack.
- **Full path**: reimplement the `d0xx`/TLS-like session (follow-on RE;
  handshake formats + key schedule over the custom framing).

## Validation loop

The Python client (`mc/`, `python -m mc.run`) speaks this spec against real
MC peers: run until the peer logs `STATE peer: 2` + `DATA len=33` (mcpeer) or
*Invitation accepted* / *Connected to participant* (a real app stack) — that
is interop, proven in the peer's own logs.