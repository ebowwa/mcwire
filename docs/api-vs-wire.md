# The public API vs. the wire — what `MultipeerConnectivity` abstracts, and what mcwire found underneath

Apple ships `MultipeerConnectivity` as ~15 public methods and three delegate
protocols with no wire documentation. This document maps every element of
that public surface to what actually crosses the network — as reverse-
engineered in this repo — and evaluates how much of it the foreign client
speaks. Every wire claim links to its evidence in the round log
(`d0xx-tls.md`) or byte spec (`mc-protocol.md`).

The API surface below is quoted from the SDK headers (macOS 26.5 SDK;
unchanged in essence since iOS 7 / macOS 10.10).

---

## 1. The map: API element → wire reality

| Public API | What the headers say | What actually goes over the wire | Evidence |
|---|---|---|---|
| `MCPeerID(displayName:)` | "an ID for the local peer" | An **8-byte random token** is minted per process. The display name, the token, and the mDNS instance name are one self-referential triple: instance name = **base36(token)**, greeting idString = base36(token)+name, peerID NSData = `[8B token][1B namelen][name]`. Greeting, invite, and Bonjour record must describe the *same* peer or the framework rejects the session. | mc-protocol.md "Identity"; R25 (identity system cracked from disassembly) |
| `MCNearbyServiceAdvertiser(discoveryInfo:serviceType:)` | advertise on Bonjour | `_<type>._tcp.local.` record; instance = base36(token); host = per-machine **UUID hostname** (`<uuid>.local.`); TXT carries the discoveryInfo keys **plus `_d` = display name**; ephemeral TCP port in SRV | mc-protocol.md "Discovery record"; R49/R51 logs |
| `startAdvertisingPeer()` | begin advertising | Registers the record via mDNSResponder. Gotcha we hit live: on multi-interface hosts the A records (loopback, self-assigned link-local, VPN, LAN) come back in arbitrary order — the *browser* must choose wisely or the session strands at ICE | R50 (`mdns.py` address selection) |
| `MCNearbyServiceBrowser.invitePeer(...)` | invite a found peer | **The whole TCP browser flow**: connect to the advertised port → `hello1` → their greeting → `echo16` receipt **#0** → `INVITE` (binary plist) → `caps` → their connect plist → our connect plist → receipt #1. Every message framed `op(2B)\|flags(2B)\|bodylen(4B)\|CRC32(4B)\|seq(4B)`, CRC = zlib.crc32 with bytes 8–11 zeroed. Receipts are **zero-indexed per stream** — a mismatched number is fatal. | mc-protocol.md framing; R15–16, R25, R41 |
| `invitationHandler(true, session)` (delegate) | accept the invitation | The advertiser answers with its own connect plist carrying an **89B (macOS) / 121B (iOS) ConnectionData TLV blob** — addresses, tokens, and the GCK port — which arms the invitee's ICE engine. Blob type byte is **role-dependent** (browser must send `8000`; `8002` breaks the peer's plist parse). | R41 (blob-type fix), R34 ("ICE STARTS EVERY RUN"); iOS 121B: R51 |
| `MCSessionState.connecting` | "Peer is connecting" | Five layers deep: TCP exchange → **GCK** (Apple's private layer under MC — it is ICE/STUN: binding checks with custom attrs `8001/8004/8005`, roles `8029/802a`, USE-CANDIDATE nomination + an 87-byte candidate blob) → DTLS → c1xx identity → OSPF-like Hello/LSA | R23–24 (GCK exposed), R26–36 (ICE), R28/41 (Connected) |
| `MCSessionState.connected` | "Peer is connected" | The app's log: `Connected to participant` (GCK) **then** the OSPF-like session layer completes (Hello flags `8000…0002` → LSA → LSAACK) → `MCSession: changed state [Connecting]→[Connected]`. The peer appears in the GCK **routing table** as a member node with neighbors + RTT | R28, R41 FINAL, R49 evidence |
| `MCEncryptionPreference` `.none` | "should not be encrypted" | The `c1xx` datagram family over UDP **in plaintext** (ports 16401/16402), app-level seq/ack — fully mapped | mc-protocol.md; R1–14 |
| `MCEncryptionPreference` `.optional` | "prefers encryption but will accept unencrypted" | A **completely different data plane**: `d0xx` envelopes = `0xD0`-prefixed **DTLS 1.0** records. The suites (`c019/c018/...`) are old IETF-draft **ECDH_anon** codes Apple never registered — anonymous ECDH P-256, **no certificates at all** (the app's own log: certificate length 0). OpenSSL speaks them as `AECDH-AES256-SHA` with `@SECLEVEL=0`. `.optional` also **silently degrades to plaintext** when DTLS fails. | R37–40 (crypto cracked), R41; degradation: README key findings |
| `.required` | "requires encryption" | Same DTLS plane **plus an identity handshake** (the `--required` grammar coverage in `mcpeer`). Partially mapped | mcpeer oracle flags; R41 notes |
| `session(didReceiveCertificate:...)` (delegate) | "decide whether to accept the peer's certificate" | Fires with **count = −1 / empty** on this plane — there are no certificates; it's anonymous ECDH. Your callback is a formality | R41 ("anonymous DTLS"), R49/R51 logs (`CERT2 count=-1`) |
| `sendData(_:toPeers:withMode:.reliable)` | "guaranteed reliable and in-order" | `c105` frames inside the encrypted tunnel: `[len][seq][crc16/ARC][tokA][flags+nonce][tokB][acked][counter][payload]` — **app-level** cumulative acks + a per-message counter (byte0 += 4). The peer retransmits its hello until its ack algebra is satisfied; the exact quench lives deeper than the wire shows (open item) | R42 (c105 decoded byte-exact), R50 scope note |
| `sendData(...withMode:.unreliable)` | "sent immediately, no guaranteed delivery" | Mapped in the plaintext plane (`c1xx` seq/ack family); the c105 `0500/070b` nonce pair distinguishes data/ack frames | mc-protocol.md; R42 |
| `sendResourceAtURL(...)` | stream a file with progress | **Not decoded** — Apple fragments big payloads at the MCSession/GCK layer ("Have to wait for more data" buffers) and reassembles. Unused by the target app; open | R43 (why: apps send video as JSON frames instead) |
| `startStreamWithName(...)` | named byte stream | **Not decoded**; ditto | R43 |
| `connectedPeers` (property) | peers currently connected | Membership in the GCK routing table (`Node [pid4] ... # of neighbors`) — the same table that admitted our foreign token in R49/R51 | R49 evidence; R51 |
| `disconnect()` | leave the session | Teardown + heartbeats stop (c108 keepalives ~5.5s while connected) | R41 |

---

## 2. What the API hides (the evaluation)

**"Connected" is a five-layer promise.** One `MCSessionState.connected`
boolean covers: TCP framing + CRC + receipts, an ICE/STUN engine with
Apple-private attributes, an anonymous DTLS 1.0 handshake with non-IANA
suite codes, an in-tunnel identity exchange (c1xx with masked participant
IDs and a role tie-break), and an OSPF-like Hello/LSA admission step. Our
foreign client had to satisfy **all five** to make the boolean flip on the
far side (R41 FINAL).

**The encryption preference selects protocols, not flags.** `.none` and
`.optional` are two unrelated wire formats (c1xx vs d0xx+DTLS). `.optional`
can silently downgrade to plaintext — an API consumer cannot tell which
plane actually ran from the API surface. (The app's own log can:
`DTLS context [0x0]` means plaintext.)

**Identity is one 8-byte token wearing three costumes** (Bonjour instance,
greeting idString, peerID blob) — and the framework enforces their
self-consistency from disassembly-level rules no API doc states. The
participant ID used on the wire is the token's **masked** last-4
(`token[4] & 0x7f`), a rule we only found by pinning identities and reading
the app's mismatch behavior (R41 FINAL: the masked-pid4 bug was the last
blocker before Connected).

**The API promises arbitrary-size `sendData`; the receive path does not.**
Records beyond ~4KB vanish silently at the peer's receive layer — Apple's
own stack fragments above that ("Have to wait for more data"); a foreign
client must implement that fragmentation (not yet done) or stay ≤~2.7KB
per frame, which is exactly how the target app's video path works
(200/200 small-JPEG frames, R47).

**Ports and the shared allocator.** The GCK ICE port allocator
(16397–16402) is shared and dynamic; squatting the range starves the peer's
allocator and ICE never validates — an environmental landmine invisible in
the API (README gotchas; R32/R45).

---

## 3. Coverage: the public API vs. what mcwire speaks

| API capability | mcwire status | Validated live on | Notes |
|---|---|---|---|
| Discover (advertise role) | ✅ | macOS · **iOS** | zeroconf advertiser; found+parsed by real `MCNearbyServiceBrowser`; the iPhone oracle's Bonjour record was browsed from Macs (R51) |
| Discover (browse role) | ✅ | macOS | browses, dials, completes invite flow — invitation **accepted by real apps** |
| Join session, reach `connected` (`.optional`) | ✅ | macOS · **iOS** | full stack; app-side verdict logged (R41, R48–R51); the iPhone oracle showed `state connected peers=["PYSRV"]` on its own screen (R51) |
| Join session (`.none`) | 🟡 mapped | macOS oracle | plane fully decoded; end-to-end foreign Connected proven on `.optional` |
| Join session (`.required`) | 🟡 partial | macOS oracle | identity-handshake grammar covered by the `mcpeer --required` oracle |
| `sendData` reliable | ✅ | macOS · **iOS** | c105 + byte-exact acks; the iPhone's hello/ping envelopes decoded at the foreign peer and acked (R51); our envelopes receipted at the transport layer |
| `sendData` unreliable | 🟡 | — | mapped in the plaintext plane |
| Payload ≥ ~4KB / fragmentation | ❌ | — | open (Apple's fragmentation protocol undecoded) |
| Named streams | ❌ | — | undecoded; unused by the target app |
| Resources (`sendResourceAtURL`) | ❌ | — | undecoded; unused by the target app |
| App-level video | ✅ | macOS | `kind:"frame"` JSON envelopes, 200/200 frames (the path shipped iOS builds actually use) |
| Foreign-peer platform coverage | ✅ | macOS · **iOS** | the mcwire client runs on macOS hosts (same-box, Mac↔Mac) and joins **real iPhone MCSession** from Macs (R51) |

iOS runtime validation = the shipped `ios/mcoracle` running on a physical
iPhone 13 mini (iPhone14,4): its Bonjour record browsed, its invitation
accepted, its session Connected (verdict on the device's own UI), and its
`hello`/`ping` envelopes decrypted + acked by the foreign client — from two
different Macs (R51).

Bottom line: for the parts of the API a chat/video-style app actually uses —
discovery, invitation, session establishment, reliable JSON/data envelopes —
the foreign client is at parity with a real Apple peer on the wire. The
unimplemented remainder (streams/resources/big-payload fragmentation) is
precisely the surface the target app doesn't use either.

---

## 4. Method note

The API column is quoted from the SDK headers — verified **byte-identical**
between the MacOSX 26.5 and iPhoneOS 26.5 SDKs (`MCSession.h`,
`MCNearbyServiceAdvertiser.h`, `MCNearbyServiceBrowser.h`, `MCPeerID.h`,
`MCError.h`; one shared API since iOS 7 / macOS 10.10).
The wire column comes exclusively from this repo's captures and live
probing: ~53 annotated session datagrams (`mc/templates/d0xx/`), the
byte-exact TCP templates (`mc/templates/tcp-clipair/`), and 51 rounds of
live validation against real framework peers — culminating in the
self-contained oracles (`Sources/mcoracle`, `ios/mcoracle`) that let anyone
reproduce the API's "Connected" with this repo alone
(`tools/verify-session.sh`).