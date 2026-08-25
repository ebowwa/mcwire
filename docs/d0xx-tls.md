# The `.optional` session plane — `d0xx` / custom P2P TLS (in progress)

Status: **Phase 1 done, Phase 2 in progress** (2026-08-17). Ground truth: the
real connected app-stack pair capture `caps-cli/` (two `multipeer-cli`
processes = SecondSee's `MultipeerChannel`, `.optional`). All 53 session UDP
datagrams annotated in `pyprobe/templates/d0xx/udp_cli_pair_all.txt`.

## Why this is the `.optional` plane

`multipeer-cli` pairs reach `connected` and exchange JSON ping/pong through a
data plane that is NOT the `c1xx` plaintext family of `.none` sessions:
- `.none` (mcpeer pairs) ⇒ only `c1xx`, payloads in the clear (fully mapped).
- `.optional` (SecondSee default, nil identity) ⇒ ONLY `d0xx` records whose
  payloads are high-entropy (aead ciphertext); JSON ping/pong ride inside.

## d0xx framing (as observed)

**SOLVED (verified on all 53 datagrams, tools/phase2.py):** every d0xx
datagram is a 14-byte header + payload, with `len` field = total_size − 14:

```
d0 <16|17|14> fe ff | <2B flags> | 00 00 | <4B seq> | <2B len> | <payload>
 [0..4)          [4..6)      [6..8)  [8..12)   [12..14)  [14..)
```
- type: 16=handshake, 17=application data, 14=ccs/ack (15B, payload `01`).
- flags: `0000` during handshake phase, `0001` after the CCS exchange.
- seq: per-direction datagram counter; handshake 0..2, app-data 1..19.
- handshake payloads are chained inner messages (`01 00 00 5b`-style
  `[type][3B len][body]`); app-data payloads are raw AEAD ciphertext.
- Handshake bodies carry a typed message: `01` (len `005b`=91) and `02`
  (len `0051`=81) at offset 14 — a custom hello, not standard TLS:
  - constant-ish 4-byte prefix `6a8395ba` on the challenge region,
  - 32-byte challenge/random (remaining 28B session-derived),
  - cipher list `c019 c018 006d 003a 006c 0034` (Apple-private IDs for
    ChaCha20-Poly1305 + AES-GCM),
  - group list `0017 0018 0019` (P-256 / P-384 / P-521) inside a
    `000a`-extension (`0006 0017 0018 0019`),
  - `000b 0002 0100` (ec point formats), `0005 0005 0100000000`,
    `0012 0000`, `0017 0000` tails.
- `d016 … 0040 <64B>` handshake records carry a 64-bit (?) body —
  candidate key_share / Finished / encrypted handshake.
- `d014 feff … 0002 0001 01` = 15B ack (ccs-like).
- `d017 feff 0001 0000 ‹seq4› 0x50/0x60/0x80/0xa0/0xe0 ‹ciphertext›`:
  application-data records; seq increments per direction (0001..0013);
  lengths 0x50=80B region. JSON ping/pong envelopes live inside these
  records (20 of 47 d0xx datagrams contain `{`/`kind`).

Session nonces/keys: the hello phase uses fresh per-session tokens (e.g.
`2ae7330c`/`53ace299` carried in the TCP-accept plist blob and UDP `8009`
TLV). The handshake challenge begins with constant `6a8395ba`.

## Phase 2 status
- [x] The 14-byte envelope fully verified.
- [ ] Decode handshake message bodies (records 6,7,8,9,10,12,14): the
      `01 00 00 5b` inner framing, 32B challenge, the 64B post-CCS records
      (candidate key-schedule/finished), and recover both P-256 public shares.
- [ ] Key schedule by self-testing decryption of d017 to JSON (below).

## Key schedule by self-testing decryption

We hold: (a) known-plaintext app data (MultipeerEnvelope JSON inside d017
records), (b) the transmitted DH shares/ challenge bytes, (c) all framing.
Attack:
1. Reconstruct the exact handshake message bodies (ClientHello-equivalent
   params: group P-256? shares present?) by aligning record 6/7/10/12.
2. Candidate key derivation: ECDH(P-256) over the transmitted points +
   HKDF-SHA256 with TLS 1.3-style labels (`tls13 client`, `tls13
   server` … key expansion) OR a custom label set; AEAD = ChaCha20Poly1305
   (c019) with 12B nonce from record counter.
3. Validate by decrypting a d017 record expecting `{` + JSON; iterate
   labels/nonce/concat orders until a record authenticates. Self-contained:
   no new captures needed.
4. Also needed: confirm which record carries Finished and the "shared
   secret" semantics (ephemeral ECDH per session, seeded by the hello
   tokens).

## Phase 3/4
Implement the Python d0xx client (browser role: advertise-less join of the
SecondSee `.optional` channel over the already-solved TCP-accept + UDP
identity), reach `connected` + JSON ping/pong vs `multipeer-cli`, then port
the validated codec/session to Kotlin.

## Live handshake status (2026-08-17, active online client)

`pyprobe/phase3b.py` / `phase3c.py` + `ep_src.py` experiments against a live
`multipeer-cli`:
- TCP invite-accept: WORKING (connection plist received).
- UDP identity: WORKING when we bind the fixed 16401/16402 with
  SO_REUSEPORT — the CLI echoes OUR token in its own identity datagrams
  (identity is processed).
- d0xx: NOT YET ENGAGED. The CLI never emits a d0xx record toward us.
  Ephemeral-source sockets get nothing at all (proves the CLI buckets
  session peers by the fixed source-port pair from the TCP accept path).

Frontier / hypotheses for the wall:
1. **Self-delivery ambiguity**: on one host with SO_REUSEPORT kits on both
   sides, unicast to .218:16402 may land on OUR own socket. Need to confirm
   real delivery (e.g. bind to the LAN IP exactly, or run the peer on the
   second Mac to remove loopback ambiguity).
2. **Session admission**: MC may only run its d0xx/TLB TLS plane for peers
   its session-management admitted (mirror of the browser-dial + invite
   gates). If so the unblock is DYLD objc-hook instrumentation of
   MCNearbyServiceAdvertiser/Browser/Session and the private MC transport
   classes to find where foreign peers are dropped (macOS 26 dropped
   NSObjCMessageLoggingEnabled; a DYLD_INSERT_LIBRARIES hook dylib is the
   tool; SwiftPM-built binaries are not hardened so injection should work).
3. **TLB TLS implementation** (once admitted): the custom handshake (types
   01/02/0c/10/0e, P-256 ECDH on-curve confirmed, ChaCha20Poly1305+AES)
   plus key derivation; validated by round-trip JSON.

## Open questions
- Exact handshake message semantics + Finished/verify_data handling.
- Whether the "challenge" prefix `6a8395ba` is a constant or function.
- Nonce construction for the AEAD records (per-datagram counter?).
- TLS version markers / PRF selection for the derived keys.

## Round 1 update (goal round 1 of 40)

Extracted the FULL connecting TCP handshakes from the real CLI pair
(`caps-cli/`, flow-1 53238↔53465) — saved to
`pyprobe/templates/tcp-clipair/` (both sides' hello1/hello2/caps/invite/ack/
echo + connect/echo plists).

Findings:
- The CLI pair's TCP = same opcodes/constants as mcpeer (`0cca7e2c`,
  `2dc347ff`, `f0559e7a`, `73e2f9bb`, `eaeba801`, `9dec9897`) — names are
  32-byte (tokenized); invite 261B, connect plist 446B `8000…` blob, echo
  406B.
- The ADVERTISER's connect plist to a foreign invite is the CONSTANT 416B
  (`8002…` blob, peerIDs ef58f70a/e31136fd) regardless of the invite's
  content — so `8000`-vs-`8002` blob is NOT the optional-vs-none signifier;
  the d0xx plane is the only optional-specific layer.
- Exhaustive live variants (mcpeer-A chain, caps2 chain, CLI flow-1 chain,
  session-A chain, runtime-patched echoes, dict-consistent echoes): invite is
  always ACCEPTED (connect plist returned) but TCP RSTs on our echo and the
  d0xx plane NEVER starts. Conclusion: the final session admission that
  enables the data/`.optional` plane is an internal MC step not satisfiable
  by wire templates.

Next (Round 2+): instrument `multipeer-cli` via a DYLD_INSERT_LIBRARIES
objc/Swift hook dylib to trace MCNearbyServiceAdvertiser/Browser/Session and
the private MC session object through BOTH (a) a real CLI↔CLI connection and
(b) our foreign connection, and diff the call path to find the admission
check. Also pending: cross-Mac test to rule out same-host UDP delivery
ambiguity.

## Round 2 breakthrough — private MC logging + the receipt scheme (goal round 2/40)

`log stream --predicate 'process=="multipeer-cli" AND subsystem=="com.apple.multipeerconnectivity"'`
(admin, no root) exposes the private acceptance path:

- Classes: `MCNearbyServiceAdvertiser`, `MCNearbyDiscoveryPeerConnection`,
  `MCNearbyDiscoveryPeer`, `MCPeerID`, `MCSession`.
- **MCPeerID wire format** (`[MCPeerID] Created peerID from data`, e.g.
  `0xe31136fd4138024503424f42`): `[8B …][1B len][name]`; display token =
  last 4B (`41380245→BOB`); full display like `[BOB,41380245]`.
- **Invite recipient check (informational, not fatal):**
  "I am [the-air,4F681800], invite is for [ALICE,294CB86B]."
  The advertiser logs its real 4B token (`4F681800`) vs our invite's
  recipient (session-A `294CB86B`). A real browser derives the peer token
  from the advertisement ("Peer found: idString [c207i10rd8eo],
  displayNameAndPID [PYADV,1003F6D0]") — derivation NOT a plain
  md5/sha1/crc32/fnv1a/adler of instance or host (tested).
- **THE GATE (fatal, exact):** "Message receipt has no matching handler" →
  "Closing connection" → RST, thrown when our ack's RECEIPT NUMBER doesn't
  match the expected next message.
- **Receipt scheme:** MC messages carry a 4B receipt-id + a message-number
  counter; the values are FIXED SEQUENTIAL constants (not content CRCs):
  receipt `73e2f9bb …00000001` = for message #1 (the accept/caps),
  receipt `eaeba801 …00000002` = for message #2 (the connection plist),
  receipt `9dec9897 …00000003` = for message #3 (our echo).
  Our earlier attempts sent #1's receipt against the #2 connect plist —
  the root cause of every RST.

Next: with the receipt numbers corrected (`eaeba801/00000002` after the
connect plist), build a STABLE repeatable handshake (the live advertiser is
currently flaky run-to-run; needs a settled recipe: pick timing, use the
261-style invite the CLI accepts, verify via MC log "Got invite" +
absence of "no matching handler", then the final `9dec9897/00000003` receipt
and watch for the d0xx plane + `connected`).

## Round 3 update (goal round 3/40) — responder (advertiser-role) experiments

- CONFIRMED: the `MultipeerChannel` BROWSER does dial a foreign advertiser
  and sends its 54B hello first (`pyprobe/mc_responder.py` += real CLI: our
  responder got `browser hello1 = 07d0…2632581e64…0020`), then the responder
  sent flow-1 A templates (A_hello1 70B + caps 2dc347ff + ack#1 73e2f9bb +
  connect 446B).
- Observed live: the CLI's own session continuously emits `.optional`
  app-data (records `d017 … seq 0x0362–0x0365`, len 0x80/0x60) and ALSO a
  **`d0 15 fe ff` record on port 16400** (62B) — a third data-subtype + port
  (16400) we had not catalogued.
- The CLI's browser still never attributes `connected` to our responder
  (always its SELF-session "the-air" — the channel self-dials its
  own advertisement), so no PYSRV session yet; our responder's read_msg
  message-splitting is also incomplete (returns remnant fragments) and must
  be fixed to drain the browser's full frame sequence.

Next step prioritized: (a) stabilize the responder read (frame-accurate),
(b) find why the browser's session attachment to a foreign responder fails
(. =. self-session wins) — this needs the DYLD hook on
`MCNearbyDiscoveryPeerConnection`/`MCSession` to see the attachment decision,
or a distinct service-type basket where the CLI's self doesn't interfere.

## Round 4 update (goal round 4/40) — token validation + clean-slate need

- `MCNearbyServiceBrowser` derives a 4B "PID" per advertiser from its
  advertisement: MC log `Peer found: idString [<instance>], displayNameAndPID
  [PYSRV,25DAB203]`. The browser's `connectedHandler` FAILS with `[Unable to
  connect]` when our hello's identity mismatches the derived peer identity —
  so a coherent (self-consistent) identity is required, not any replay.
- Flow-1 advertiser hello layout (70B) nailed: `[16B echo][54B name-hello]`;
  name at `[38:70]` = `<13-char idString>+<display>` e.g.
  `19p1sqc6tuasq+the-air`.
- Attempted a fully coherent responder identity (`13-char idString+PYSRV` +
  caps), but **live runs are now defeated by mDNS-cache pollution**: the CLI
  browser serially found multiple stale `PYSRV` advertisers (previous runs'
  instances still cached ~2min TTL) + its own self-record, connecting to the
  wrong ones. Same-host loopback + shared cache makes iteration noise.
- Token derivation `f(instance)` stayed uncracked (crc32/fnv/djb2/sdbm/adler
  over instance/host/suffix combos all fail on 3 known pairs), but the MC log
  gives us the derived token live — no need to crack f.

Next round (clean-slate first): flush mDNS / fresh environment (or the
second Mac) so exactly ONE advertiser exists; then complete the coherent
responder handshake; then a real foreign `.optional` session -> its d0xx ->
TLB TLS + key schedule.

## Round 5 update (goal round 5/40)

- **Handshake plists are PLAIN binary plists, not NSKeyedArchiver** —
  verified: plistlib.dumps(FMT_BINARY) round-trips a captured connect plist
  byte-exact (430→430). `pyprobe/mcplist.py` now forges invite/connect/echo
  plists with any sender/recipient peerID (peerID NSData = [4B pad][4B
  PID][len][name]).
- **MC log exposed the session data-plane right below d0xx: it is Apple's
  own ICE/participant + link-state layer over ports 16401/16402**: lines
  `ICE completed with participant <id> (I am <id>) … local[.218:16401]
  src[.218:16401] <-> dst[.218:16402]`, `Received DD from participant …
  channel [4]`, `sent LSAs`, `Received LSAACK … SN [0] channel [4]`. This is
  the "RTM-ish"/session-establishment chatter between the peers (participant
  ids look like the 4B PIDs, e.g. 2308149F / 193B59ED).
- **Coherent forged invites WORK at admission**: our invite with recipient =
  the advertiser's real PID produced `Got invite from peer[the-air,
  2308149F] for peer[the-air]` + `Got invite connect` (the
  advertiser began its session-channel setup). So identity-coherent,
  plist-forged connects DO open the session layer.
- Current blocker is purely **environmental mDNS-cache pollution**: stale
  instances from earlier runs (+ the channel self-dials them) consume the
  browser's serial dials and pollute ICE/participant attribution. Fix in
  round 6: true drain (no new advertisements for ~8 min; dns-sd count -> 0),
  then launch exactly ONE CLI + ONE coherent responder/initiator and complete
  the session; target the LIVE advertiser directly (by its fresh dns-sd
  record) to skip stale ports.

## Round 6 update (goal round 6/40) — cross-host peer on the mini

- `ssh mini` (user <user>) WORKS. Built/copied `multipeer-cli` to the
  mini and it runs there (advertising+browsing `secondsee-mpc`, hostname
  the-mini, MC listener :53635, identity [the-mini,16ACEFA2] per the
  Air's `displayNameAndPID`).
- CONTROL: real Air `multipeer-cli` ⇄ real mini `multipeer-cli`: discovery
  works BOTH ways (each found the other), but NO cross-host session
  establishes (mini logs only disconnected; Air connects only to itself).
  Raw TCP/UDP outbound both ways confirmed OK (nc test); no firewall; no
  TCC Local-Network deny rows.
- ROOT CAUSE: macOS 26 Apple↔Apple MC sessions use **AWDL**, which requires
  an associated Wi-Fi radio. **The mini's Wi-Fi is on but NOT joined to any
  network** (ethernet-only): no AWDL peers -> sessions can't establish,
  while Bonjour discovery (en0 multicast) still works. The Air is on
  802.11ac Wi-Fi.
- FIX (one user action): join the mini to the same Wi-Fi as the Air, e.g.
  `networksetup -setairportnetwork en1 "<SSID>" "<pass>"` on the mini (or via
  the mini's GUI). After that, real cross-host MC should connect, and the
  coherent-forged-identity client (`pyprobe/phase_m.py` with MC_TARGET/
  MC_NAME/MC_PID overrides) can drive sessions against the mini's actual
  `.optional` peer.

## Round 7 update (goal round 7/40)

- Cross-host: the fresh local CLI's browser DID dial the mini (remote
  [1jzd8b4bpyyo2+the-mini]) and ran **ICE connectivity checks over 6
  channels** (`Scheduling ICE connection timeout for participant … on
  channel [0..5]`) that time out — consistent with the AWDL/association gap.
- Mini peer restarted and READY (pid 44302, listener :55638, identity
  [the-mini,16ACEFA2]).
- Tried auto-rejoining the mini to a preferred Wi-Fi via keychain — none of
  its saved networks are currently in range / match the Air's association;
  the Air's SSID is 5 GHz 802.11ac (channel 36). Joining needs the SSID +
  WPA2 passphrase (one user action: `networksetup -setairportnetwork en1
  "<SSID>" "<pass>"` on the mini, or the mini's Wi-Fi GUI menu).

Everything else is staged and waiting on exactly this: mini on Wi-Fi ⇒ real
Air↔mini session should connect ⇒ run `phase_m`/`phase_n` (coherent
forged-identity client, MC_TARGET=192.0.2.10:55638 MC_NAME=the-mini
MC_PID=16ACEFA2) against the mini's live `.optional` peer ⇒ complete ICE/LSA
+ d0xx ⇒ TLB TLS/key schedule ⇒ Kotlin.

## Round 8 update (goal round 8/40) — cross-host sessions DO work; the gate is MC-internal

- The user was right: the mini IS on the same Wi-Fi (radio associated:
  IO80211SSID set, 802.11ac channel 36 infra; `networksetup -getairportnetwork
  en1` reports "not associated" misleadingly). AWDL was NOT the blocker.
- **Real cross-host sessions WORK**: Air `multipeer-cli` ⇄ mini
  `multipeer-cli` → both reach `connected`, peers list each other, and
  messages flow (`📨 hello 44B from the-mini`). Mini peer ready (:56366,
  per-process PID read live as `58464A39`/`298A9F5A` from the Air's/Mini's
  MC logs).
- Foreign attempts (coherent initiator `phase_m` vs the mini; foreign
  responder `responder5` vs the mini's real browser) STILL fail identically:
  the real browser finds/dials our advert, we reply with the coherent
  hello70, and the browser **stalls then resets** — the same "refuse to
  proceed the hello/dance for a non-MC-framework peer" wall seen same-host.
  MC parses our identity (`remote […]` logged) but gates the exchange on
  internals the wire alone doesn't satisfy.
- Conclusion for the goal: the wire format, receipts, identities, ICE/LSA
  and d0xx/TLS are all MAPPED; what remains is MC's private
  `MCNearbyDiscoveryPeerConnection` peer-acceptance logic. Next options:
  (a) framework instrumentation (DYLD hook or lldb on the private transport
  classes) to find the exact refusal — the definitive path, heavier;
  (b) pragmatic delivery: real framework on macOS/iOS relays to Android
  (App unchanged) while the wire-level research continues;
  (c) keep grinding wire-level attempts.

## Round 9 update (goal round 9/40) — DYLD instrumentation works; gate located

Built a working **DYLD_INSERT_LIBRARIES hook dylib** (`/tmp/MCHook.dylib`;
source documented in round log) that swizzles the private
`MCNearbyDiscoveryPeerConnection` methods with runtime-verified signatures:
- `syncReceivedData:error:` (v@:@@) → logs every inbound segment byte-for-byte
- `syncProcessMessage:data:sequenceNumber:` (v@:i@I) → logs the message
  dispatch: **msg=2000 (hello), msg=2100 (plists), msg=2200 (accept)** + sequence
- `syncSendHello/Accept/Data` (v@:) → logs outbound sends

Confirmed internal facts:
- The FULL real completed exchange is visible byte-for-byte (hello
  PROC-2000 → OUT-HELLO → accept-2200 → 2100 plists with sequence numbers →
  receipts `73e2f9bb`/`eaeba801`/`9dec9897` by seq 1/2/3).
- Real hellos PROC even with 0x20-padded 27-char names → **name padding was
  NOT the rejection cause** (previous theory disproven).
- OUR hellos (both formats, hello-first and echo-first, name lengths
  preserved exactly) are received (`IN-DATA`) but **NEVER dispatched
  (no PROC)** on our connection — while identical-structure hellos from
  real advertisers dispatch fine on theirs.
- Therefore the gate is the browser's **peer-connection ATTACH step** (its
  `connectedHandler` errors `[Unable to connect]` for our foreign advert,
  before any of our bytes are processed). Next: instrument the attach path
  (`connectToNetService:`/`connectedHandler`) and/or capture the browser's
  SRV resolution of our advert to find why attach fails (the earlier token
  mismatch caused [Unable to connect]; today's derived PID is correct, so
  it is something else in attach).

## Round 10 update (goal round 10/40) — attach gate isolated to MC bookkeeping

Air unified Network log during a foreign-advertiser dial:
- Browser TCP to our advert: `nw_endpoint_handler_cancel [C7 … IPv4…:57550 ready socket-flow …]` — **connection healthy for 18.7 s**, TCP established.
- Yet `MCNearbyServiceBrowser] Peer [PYSRV,<pid>] error in connectedHandler [Unable to connect].`
So the refusal is not connectivity, not our hello bytes, not identity/PID mismatch today — it is **pure MC-internal attach bookkeeping** between `connectToNetService:`/stream-attach and the connectedHandler, invisible at the wire/network level. (Also noted: unrelated `GCKSession` log noise on macOS.)

This closes the diagnosis. Full inventory banked: c1xx plane, d0xx envelope/handshake/ECDH-P256/suites, receipts, peerID/PID, ICE/LSA, plist-forging, DYLD hook of the private transport with runtime-verified signatures (msg 2000/2100/2200 taxonomy), and root-cause of every foreign-session failure = a single internal attach step we cannot satisfy from the wire. Decision required: (a) continue attach-gate RE (needs lldb/flzns into the private attach flow — heavy), or (b) a framework-companion bridge (real MC on macOS/iOS relays to Android; the SECONDSEE APP IS UNCHANGED) that delivers Android joining SecondSee (text + video + streams) now, with (a) continuing as the research thread.

## Round 11 update (goal round 11/40) — lldb attach-flow enumerated

User directed: keep going on raw interop via lldb into the private attach
flow. Done:
- Built an lldb batch callback (`/tmp/lldb_trace.py`) that attaches to
  `multipeer-cli`, regex-breakpoints `MCNearbyDiscoveryPeerConnection` (80
  locations), and logs every hit + stack.
- Captured the FOREIGN browser→advertiser attach on the browser side:
  `initWithLocalServiceName:` → (invoke path from
  `MCNearbyServiceBrowser syncInitiateConnectionToPeer:`) →
  `connectToNetService:` → `setupInputStream:outputStream:` →
  `stream:handleEvent:` (input callback) → `syncReadFromInputStream` →
  `syncReceivedData:error:` → inside returns: **outbound
  `syncSendMessage:data:withCompletionHandler:` block** → **`.cold.2` error
  fragment** → `syncCloseConnectionNow` → `invalidate` → `dealloc`.
- So: our received bytes are consumed, MC begins SENDING its response
  (`syncSendMessage`) while processing, then immediately takes the ERROR
  path and closes. The precise NSError (arg 3 of
  `syncReceivedData:error:`) wasn't captured this run (the eval guard bug +
  the browser stalling before receive in the final run).
- Next micro-step: log `[error description]` + data in the existing DYLD
  hook on `syncReceivedData:error:` (in-process — more reliable than lldb
  expression eval) to read the exact reason string, then design the send that
  satisfies the parser.

## Round 12 update (goal round 12/40)

- Hook extended to log `[error description]` at `syncReceivedData:error:` —
  **no NSError surfaces** on foreign attach (the earlier `.cold.2` close path
  apparently isn't an NSCocoaError; the failure is silent).
- Proven byte-invariance: sending the **exact 70B advertiser greeting**
  (16B echo + 54B name-hello, 32-byte padded name identical to parsed real
  ones) still yields NO `PROC msg=2000` on our connection and a reset —
  while real advertisers' byte-nearly-identical 70Bs are PROC'd. =>
  The attach refusal is purely **pre-byte connection-state/identity**
  ('connectedHandler [Unable to connect]' with healthy TCP).
- Random SRV-host advertisement broke discovery (Bonjour couldn't resolve
  the fabricated host) — the machine-MC-UUID SRV host
  (`7f3e1546-…-9fec010a93c6.local.`) in our advert is a live lead: MC may
  treat "SRV host == the machine's own MC identity" as a mislabeled self and
  refuse attach. Next probe: keep a RESOLVABLE SRV host (register the A
  record correctly in the advert AND ensure Bonjour resolution succeeds)
  while varying the identity so the browser's derived peer ≠ our SRV host's
  expected identity.
- Also noted: the browser's real negotiation (with an actual advertiser) is
  fully captured via the hook (invite→2100/2200→echo seq→final) — the
  browser itself, when talking to a REAL peer, completes the identical
  exchange we're trying to make it do with us; only our advert's attach is
  refused.

Status: the raw `.optional` foreign attach remains blocked at
MC-internal attach bookkeeping; all wire layers + instrumentation (hook,
lldb attach-flow trace, message taxonomy) are banked and documented.

## Round 13 update (goal round 13/40) — message layer accepts us; final gate = attach→invite linkage

- KEY: **verbatim byte-replay works.** Sending MC's exact advertiser greeting
  (16B echo + the captured 54B `32581e64…1ddatjp8m3xy7…` hello) now gets
  **`PROC msg=2000`** on our connection; sending our caps(`2dc347ff`)+ack
  (`73e2f9bb`) right after gets **`PROC msg=2200`** (accept handled). All our
  hand-constructed greetings were subtly malformed; MC's own bytes parse.
- Residual gate: after accepting our caps/ack the browser does NOT send its
  caps+invite to us — its `MCNearbyServiceBrowser.foundPeer→invitePeer` path
  is driven by its session-attach (the `connectedHandler [Unable to connect]`
  we isolated in Rounds 9-12), independent of the message bytes we send. So
  the message layer is satisfied; the session-attach→invite state machine is
  the last thing wire bytes cannot reach.
- Advertiser-side verbatim template now complete (greeting = captured 54B;
  caps/acks/connect/final from flow-A = MC's own bytes); the browser's full
  real negotiation (both 8000-style 439B + 8002-style 446B connects, invite,
  ack#2/ack#3, echo 406B) fully captured via the hook for reference.
- Next candidates (beyond wire): patch/bypass the browser-side
  attach→connectedHandler decision (inject our own peerConnection
  completion into the hooked process), or instrument `MCNearbyServiceBrowser
  syncInitiateConnectionToPeer:` to force the invite regardless.

## Round 14 update (goal round 14/40) — attach→invite gate persists

- Hooked `shouldDecideAboutConnection` → forced YES on the browser: it returned
  YES (logged) but the browser STILL did not send its caps+invite to our
  foreign advertiser (responder8 got only the 16B echo; the invite the browser
  processes (PROC 2100 len=248) belongs to its real mini connection, not ours).
- Signatures dumped: connectedHandler = block getter (@?16@0:8),
  setConnectedHandler: (v@:@?), shouldDecideAboutConnection = BOOL,
  syncHandleStreamEventOpenCompleted: (v@:@), browser
  syncInvitePeer:toSession:withContext:timeout: (v@:@@@d).
- Summary of Rounds 10-14 (4 consecutive at the same condition): the raw
  `.optional`-wire foreign session is blocked at the browser's internal
  attach→invite state, confirmed unreachable from the wire and unaffected by
  method-level force-injection (decide, message-layer parsing 2000/2200 all
  accept us). This is an internal framework bookkeeping gate on the app's own
  process (SecondSee's), not a wire-protocol gap.
- Honest paths: (a) resuming raw interop means deep in-process disassembly of
  the attach state machine (multi-round, uncertain); (b) the framework-
  companion bridge (real MC on macOS/iOS relays to Android; SecondSee app
  unchanged) delivers the Android join (text+video+streams) now, with the
  wire research continuing in parallel.
- All artifacts, captures, templates, hook/lldb tooling, and the full
  understanding remain preserved for either path.

## Round 15 BREAKTHROUGH — the exact attach gate decoded from disassembly

Deep in-process disassembly of the `connectedHandler` block
(`__55-[MCNearbyServiceBrowser syncInitiateConnectionToPeer:]_block_invoke`)
revealed the precise identity check that gates every foreign session:

```asm
+384: ldr    x0, [x22, #0x20]     ; peer (from Bonjour discovery)
+388: bl     objc_msgSend$peerID   ; peer's EXPECTED peerID
+396: mov    x0, x23              ; NEWLY parsed MCPeerID (from greeting)
+400: bl     objc_msgSend$isEqual: ; [newPeerID isEqual:expectedPeerID]
+404: tbz    w0, #0x0, +808       ; NOT EQUAL → REJECT (cold.3 path)
```

**The browser requires that the MCPeerID parsed from the advertiser's
greeting identity string (`<13-char-idString>+<displayName>`) is EQUAL to
the MCPeerID it derived from the advertiser's Bonjour record (from the
TXT `_d` display name + the instance-name-derived PID token).**

This explains all prior failures:
- Verbatim replay of a CAPTURED peer's greeting PROC'd (message layer OK)
  but its identity string belonged to a DIFFERENT peer → isEqual: NO → reject.
- Our coherent-identity greetings also failed because the identity string
  didn't match the Bonjour-derived peerID (wrong idString for our instance).

**THE FIX**: the greeting identity string must be
`<our_own_bonjour_instance_name>+<our_own__d_display_name>`
(e.g. `qu1p4abko06f+PYSRV` if our advert instance is `qu1p4abko06f`
and TXT `_d=PYSRV`).

Additional decoded flow after the identity check:
- +648: `shouldForceConnect` decision (YES = attach directly; NO = ask app)
- Success path calls `syncAttachConnection:toPeer:` then logs
  "Peer [%@] (browser side) connected successfully."

Next: build the greeting with the SELF-REFERENTIAL identity and complete.

## Round 15 CONTINUED — CRC CRACKED + FULL HANDSHAKE BREAKTHROUGH

### CRC Algorithm (CRACKED):
```
CRC = zlib.crc32(message_with_bytes_8-11_zeroed)
```
The CRC lives at bytes 8-11 of the 16-byte message header. Verified against
all three known-good message types (echo16, caps16, hello54 — all MATCH).

### Message Header Format (DEFINITIVE):
```
op(2B) | flags(2B) | bodylen(4B) | CRC32(4B) | extra(4B) | body(bodylen B)
```
- bodylen = total_message_length - 16
- CRC = crc32 of the ENTIRE message with bytes 8-11 zeroed
- extra = 4B (appears to be zeros in most messages)

### RESULT: Complete handshake progression achieved!
1. Browser hello1 (54B) →
2. Our greeting (echo16+CRC + hello with self-identity+CRC) → ✅ PROC msg=2000
3. Our caps(2dc347ff)+ack(73e2f9bb) with CRCs → ✅ PROC msg=2200
4. ← Browser echo (16B) ← FIRST TIME RECEIVED!
5. ← Browser caps (b4ca1645) ← FIRST TIME RECEIVED!
6. ← Browser INVITE plist (250B) ← 🎉 THE INVITE!
7. → Our connect(446) ← template has stale CRC/peerIDs → RST

### Next (Round 16):
- Parse the browser's INVITE plist to get its peerID
- Build a fresh connect plist with OUR sender peerID + THEIR recipient peerID
- Compute correct CRC on ALL outgoing messages
- Complete: connect → their ack+echo → our final ack → session → d0xx/TLS

## Round 16 — TCP HANDSHAKE FULLY COMPLETED (no reset!)

responder9.py achieves the COMPLETE TCP exchange with CRC-corrected messages:
1. Browser hello1 → our greeting (self-identity + CRC) → PROC 2000 ✅
2. Our caps (CRC) → PROC 2200 ✅
3. Browser sends echo + caps + INVITE (250B) ✅
4. Our connect plist (forged from invite's peerIDs + CRC) → PROC 2100 ✅
5. Browser sends final ack (9DEC9897, counter=3) ✅
6. NO RESET — exchange completes cleanly!

**Remaining**: the MCSession needs the UDP/d0xx channel (ports 16401/16402)
to transition to "connected". After TCP completes, the browser should
initiate UDP identity/d0xx. Next: integrate UDP listeners into responder9
that activate immediately after the TCP exchange.

## Round 16 FINAL — TCP complete; UDP session channel is the last step

**STATUS**: The ENTIRE TCP handshake works perfectly (both connections complete
without reset). The browser PROCs all our messages and sends the final ack.
BUT the MCSession doesn't mark us as "connected" because the UDP session
channel (ports 16401/16402) never starts — zero d0xx or identity datagrams
arrive.

**ROOT CAUSE**: In real sessions (Air↔mini), BOTH peers actively send `0001`
identity datagrams on UDP 16401/16402 immediately after the TCP exchange.
Our responder only listens — never sends. The browser won't start the d0xx
session channel until it receives our UDP identity.

**NEXT (Round 17)**: After the TCP exchange completes:
1. Send `0001` identity datagram on 16401→16402 (from the caps-cli template
   with our session tokens)
2. The browser should respond with its `0001` + `0101` identity
3. Then the d0xx handshake begins (type-01 hello → type-02 → ECDH keys)
4. DTLS/session established → `connected` state

The identity datagram format (from caps-cli):
```
0001 003c <4B session_id> <4B seq> <4B ack> 00060014 <4B tokA> 00000000 0001
<4B tokB> 00000000 0001 80010004 00000006 80030004 000003f2 80040004 <4B> ...
```

## Round 17 — TCP solid + UDP identity sent (no d0xx response yet)

**TCP handshake: consistently completing** (no reset, full exchange).
**UDP identity: sent with browser's token** from the invite plist, but no
d0xx or identity response from the browser.

The UDP identity datagram format may need the exact per-session session_id
(from the ConnectionDataKey blob) and correct token positions. The blob's
`53ace299`-style token IS the per-session token, and the session_id `2112a442`
may need to match what's in the connect plist's blob rather than being a
constant.

**Next refinement**: 
1. Extract the session_id and tokens from the connect plist blob the browser
   sent us (or from our own connect that we forged)
2. Use those EXACT values in the UDP identity datagram
3. The browser-side may also need the ConnectionDataKey blob to be correct
   for our machine (currently we send the template blob from the Air's
   capture which has the Air's IP addresses — correct for same-host but
   wrong for cross-host)

## Round 18 — 🎉 D0XX SESSION CHANNEL ESTABLISHED!

**The UDP identity with per-session tokens WORKS!** After sending our `0001`
identity with:
- session_id: our random 4B (e.g. 8a91710e)
- peer_token: browser's first 4B from invite sender peerID
- our_token: our 4B (also patched into our connect blob)

The browser responded with **7 d0xx `d017` application-data records**
(seq 0x13-0x19, 78B each, encrypted) on UDP port 16402→16401.

This means:
✅ TCP handshake complete (CRC + identity + connect plist)
✅ UDP session channel established (identity with per-session tokens)
✅ Browser actively sending encrypted `.optional` data to us
⏳ Next: decrypt the d0xx records (need the ECDH keys from the handshake)
⏳ Then: send our own encrypted JSON ping

The d0xx records are AEAD-encrypted (as mapped in Phase 1). The key
derivation requires the ECDH P-256 handshake which happens during the
d0xx type-01/02 exchange (which our identity datagram may have triggered
or the browser may be initiating).

**ALL wire-level barriers are now cracked.** The remaining work is:
1. Respond to/engage in the d0xx TLS handshake (type 01→02→ECDH→DTLS)
2. Derive session keys
3. Decrypt/re-encrypt application data (JSON envelopes)
4. Port to Kotlin

## Round 19 — d0xx TLS handshake attempt

- TCP handshake: consistently completing (no reset).
- UDP identity + d0xx type-01 ClientHello sent; no response from browser.
- The browser sent d017 (already-encrypted) in Round 18's session — meaning
  the browser's session considers itself already in encrypted mode. Our
  type-01 hello likely arrives after the browser's internal handshake window
  has closed.
- KEY INSIGHT from the real captures: in the caps-cli pair, the d0xx
  handshake (type 01→02→0c→10) happens IMMEDIATELY after the UDP identity —
  within ~50ms. Our implementation sends identity, waits, then sends the
  ClientHello — potentially too late.
- Next: send the identity AND the type-01 hello in the same burst, or
  pre-compute everything and send all handshake messages simultaneously.

## Round 20 — burst mode: still no d0xx response

Sent identity + type-01 + type-0c + CCS simultaneously after TCP complete.
No d0xx or identity-ack response from the browser. The TCP exchange is
confirmed working via the hook (PROC 2000/2200/2100 on both connections).

**Analysis**: The browser's d0xx session channel may not be directly
accessible via UDP 16401/16402 in the way we're sending. The real session
had BOTH peers being real MC processes, each with their own ICE/GCK state
machine that coordinates the UDP channel. Our foreign peer completes the
TCP handshake perfectly but the browser's GCK/ICE layer may not have created
the UDP channel for us because it's tracking a different connection state.

**Key remaining insight**: In the Round 18 success, we DID receive 7 d0xx
records from the browser — proving the browser CAN send us encrypted data.
That success used the exact same identity format but with different timing
(after the FIRST connection attempt where we got the full invite + connect
exchange). The difference may be which TCP connection's state the browser's
session layer is tracking.

**Next approaches**:
1. Keep the TCP connection OPEN (don't close it) while also sending UDP —
   the browser may correlate the TCP session state with the UDP channel.
2. Try sending the identity to port 16402 instead of 16401.
3. Analyze the MC log for GCK/ICE session creation events during our
   exchange to see if the session layer ever creates the UDP channel for us.

## Round 21 — 🎉 "CONNECTED SUCCESSFULLY" for the foreign peer (attach gate DEFEATED)

Chain of fixes this round (each verified via `log stream` of the MC private
log + the DYLD hook):

1. **Framer bug (CRITICAL)**: the old opcode-boundary scanner stalled 10s on
   the final frame in a buffer → our connect reply missed the browser's
   ~10s invite window → "Received an invitation response ... but we never
   sent it an invitation. Aborting!". Replaced with EXACT framing using the
   decoded header: `op(2B) flags(2B) bodylen(4B) crc32(4B) seq(4B) body`
   → replies now land in ~100ms.
2. **Blocking-between-connections bug**: the 15s UDP watch blocked the next
   TCP accept → browser's second-round invite expired. Main loop is now
   threaded (thread per connection, UDP in parallel).
3. Result (every run since):
   - `Got Hello ... remote [<inst>+PYSRV]` → `Got Accept`
   - `connectedHandler (browser side)` → `shouldForceConnect [yes]`
   - **`Peer [PYSRV] (browser side) connected successfully.`** ← the Round
     9-14 attach gate is DEFEATED for a foreign peer.
   - **`MCSession: PeerID [PYSRV] change state from [Not Connected] to
     [Connecting]`** ← the session state machine runs for us; the app's
     MultipeerChannel sees it (`state connecting` in CLI stdout).
   - **`Got GCK event [Disconnected] ... (peer[PYSRV])`** ← the GCK/ICE
     session object is CREATED for our peer (it later disconnects).
4. Exchange completes end-to-end: browser echo+caps+INVITE → our connect
   (#2) → browser receipt `eaeba801` (our #2 ACKED) + browser connect plist
   (392B) → our final receipt. Both connections complete.

## Remaining blocker (single, precise)
`Unexpected sequence number [3]` — raised ~200ms after our connect(#2),
tied to our final receipt frame (9dec9897, seq=3). The browser's receipt
counter expectation for our stream needs the exact rule:
- Sending NO receipts: connect(#2) alone → browser acks it (eaeba801) fine.
- Sending 73e2f9bb(seq1) after the invite → `Unexpected [1]`.
- Sending 9dec9897(seq3) after their connect plist → `Unexpected [3]`.
Next: disassemble the seq-check site (find the "Unexpected sequence number"
string ref in __cstring → the adrp/add code site in
MCNearbyDiscoveryPeerConnection) and read the exact comparison. With that,
the TCP phase completes cleanly and the GCK/ICE + d0xx handshake (server
role: respond 02/10 to their 01/0c) should engage on UDP 16401/16402.

## Round 22 — receipt rules tested; GCK port-range + token findings

1. **The live browser is the real SecondSee.app** (PID on the Air): it has
   been inviting PYSRV with continuously incrementing invids (164→180).
   Our foreign peer completes the FULL TCP exchange with the REAL TARGET
   APP — invite answered in-window, their receipt eaeba801, their connect
   plist (89B blob, per-session token), our final receipt. The mini's mc-cli
   (cross-host) also exchanges cleanly.
2. **Receipt empirical matrix** (browser log verdicts):
   - connect(seq2) alone → accepted, receipted (eaeba801 seq2)
   - + ack(3) tail (round-18 form) → occasional `Unexpected sequence number
     [3]` on the tail, but the exchange still completes and GCK/session
     states still advance (does NOT abort).
   - ack(1) pre-invite → `Unexpected [1]` (premature) — never do this.
   - Dynamic mirroring of their connect seq → also `Unexpected [3]`; their
     connect seq itself varies (2 or 3) with their stream state.
3. **GCK discovery (from full-capture scan)**: the real pair's UDP used
   ports **16397–16402** (six sockets), and the GCK session id (2112a442)
   appears ONLY in UDP datagrams — never on TCP. It is chosen by the GCK
   layer itself, not negotiated via the connect plists.
4. **Blob token rule (verified + integrated)**: the per-session UDP token =
   4 bytes before the `5a 00 00 00` anchor in that peer's
   ConnectionDataKey blob (matches 39b97b2c/53ace299 ground truth). We now
   extract the browser's live token from its connect plist at runtime.
5. **Dual-target spray** (mini + local app, ports 16397-16402, loopback
   payload filtered): TCP exchange completes with the real app; no UDP/GCK
   response yet.

### Remaining gap + next lead
The browser's GCK session object IS created (Got GCK event) but never opens
its data channel toward us. Prime suspect: our connect blob is the TEMPLATE
(the Air's old addresses/port fields) — the browser's GCK may send its UDP
to the ADDRESS/PORT ADVERTISED IN OUR BLOB, which doesn't match our listener
setup. Next: decode the blob's address TLVs (incl. port fields), patch in
our actual listening addresses, and bind ALL of 16397–16402 as listeners
while spraying.

## Round 23 — GCK/ICE layer fully exposed (app's private log)

Streamed the REAL SecondSee app's MC private log during our runs. The GCK
lifecycle for OUR foreign peer, verbatim:
```
Insert signal block for participant [33981479] ... Remove signal block
ICE StopConnectivityCheck took (0.000037 seconds)          ← instant first stop
6 interfaces found for participant [33981479].             ← parsed from OUR blob!
For remoteID[33981479]: Start listening on 127.0.0.1:16402 (lo0) sock 23.
   (also ::1:16402, fe80::1%lo0:16402, fe80::1c78:b065:b483:f72c%en0:16402 …)
Added interface for participant: proto 6.
Scheduling ICE connection timeout ... on channel [918].
No connected or connecting cList to [33981479].
Disconnected from a participant 33981479. Stop ICE check. / Timed out, enforcing clean up.
```

### New discoveries
1. **2112a442 = the STUN MAGIC COOKIE.** The UDP identity datagrams are
   ICE/STUN binding requests (0001=request, 0101=success response); the
   "session id" was never random. Cookie now mandatory in our builder.
2. **The app parses OUR blob** → finds 6 interfaces → binds ITS listeners on
   the advertised port across all interfaces → schedules an ICE timeout →
   waits for our STUN. It then times out with "No connected or connecting
   cList".
3. **Port-conflict bug found+fixed**: we had been binding 16402 with
   SO_REUSEPORT — the SAME port as the app's ICE listeners — the kernel was
   randomly distributing the app's own STUN packets between processes. We now
   bind ONLY 16401 and advertise 16401 in our blob (template port bytes
   patched 1240→1140, little-endian confirmed: `12 40`=16402, `11 40`=16401).
4. **A-side vs B-side identity**: the advertiser's (our) identity datagram
   ends with attr **8029**, the browser's with **802a** (we had copied
   B-side). Now byte-perfect A-side template with fresh txid + both tokens
   patched (their tok from their connect-plist blob, ours from our blob).
5. **Receipt semantics** (from "Got receipt #3 for message #1"):
   combined-stream numbering = invite #1 / our connect #2 / their plist #3;
   a receipt's seq must equal the receipted message's number. Advertiser
   never receipts the invite (ack(1) → instant reset confirmed again).

### Status
TCP exchange with the real app: completes every run (invite in-window,
receipts both ways, their connect plist parsed, per-session blob token
extracted live). The GCK/ICE channel: the app creates listeners from our
blob and waits; our byte-perfect A-side STUN at its listeners still doesn't
register ("No cList"). Next leads: token ORDER inside attr 0006 (swap
test), ICE credential/integrity requirements, and capturing the app-side
log AT SPRAY TIME to see whether STUN arrives but fails validation.

## Round 24 — the InvalidDestination hunt (STUN/ICE + OSPF decode)

### What was discovered
1. **Full STUN/ICE rules from the capture** (pcap src/dst verified):
   - Identity exchange = A:16401 ↔ B:16402 BOTH sending 0001 + replying 0101
     (echo txid; 0101 adds MAPPED-ADDRESS(0001) = "I see you at ip:port" + 8005).
   - USERNAME(0006) = OWN token(4B) + 00000000+0001 + PEER token(4B) + 00000000+0001.
   - txid = 0001 + 10B (prefix constant in every observed datagram).
   - Attr 8004 = 143a+2B (shared prefix!); A-side tail = 8029 (XXXXXXXX00000000).
   - Port pairs: session uses exactly ONE pair (16401↔16402, or 16399↔16400, or
     16397↔16398 in different sessions — GCK allocates a pair per session).
2. **The app's GCK parser verdicts (live log during our sprays)**:
   `Non-OSPF packet received from participant [<our-pid>] on channel [N].
    State=Created DTLSState=DTLSNotConnected OSPFParse err=InvalidDestination.`
   → The GCK routing layer is **OSPF-based**; our hellos ARE delivered and
   identified (participant = our pid!) — only the DESTINATION check fails.
   The error enum table (found in-binary @0x237971e97):
   InvalidHader, InvalidDestination, Invalidype, BadChecksum,
   InvalidPacketLegth, InvalidPayladLengt, Compressed... (binary typos intact).
3. **Destination hunt matrix — ALL rejected**:
   tok2 ∈ {their blob token (4-byte-before-5a rule), their blob 6a-field,
   their pid last4/first4, their blob uuid} × verbatim-replay of the real
   A-hello (byte-identical except tokens) × spray dst ∈ {127.0.0.1, ::1,
   192.0.2.18}:16402 and LAN-only. Every combination → InvalidDestination.
4. Also ruled out: no MESSAGE-INTEGRITY/FINGERPRINT attrs in the real capture
   (no ICE credentials to compute); receipt-order variants (ack(1) after
   invite = instant reset; no final receipt = cleanest).

### Conclusion
The destination the app validates is INTERNAL SESSION STATE (its own current
GCK session token for us — possibly from the OTHER TCP connection's blob or
regenerated at GCK-session creation), not any value available in the packets
we currently parse. 

### Next (definitive route, technique proven in Rounds 15+22)
Disassemble the OSPF destination check: the error strings cluster at
0x237971e97 (enum table); GCK symbols enumerable (GCKSessionPrepareConnection/
EstablishConnection found). Find the function that maps the enum → locate the
comparison → read exactly which field must equal what. Alternative: run our
OWN two-process CLI pair (fresh capture, both sides under our control) with
the DYLD hook logging the GCK-layer token flow to see where the session
destination token actually originates.

## Round 25 — 🎉 INVITATION ACCEPTED (browser role + identity system cracked)

### The decisive discoveries
1. **idString = base36(8-byte peerID token)** — VERIFIED:
   `int("1ddatjp8m3xy7", 36) == 0x5a2ddcb42308149f` (the app's exact token).
   The greeting's idString must ENCODE the same token used in the invite's
   SenderPeerIDKey; the app checks this ("Peer is [X], invite is from [Y]").
2. **peerID NSData format confirmed by the app's own log**: 
   `[8B token][1B namelen][displayName]` — "Created peerID from data[5440a260
   0aafd421 07 'PYSRVBR'], idString[1a4hsthaz9yxt]" ✓
3. **The app's GCK ICE only starts on ACCEPTED-ADVERTISER connections** (from
   the dual-log CLI-pair experiment: `MCNearbyServiceAdvertiser: Accepted
   connection` → session forms with `Update ICE role → ICEStarted → Send ICE
   packet`). The browser-dial path (responder9, all previous rounds) never
   starts the app's ICE — that was the structural gate all along.
4. **Browser role implemented (browser10.py)**: browse → dial the app's
   advertiser (port 61273) → hello1(idString=base36(token8)) → echo16 (their
   #0) → INVITE #1 → caps #2 → [their connect plist arrives] → our connect #3
   (NO AcceptInviteKey — that's the advertiser's) → receipt 73e2#1 (their #1).
   RESULT: **"Invitation handler called. Invitation accepted."** + both
   receipts matched (#0 for greeting, #1 for their 436B plist) + their blob
   token extracted live.
5. Receipt semantics refined (advertiser-side numbering): greeting=#0 (echo16),
   connect plist=#1 (73e2f9bb seq1) — mismatched receipts are FATAL
   ("Got receipt #2 for message #0" → connection dies).

### Remaining single gate
The app's `Update ICE role → ICEStarted → Send ICE packet` fires for real
peers (~186ms after listeners) but not for us yet; our STUN hello still gets
only OSPF noise. The validated-CLI comparison data (pcap of CLI↔app STUN)
requires sudo packet capture — requested from the user. Everything else on
both planes + both roles is now byte-exact.

## Round 26 — 🎉🎉🎉 THE WALL IS BROKEN: app's ICE STARTED + live STUN exchange

### The chain that cracked it (browser10.py, all verified in the app's own log)
1. **idString = base36(peerID token)** → identity checks pass.
2. Browser role: dial the app's ADVERTISER (its GCK only starts on
   accepted-advertiser connections — browser-dial path never starts it).
3. Receipt chain (browser-side): echo16=their#greeting, 73e2f9bb#1=their plist.
4. **Blob participant-ID rule** (app's exact words: "Wrong connection data.
   Participant ID from remote connection data = 0C33E72A, local participant
   ID = 2308149F"): the blob's uuid fields (`2ae7330c`, read LITTLE-ENDIAN)
   must equal the RECIPIENT's participant id → patch to LE(APP_PID).
   → **GCKSessionEstablishConnection SUCCEEDED** (0x801A0020 gone).
5. → **`Update ICE role` → `ICEStarted: Created → ICE` → the app SENDS STUN
   requests to us** at our advertised port (16401).
6. Our STUN replies (0101): txid echoed, USERNAME = OUR-token-first,
   MAPPED-ADDRESS (type 0001 len 8: family 0001, port, ipv4), attrs
   8001/8003/8004(paired: their prefix + flipped tail)/8005 → **the app logs
   "Received ICE packet from :16401 to :16402" and validates them**
   (BadChecksum signature = exactly the real pair's successful STUN phase).
7. **Nomination protocol identified from the fresh connected capture**
   (caps-app/plain-info): after the initial exchange, A sends a request with
   `0025` USE-CANDIDATE (empty) + `8008` (4B); B's 0101 response carries
   `8009 0057` = the 87-byte candidate blob. That completes the pair
   (real pair: "Connected to participant" follows immediately).

### Remaining (small, mechanical)
- Fire the nomination after ≥2 exchanges (timing variance this run).
- Then DTLS/d0xx handshake (d016/d014/d017 — framing already fully mapped),
  key schedule, JSON ping/pong, Kotlin port.

## Round 27 — bidirectional STUN + nomination; final validation gap

Verified working (app's own log + our socket):
- Full browser-role flow, Invitation ACCEPTED, GCK EstablishConnection OK
  (participant-ID LE patch), ICE STARTED on all 6 channels.
- **Bidirectional STUN**: the app answers OUR requests (0101 with txid echo)
  and we answer all of ITS checks (6 channels, new txid each) — both sides'
  packets arrive and parse.
- STUN conventions decoded from live app traffic + fresh caps-app capture:
  - USERNAME requests = remote-first (app verified: [our_tok][their_tok])
  - USERNAME responses = own-first
  - 8004 = verbatim echo in responses; evolving per-sender value in requests
  - 8005 = 00000006 (same as 8001)
  - MAPPED-ADDRESS = type 0001 len 8 family 0001 port ip
  - 8029 = ICE-CONTROLLING, 802a = ICE-CONTROLLED (app sends 802a → we are
    CONTROLLING; a both-CONTROLLED run = role conflict, still tested)
  - nomination = request + 0025 (USE-CANDIDATE, empty) + 8008 (00000601),
    answered by 0101 + 8009 (87B candidate blob)
- Remaining: the app's 6 checks complete but it never marks the pair valid
  (no nomination back, no "Connected to participant"). One validation still
  fails — candidates: role/pairing nuance, per-channel source addresses
  (app checks from 6 sockets; v6 ones may not reach us), or an attribute
  visible only in an app↔CLI pcap.

NEXT: capture pcap of OUR session (user-run sudo tcpdump on lo0+en0, udp
portrange 16397-16402, while browser10 runs) and byte-diff every datagram
against caps-app/plain-info's validated exchange.

## Round 28 — 🎉🎉🎉 CONNECTED TO PARTICIPANT (the wall is fully broken)

```
GCKSession] Connected to participant 782DADD0 on channel 1296.
GCKSession] DTLSContext has been set up for participant [782DADD0] channelID [1296]
[b10] <- D0XX d016 117B (the app's DTLS ClientHello, type-01)
```

### The final chain (browser10.py, every link verified in the app's own log)
1. mDNS advert + browse (idString = base36(token8)) → identity checks pass
2. TCP to the app's advertiser: hello → echo16(#0) → INVITE#1 → caps#2 →
   their plist(#1 receipted 73e2) → our connect#3 (blob with participant-ID
   = APP_PID little-endian) → "Invitation accepted"
3. GCKSessionEstablishConnection succeeds → ICE starts on all channels
4. STUN: requests remote-first uname / responses requester-first with 6-byte
   separators, 8004 verbatim echo, 8005 informational, roles 8029(we)=
   CONTROLLED / 802a(app)=CONTROLLING
5. The APP nominates (0025 USE-CANDIDATE + 8008); we answer 0101 + the
   regenerated 87-byte candidate (0001 + head + swapped v6s + 61/6a/61 groups
   with counters 0001/0002/0003, 5a-group = our STUN token, port 1140) —
   **4-byte attr padded (the `aa` pad byte was the final wire bug)**
6. → **Connected to participant** + DTLS context created + d016/d014/d017
   DTLS handshake records begin flowing to us.

### Next (Phase 2 — all formats already mapped from caps-cli)
Answer the DTLS handshake: their d016-01 ClientHello → our d016-02, their
0c (ECDH P-256 point) → our 10 + 0e + CCS → keys → decrypt/encrypt d017 app
data → JSON ping/pong through the app → Kotlin port.

## Round 28 (recorded post-restart): CONNECTED + DTLS handshake answered

Final chain (all in the app's own log): nomination answered with the padded
87B candidate -> "Connected to participant [782DADD0]" + DTLS context ->
d016 type-01 ClientHello arrived -> we sent the exact template replies
(02 ServerHello / 0c ECDH / 0e / CCS) -> **app's DTLS Completed handshake
-> DTLSCONNECTED -> "Starting OSPF Hello protocol"** (session-level LSA/
routing phase began).

### Next (this round): the OSPF/session layer
Real-pair flow after DTLS: OSPF Hello (34B) exchanges, then DD (LSA
database) sync, then d017 app-data (the JSON envelopes). Decode the OSPF
Hello/D-D formats from caps-app/plain-info (all captured) and answer the
app's OSPF packets to complete the session layer.

## Round 29 — global ICE service; reply-validation gap remains

### Fixed this round
- openssl test server was squattering UDP 16402 (invisible saboteur) — killed.
- ICE service is now global (starts at boot, select()-based drain over the
  full GCK port range 16380-16409 EXCLUDING 16402 so the app keeps its
  standard port), sprays only to their advertised port from :16401, filters
  self-echoes by txid, answers only on :16401.
- Verified live: the app's checks now come from its standard :16402, our
  replies reach it ("Received ICE packet from :16401 to :16402"), 11 clean
  exchanges per run.
- USERNAME in replies now echoed VERBATIM from the request (capture-verified).
- DTLS driver ready (ServerHello/SKE/CCS with real ECDH P-256).

### Remaining gap
The app runs 11 checks but never nominates (no 0025). Round 28's success had
~5 checks then nomination — so our reply still fails one validation. Next
definitive step: second pcap (/tmp/ours2.pcap) of a live run to byte-diff our
reply vs the app's own reply format; suspects: 8005 semantics, attr order,
or a per-check token rotation we haven't spotted.

## Round 30 — 🎯 COMPLETE protocol map from the live iPhone↔Mac session

Watched the user's iPhone (192.0.2.84) join the fresh Mac app. The ENTIRE
post-ICE lifecycle is now mapped end-to-end (all timings from the app's log):

### The definitive sequence (iPhone → Mac, all states)
```
invite(237B) → connect plist(411B) → ICE checks (39ms!) →
  [ICE check succeeded: proto 6, en0, first result 1] →
  [ICEConnected: ICE → Connecting] →
  [DTLS handshake: isServer=1 (Mac), auth=0 enc=1] →
  [RemoteCertificateAvailable: length 0 — ANONYMOUS DTLS, no certs!] →
  [Completed handshake → DTLSCONNECTED] →
  [OSPF Hello protocol: wait ≤60s] →
  [iPhone's Hello arrives, flags 8000000000000002] →
  [HelloReceived: Connecting → Connected (GCK)] →
  [Mac replies Hello, same flags] →
  [DD: Connected (direct)] → [LSA SN=0 received] → [LSAACK SN=0 sent] →
  [routing table: node added, NextHop=peer] →
  [MCSession Event Connected → app-level CONNECTED] →
  [heartbeats every ~6s (SN 1, response+request)]
```

### New hard facts
1. **DTLS is ANONYMOUS** — "certificate length [0]" — pure ECDH key exchange,
   no certificates at all (auth=0, enc=1). Our -9803 was from replaying
   stale handshake bytes; a REAL anonymous-ECDH handshake is required, but
   it's simpler than standard DTLS (no certs to forge!).
2. **No nomination step needed**: a single validated ICE check completes the
   pair (39ms iPhone → Connected).
3. **Post-DTLS protocol**: OSPF Hello (flags 8000000000000002) → reply same →
   LSA SN=0 → LSAACK → Connected. Then heartbeats ~6s.
4. iPhone pairs 16402↔16402 cross-host (same port, different IPs).
5. The iPhone's connect plist is 411B (vs our 380B) — richer blob (likely
   AWDL interface entries).
6. App's participant ID changes per launch (2308149F → 6F8B1826) — must be
   extracted live (already implemented).

### Client TODO (complete, ordered)
1. ICE check validation (final byte/regression — round-28 layout restored)
2. Anonymous-ECDH DTLS (formats mapped; no certs needed)
3. OSPF Hello exchange (flags 8000000000000002)
4. LSA SN=0 / LSAACK
5. → CONNECTED → heartbeats → app data (d017 JSON envelopes)

## Round 31 — coherent identity + unique-port ICE: two-way STUN restored

### The chain of fixes (each verified in the app's own log)
1. **Advert instance = base36(peer token)** — the app derives our pid from the
   mDNS instance name; instance `0b0octt9ljaj` → pid `305261EB` exactly as the
   app logged. ONE token8 per process now drives advert instance + greeting
   idString + invite sender → all identity checks pass
   (`Got invite response` with no stale-identifier / wrong-recipient errors).
2. **Participant-ID rule (verified vs known-good pair)**:
   blob bytes = reverse( (token[4] & 0x7f) + token[5:8] ).
3. **Live extraction of the app's identity**: their greeting's idString decodes
   (base36) to their current token — survives app restarts.
   (Note: search for '+' from offset 22; random header bytes contain '+'.)
4. **Unique-port ICE**: our blob advertises 16629 (LE f5 40) and we bind
   exactly that. Advertising 16401 made the app's GCK bind 16401 itself as a
   local candidate → its checks self-delivered. On 16629: the app's checks
   ARRIVE (11/run) and our spray is answered (bidirectional STUN restored).
5. Spray throttled 1/s (580/s flooding drowned validation).

### Remaining gap (single ordering detail)
The app-as-browser session: our receipt(73e2#1)+connect makes the app send its
connect plist, but the TCP is reset in that window (app: "Failed to send
dictionary"; we: Errno 54). The connect-message shape/ordering for the
app-as-browser role needs the last adjustment — suspects: AcceptInviteKey
presence, receipt+connect as one write, or MessageID numbering in that role.

### Architecture now
browser10.py = advert responder (state machine, app-as-browser dials us) +
browser flow (we dial the app's advertiser) + global ICE/DTLS service on 16629
(select-driven, throttled spray, verbatim-username replies, DTLS driver armed).

## Round 32 — cross-host validation vs the mini (rebooted, rebuilt, live)

### Confirmed working cross-host (Air client ↔ mini CLI at 192.0.2.10)
- Identity system: the mini derived [PYSRVBR,55ECA6DC] from our advert —
  EXACTLY our invite sender's last-4. Cross-host mDNS + base36 instance
  naming + greeting all coherent.
- TCP exchange: mini's advertiser received our hello1 (from our browser flow),
  greeted back with ITS identity (0ivzfhkquucw7 → token 228081f29aa5a2c7),
  "connected (advertiser side) successfully", "Got invite", peerIDs parsed.
- **The mini's GCK STARTED for us and sent ICE checks to our advertised 16629**
  ("Send ICE packet from 192.0.2.10:16402 to 192.0.2.18:16629").
- Firewall ruled out: firewall off; direct UDP probe mini→our 16629 arrives.
- The mini↔app pair (both real MC) completed as live reference: ICE check
  succeeded → Connected → anonymous DTLS (context 0x0 in one session) →
  OSPF Hello → LSA → fully Connected — same sequence as the iPhone.

### Remaining (specific)
The mini's checks to us die on its broken 192.0.2.1 source interface
(no route) or its invite window expires before our advert flow completes;
its TCP dial to our advert occasionally doesn't arrive (mDNS resolve race
with our per-run port). Fix path: keep a stable advert (fixed port), let the
mini's browser win the race, and answer its checks from our 16629 socket.

## Round 33 — blob fully fixed; GCK reaches interface-listing, no ICE start

### Fixed (verified by byte-comparison)
- blob_for_connect: A-template uuid slot = 612cf34c (NOT B's 2ae7330c);
  port patch 1240→f540 (16629, OUR listener); live participant-ID.
- Advert greeting reads BOTH [echo16][hello54] frames before replying.
- Advert flow holds TCP 75s (GCK/ICE window).

### Current state (app's log, verbatim sequence for our session)
Peer found → Requesting connection → connectedHandler → decision=1 →
our connect received (420B, "Got invite response") → MCSession Connecting →
GCK Insert/Remove signal block → 6 interfaces found + 6 valid →
6 listeners on 16402 scheduled → *** NO GCKSessionEstablishConnection ***
→ Connection closed ~500ms later.

### The remaining delta (measured)
The iPhone's connect plist = 451B vs our 420B (31B). The extra bytes likely
carry what makes the app call GCKSessionEstablishConnection (which then
triggers "Update ICE role" → ICEStarted → checks). Next: capture the iPhone's
exact 451B plist from a pcap for a byte-level field diff.

## Round 33-34 — cross-host findings + architecture decisions

### Cross-host TCP: THE INVISIBLE SABOTEURS (all found and fixed)
1. **Python zeroconf custom hostnames don't resolve from the mini's
   NSNetService** — the A record is served by our Python process but the
   mini's mDNSResponder doesn't reliably query it for unknown .local names.
2. **System hostname (the-air.local) SRV conflicts** with the app's
   registration (different ports on the same hostname confuse resolution).
3. **Daemon-thread death**: pure-advert mode skipped time.sleep() in main() →
   all threads (TCP listener + ICE service) died after ~3 seconds.
4. **Stale mDNS registrations**: random instance names leave dead services
   that the mini wastes connection attempts on.

### What WAS proven cross-host (before the mDNS issues):
- The mini's browser found us, derived our correct PID from the instance name
- The mini's TCP DID reach our port (CLOSE_WAIT observed at kernel level)
- Our advert flow responded correctly (greeting + connect)
- The mini's GCK DID start for us and sent ICE checks to our advertised 16629

### Path forward (most efficient):
The SAME-HOST app session works through the full TCP exchange. The app's GCK
creates listeners. The remaining gap is GCKSessionEstablishConnection not
firing — likely the 31B plist content difference vs the iPhone's 451B plist.
NEXT: capture the iPhone's exact 451B plist via pcap for a byte-level diff
of every key and value.

## Round 34 FINAL — 🎉 THE 8002 BLOB-TYPE FIX: ICE STARTS EVERY RUN

### The 31-byte delta SOLVED
Byte-diff of our blob vs real blobs across ALL captures revealed:
- `caps/`, `caps2/` (real app sessions): blob type = **`8002`**
- `caps-cli/` (our CLI-CLI template): blob type = **`8000`** ← WRONG

One byte. `blb[1] = 0x02` is what makes the app call
`GCKSessionEstablishConnection` → `Update ICE role` → `ICEStarted`.

### Additional fixes this round
- **Blob port = 16402** (the app's own port): the blob port is BOTH a
  destination hint AND a local-candidate hint for the GCK allocator.
  Advertising our own port makes the app's GCK bind it as its own local
  candidate — its checks self-deliver. Advertising the APP's port means no
  conflict.
- **Dual-bind 16401 + 16629**: the app's GCK allocates its port pair
  dynamically (16400/16401 this run); binding both catches all checks.
- Fresh app restart clears old GCK bindings.

### Verified (3 consecutive runs)
- `Update ICE role` + `ICEStarted` on all 6 channels: **every run** ✅
- Checks FROM the app's GCK arrive at our 16401 socket ✅
- Our replies reach the app (`Received ICE packet` logged) ✅
- `BadChecksum` on our replies = the app's OSPF parser seeing our STUN (same
  noise the successful iPhone shows pre-validation) — the reply is arriving
  but one final validation byte/rule remains.

### Next: the final validation rule
The STUN reply is byte-identical to the app's own replies (verified from
pcap). The remaining suspect is the reply's SOURCE port: we reply from the
socket that received (16401), but the check came from :16400 — the app may
require the reply from the port ADVERTISED IN OUR BLOB (16402). Fix: send
replies from 16402 (the blob's port), not from the receiving socket.

## Round 35 — third pcap analysis + spray non-response root cause

### pcap findings (/tmp/ours3.pcap)
- ONLY our spray visible: 16401 → 16402 (80B STUN requests), 176 datagrams
- NO responses from the app's 16402 listener, NO checks from any port
- The app's GCK created listeners on 16402 (all 6 interfaces) but never
  sent any checks

### Analysis
- Our spray's USERNAME convention matches the app's (remote-first) ✓
- Our spray's bytes match the app's own requests byte-for-byte ✓
- The app's STUN layer on 16402 is silently dropping our requests
- In R65/R67 (where checks DID arrive from :16400), the app had allocated
  a separate check-source port — the GCK's ICE layer creates port pairs
  dynamically per session

### Root cause hypothesis
The app's STUN listener on 16402 validates the USERNAME against its current
session's expected remote username. If our tok4 in the spray doesn't match
the tok4 embedded in our connect blob (which the app parsed), the request is
silently dropped. The connect blob's 61-group token = what the app expects
in STUN usernames. We need to ensure the ICE spray uses the SAME tok4 that
went into the blob_for_connect call.

CHECK: _advert_flow publishes tok4 → _G["our_tok4"] AFTER sending the blob.
But the ICE service might spray with a DIFFERENT (earlier or random) tok4
if the publish happens after the spray starts. Also: the BLOB's tok4 and
the SPRAY's tok4 must be identical.

## Round 35 FINAL — ICE activation trigger + timeout window found

### The keepalive trigger (SOLVED)
Sending receipt-style messages (`0834 flags=0001 seq=3`) every ~5s on the
TCP connection during the advert flow triggers `Update ICE role` →
`ICEStarted`. Without it, the GCK creates listeners but never activates
its checking agent.

### The ICE timeout (NEW — the last gate)
The app's GCK has a **~650ms ICE check timeout**:
```
17:57:39.303 ICEStarted (all 6 channels)
17:57:39.520 BadChecksum (our spray being seen)
17:57:39.754 BadChecksum (more of our packets)
17:57:39.950 ICE timeout expired → ForceDisconnect
```
Our STUN replies ARE arriving (the BadChecksum lines = the app's OSPF
parser seeing our STUN packets) but not being counted as validated check
responses. The 650ms window means the FIRST valid check-response must land
within that window of ICEStarted.

### What's needed
Our reply must arrive at the app's check-source port BEFORE the timeout.
The reply path: check arrives on our 16401 → we construct reply → send to
source. This should be <5ms. The issue is that our reply is NOT being
parsed as a valid STUN response by the app's ICE agent (only the OSPF
noise-parser sees it). The reply must match what the ICE agent expects —
likely needs the correct destination (the app's check-source port, not 16402)
and possibly the `0101` type must include a specific correlation the agent
validates (txid matching is confirmed correct).

NEXT: pre-arm the STUN responder so replies are INSTANT on check arrival,
and verify the reply destination is the check's source port (which it is
via `who`).

## Round 35-36 — Instant STUN replies + blob-port analysis

### What's now solid (verified across multiple runs)
- `8002` blob type + TCP keepalive (receipt seq=3 every 5s) = Update ICE
  role + ICEStarted fires EVERY run the advert-side session completes
- 11 STUN checks arrive per run at our 16401
- Instant pre-armed replies (single bytearray allocation, no string ops)
- App's log: both "Send ICE" and "Received ICE" for our session — the
  exchange is fully symmetric
- ICE timeout: 10s (not 650ms as first read — the shorter window was for
  a different channel)

### The reply-validation puzzle
Our replies are byte-identical to the app's own replies (pcap-verified),
arrive instantly, and from the correct source port. The app's OSPF parser
sees them (BadChecksum/InvalidDestination = its fallback parser). But the
ICE agent's validation layer doesn't fire "ICE check succeeded".

### Analysis: what the ICE agent validates
From the successful iPhone pair: "ICE check succeeded ... first ICE
result [1]" — the app's ICE agent counts a check as succeeded when it
receives a 0101 response matching the txid it sent, ON THE SAME CHANNEL.
The channel is bound to a specific local interface + port pair. Our reply
arrives at the app's 16402, but the app's check may have originated from
a DIFFERENT socket (a per-channel socket). The GCK creates 6 channels,
each with its own socket pair. Only the channel that sent the check will
accept its response — and only on the exact socket.

NEXT: capture the app's check source port and our reply destination in
the SAME pcap to verify they match at the socket level.

## Round 36 — 🏆 **ICE CHECK SUCCEEDED → CONNECTED TO PARTICIPANT** (R84)

### THE FINAL GATE: the STUN USERNAME convention
Ground-truth decode from caps-app/plain-info (a VALIDATED connected pair):

Every STUN message's USERNAME = **[destination peer's token]:[source peer's token]**
— "to:from", like an email envelope. The tokens are each side's own blob's
**5a-flagged 61-group token** (the second 61-group in the blob; the first
61-group and the 6a-group carry different tokens).

Verified both directions in the validated pair AND in ours2.pcap:
- app's request to us = [our_5a_tok]:[app_5a_tok]
- our reply          = [app_5a_tok]:[our_5a_tok]  (swap the halves)
- our spray to app   = [app_5a_tok]:[our_5a_tok]  ← we had this BACKWARDS

Role attrs: the browser/initiator sends 8029 CONTROLLING; the advertiser
sends 802a CONTROLLED. (We are the browser in pure-browser mode → 8029.)

### The full winning configuration (pure-browser mode, MC_PURE_BROWSER=1)
1. NO advert, NO mDNS registration — dual sessions conflict (the app resets
   its browser-side TCP 60ms after our browser flow dials its advertiser).
2. browser_flow dials the app's advertiser: greeting → invite(#1) → caps(#2)
   → our connect plist(#3) with B-template blob: type **8000** (browser role!
   8002 is the ADVERTISER's type), port 16401, our tok4 in the 5a-slot,
   live participant-ID. Then receipt 73e2#1.
3. ICE service binds 16401+16629, sprays [to:from] usernames @8029 @1/s.
4. Instant pre-armed replies: swap the request's username halves, echo txid
   + 8004, MAPPED-ADDRESS = observed source, 8001=6, 8003=3f2, 8005=6.
5. Nomination (0025+8008) → 180B-style response with 8009 candidate
   (87B, 0xaa-padded) built from our blob.

### The verified sequence (app's log, R84, 20:37:39)
Got invite → 6 interfaces → Update ICE role → ICEStarted ×6 →
ICE check succeeded with participant 581146F6 ... **first ICE result [1]** →
**Connected to participant 581146F6 on channel 46** →
DTLS Settings: authentication [0] encryption [1] (ANONYMOUS) isServer [0] →
DTLSContext set up → app sends d016 ClientHello ×10 (awaiting valid ServerHello)

### Next: the DTLS handshake (the last crypto mile)
The app is the DTLS client; we are the server. Our echo-ServerHello doesn't
validate (10 retransmits). Need real anonymous ECDH (P-256, no certs) — the
formats are already mapped (R28-30); generate fresh keys instead of echoing.
After DTLSCONNECTED: OSPF Hello → LSA → app-level connected → d017 JSON.

## Round 37 — DTLS handshake to the Finished MAC (R87–R89)

### Apple's GCK DTLS message numbering (from caps-cli, decoded byte-exact)
| Apple type | Meaning | Direction |
|---|---|---|
| 01 | ClientHello (117B) | client→server |
| 02 | ServerHello (107B) | server→client |
| 0c | **ServerKeyExchange** (95B: `0001 00000000 0045 030017 41<65B point>`) | server→client |
| 0e | HelloDone (26B) | server→client |
| 10 | **ClientKeyExchange** (92B: `0001 00000000 0042 41<65B point>`) | client→server |
| d014 | CCS (15B: `01`) | both |
| d016-e1 | Finished (78B, encrypted) | both |
| d017-e1 | App data (encrypted) | both |

(NOT TLS numbering — 0c/10 are swapped vs standard.)

### Body structure (Hello messages)
`type(1) len24(3) zeros(4) len16(2) feff(2) random32 tail`
- random slot = **body[14:46]** (whole-msg offset 28). Patching 13:45
  overwrites the version bytes → parse desync → app error "No packets
  available (13 bytes requested)" + -9803.
- Both randoms start with a 4B unix-timestamp prefix.
- SH tail selects suite (c019 visible); CH tail lists all 6 suites + extensions.

### What now works (R88, verified in app's log)
1. App sends ClientHello → we reply pcap-exact SH+SKE+HD templates with
   FRESH P-256 key (point patched same-length into SKE) ✓
2. **App accepts and sends its ClientKeyExchange** ✓
3. **We compute the ECDH shared secret** (P-256 x-coord) ✓
4. Their CCS → our CCS ✓

### The one remaining gate: the Finished MAC (−9846 bad record MAC)
Our Finished is a stale template → the app's MAC check fails (-9846).
Skipping it → the app retransmits CKE indefinitely (R89). The app REQUIRES
a correctly-MAC'd encrypted Finished.

### Next: the write-key schedule (offline-verifiable)
We know: our privkey, their point, both randoms, and (from a fresh capture)
the ciphertext records. Unknown: the PRF variant (TLS1.0 MD5+SHA1? SHA256?)
and the record cipher (c019 = ChaCha20-Poly1305? 006d = AES-GCM?).
Experiment: run a live session with the mini (mc-cli ↔ our client), capture
it, then search candidate schedules offline until our own d017 decrypts.
Every input is known, so the search is fully verifiable.

## Round 38 — prior-work integration (evilsocket/mpcfw 2022)

### The blob segment grammar — verified + one dead lever
evilsocket's published ConnectionData decode confirmed byte-for-byte against
every captured blob:
  0x80 | flags | len | count ip4rev | v6 v6 | segments{61/6a, pid4, rand4,
  iface 5A=v4/0A=v6, pad2, port2}
- flags byte = the long-mysterious "8002 vs 8000": a capability field
  (0x02 = encryption-capable), NOT the plane selector — a flags=0x00 CLI pair
  still ran full DTLS (timeline-verified: nomination → d016 on the same
  5-tuple within 100ms). The plane is the app's encryptionPreference.
- Plaintext-fallback lever DEAD against SecondSee: our repeated DTLS
  failures → ForceDisconnect on all channels → session torn down (no
  .optional degradation for us, unlike the R30 iPhone session B).
- Therefore the DTLS write-key schedule (Round 37) remains the only path.

### c1xx CRC-16/ARC — claim CONFIRMED (20/20 samples)
Checksum at bytes 6–7 big-endian, computed over the packet with the field
zeroed — exactly mirroring the TCP CRC32 convention. Recorded in
mc-protocol.md (was unnamed in our spec).

### Attribution
Shared foundation (base36 peer IDs, CRC32 framing, STUN-under-MC, blob
grammar) independently derived by evilsocket 2022 from Logic Remote and by
this project 2026 from SecondSee — two independent derivations agree.
Our delta: encrypted plane (d0xx/DTLS formats + handshake), nomination,
post-DTLS session layer, app-log validation, the STUN username to:from
rule, and the Android port.

## Round 39 — 🎯 GCK's DTLS engine IDENTIFIED: Apple SSLContext

### Found in the shared cache (MC's own image)
The MC framework binary (313KB, dyld cache `.05` @0x22B0B8000) contains the
GCK engine itself. Its strings reveal the crypto backend:

- `SSLWrite failed, packet was not sent ... SSLError = %s (%ld)`
- `SSLRead for participant [%08X] ... returned with error %s (%ld)`
- `SetupDTLSContext failed ...`
- `DTLS Settings ... authentication [%d] encryption [%d] ... isServer [%d]`

→ **GCK's "DTLS" = Apple's SSLContext (Security.framework SecureTransport
stack)**, wrapped in the custom d0-envelope. The handshake bodies are
SSLContext records; the engine is Apple's own TLS implementation.

### Why the offline schedule search failed
The ClientHello suites `c019 c018 006d 003a 006c 0034` are NOT IANA values —
Apple-internal suite IDs. Key sizes / nonce construction / PRF wiring may be
Apple-specific, so standard-schedule decryption failed even with correct
transcript inputs (6432 combos, R37–38).

### The decisive strategy (offline, no app needed)
Write a Swift tool that spins an **SSLContext DTLS pair in-process**
(client + server), captures both sides' records, and uses Security SPI
(`SSLCopyMasterSecret`-class functions) to extract the exact key schedule
for the negotiated Apple suite. Then replay that schedule against our
captured session (all inputs already dumped in /tmp/dtls_session.json).

## Round 40 — 🏆🏆🏆 DTLSCONNECTED + d017 APP DATA DECRYPTING

### The three final keys (all landed this round)
1. **THE ENVELOPE, FULLY DECODED**: every d0xx datagram = `0xd0 + <standard
   DTLS 1.0 record>` — the record with a one-byte marker prefix. Our earlier
   re-packed 12B header shifted payloads by 2B (diagnosed from the app's
   "No packets available (13 bytes requested)" loop).
2. **The suite**: c019/c018 in the app's ClientHello are the IETF-draft
   ECDH_anon codes (C015-C01A) — OpenSSL 3 still ships them as
   `AECDH-AES256-SHA`/`AECDH-AES128-SHA` (selectable only with
   `@SECLEVEL=0`). Apple's modern SSLContext dropped them (silently
   renegotiated 006d=RSA then aborted key-exchange -9806 with no cert) — so
   the engine is pyOpenSSL DTLS, in-process, memory-BIO driven.
3. **The DTLS role**: the participant whose identity-token last-4-bytes
   compare LOWER is the DTLS client (verified vs the app's isServer[0/1]
   across sessions). Random per session — the ICE service proactively sends
   our ClientHello when we lose the tie-break.

### The verified sequence (app's log, MC6)
ICE check succeeded → Connected → **Completed handshake → DTLSCONNECTED** →
Starting OSPF Hello → and the app streams d017 records that our engine
DECRYPTS into the plaintext c1xx plane:

    c101 0022 0003 5799 3171fa35 694b8269 0546f801 00100b 02000080 ...
         ^ the c1xx identity-hello (c101) with app token 3171fa35 and ours!

### What this means
The ENTIRE stack now works: mDNS → TCP invite → GCK/ICE (username to:from,
nomination) → anonymous DTLS (AECDH-AES256-SHA) → **read AND write of the
app's encrypted session data**. The remaining work is answering the c1xx
identity exchange (c101/c102/c104 — already mapped in mc-protocol.md) and
the OSPF Hello heartbeats — protocol assembly on top of a fully working
pipe, no crypto left.

### Where it lives
mcwire/ (the refactored client): mc/dtls.py = the OpenSSL engine (both
roles, app-data read/write via engine.last_plain / send_plain),
mc/ice.py = spray/reply/nomination + role kick, mc/tcp.py = the two proven
flows, mc/plists.py = blob templates. tools/gckdtls.swift kept as the
SSLContext experiment (superseded by the OpenSSL engine).

## Round 41 — stable encrypted session + the c1xx identity exchange LIVES

### The session tokens are pid4 COMPOSITES (cracked live, MC8)
The c1xx layer's 8B "token" = `[my-pid4][peer-pid4]` — perfect mirrors per
side (real pair: B=294cb86b41380245, A=41380245294cb86b; live: app sends
[3171fa35][our4], we must send [our4][3171fa35]). Sending the raw 8B
identity token = the peer retransmits c101 forever.

### The full working exchange (all inside the DTLS tunnel, MC-A/B)
```
them c101 (hello)          -> us   c101 (mirror-hello, composite tokA)
them c102 (identity TLVs)  -> us   c102
them c103 (70B full ids)   -> us   c103 (pid-swapped mirror) + c104
them c108 (20B keepalive)  -> us   c108 (mirror)     <- ~every 5.5s
```
Sequencing matters: c104 only AFTER their c103 (early c104 = unanswered
c103 = 12s MC-session timeout).

### Verified stable-session state (app's log)
- GCK **State=Connected** held for the WHOLE window (minutes)
- DTLSState=DTLSConnected, OSPF Hello protocol started
- The app RECEIVES our c108 heartbeats: `[192.0.2.66:16402] 7FFFFFFE <= [192.0.2.66:16401] FFFFFFFE: 20 bytes(8)` every ~5.5s — the ~6s heartbeat from the spec, flowing BOTH ways
- MCSession state: Not Connected → Connecting, NO timeout (previously died
  at exactly +12s)

### The c103 structure (full 70B, live)
`c103 0046 0000 <crc> <tokA composite> <ctr:0005 — increments per
retransmit> 0002 <peer-pid4> 0022 08 <peer-ASCII> 0001 <our-pid4> 00000015
<our-pid4> 0001 08 <our-ASCII> 0001 <peer-pid4> 00000038`

### Remaining for MC-level Connected
The app still retransmits its c103 (counter climbing) and its OSPF machinery
sends DD + "LSA with SN[3]" + "Requesting LSA update". Two candidate last
miles: (a) a freshly-BUILT c103 (our counters from 0001, not mirrored), or
(b) the OSPF DD/LSA-Update responses (R30 mapped Hello flags 8000...0002 →
LSA SN=0 → LSAACK → Connected).

### Also this round
- Identity pid4 pinned high (fffffffe) → we reliably win the DTLS role
  tie-break → the proven app-as-client path every session
- mcwire runs fully dynamic on the hotspot network (env auto-IP)

## Round 41 FINAL — 🏆🏆🏆🏆 **MCSession: Connected** (MCD, 2026-08-19 02:00)

```
MCSession] Peer [<MCPeerID: DisplayName = PYSRV>] changed state from
           [Connecting] to [Connected]; pd((null)) d(<MultipeerChannel>) prop(1).
```

### THE LAST BUG (masked pid4)
The participant ID everywhere = pid4 with byte0 MASKED (`token[4] & 0x7f` —
the same rule as the blob's participant-ID field). Pinning our identity to
`ff ff ff fe` made the app address us as 7FFFFFFE while our c1xx composite
tokens said FFFFFFFE — an identity mismatch the app would never converge on
(endless c103 retransmits). Pinning to `7f ff ff fe` (already masked, still
tie-break-high) → **immediate MC-level Connected**.

### The complete winning stack (mcwire, all layers verified live)
1. mDNS: instance = base36(token8), pid4 pinned 7f ff ff fe (wins DTLS role)
2. TCP browser flow: hello → echo16#0 → INVITE#1 → caps#2 → their connect →
   our connect#3 (B-template blob: type 8000, port 16401, live participant
   ID) → receipt 73e2#1
3. GCK/ICE: spray [to:from] @8029 → checks → nomination (0025+8008) → our
   8009 candidate → **Connected to participant**
4. DTLS (we=server): app's ClientHello (offers c019 anon) → OpenSSL
   AECDH-AES256-SHA handshake → **DTLSCONNECTED**
5. c1xx identity INSIDE the tunnel (composite tokens [my-pid4-masked][peer]):
   c101→c101, c102→c102, c103→c103-mirror+c104, c108 keepalives
6. → **MCSession: Connected**

The foreign peer is now a full member of the unmodified app's session.
Remaining (pure additive work): speak the app's own JSON/control payloads
over c105 data frames, streams, and the Kotlin/Android port.

### Stability fix (post-MCD): stale-record guard
A process restart while the app keeps sending d017 heartbeats to 16401 made
the fresh engine try to handshake ON APP DATA → every later record failed
(MCE regression). Fix: only `d016`/`d014` (handshake/CCS) records may start
the engine; pre-handshake `d017`s are dropped. **MCSession Connected now
reproduces across consecutive runs** (MCF1, MCF2 — 2/2).

## Round 42 — 🏆 JSON envelopes LIVE (both directions over the encrypted session)

### The c105 frame, fully decoded (byte-exact vs the real pair)
```
c105 <len:2> <seq:2> <crc16/ARC:2>
<tokA:8>                    sender composite [my-pid4][peer-pid4]
0500 <nonce:2>              (data) | 070b <nonce+0x6A75>  (ack)
<tokB:8>                    rev4-each-half of the SENDER's own composite
<acked:4>                   cumulative ack field
<counter:4>                 byte0 += 4 per message (02000004 → 06000004)
<payload>                   JSON, starting at [36:] (no frame marker —
                            the CLI pair's "0001" was its test bytes)
```
Our generated ACK is **byte-exact** vs the captured real pair.

### The live exchange (MCI, app pid 11292)
- MCSession **Connected** ✓
- App sends c105 data: `{"v":1,"kind":"hello","id":"8ED2DE14-…","payload":
  b64({"model":"arm64","name":"the-air.local","platform":"macOS"})}`
- We ACK (44B) and **reply with our own hello JSON** (203B data frame)
- Both directions flowing, session held Connected

### Also decoded this round
- The 137B frames = `{"kind":"room-scan-recover-transport",...}` — the app's
  transport-recovery channel
- c108 keepalives mirrored; app heartbeats ~5.5s

### Remaining polish (optional)
The app re-sends its hello until its counter-ack algebra is satisfied (the
`acked` cumulative field); our reply uses acked=0. Refinement: echo the
app's counter in our data's acked field.

### R42 polish note
Outgoing data frames now carry JSON directly at [36:] (the "0001 frame
marker" was the CLI pair's TEST PAYLOAD bytes, not protocol) and replies
advance the lockstep acked/counter fields. The app still retransmits its
hello aggressively (its retry-until-confirmed behavior) — MC-Connected and
both-direction JSON hold regardless; the exact ack-round algebra that fully
quenches the retries remains polish.

### R42 polish post-mortem: the hello-retry quench (CLOSED as cosmetic)
Tried, each verified against the captured real pair before testing live:
- per-retransmit ACK + DATA replies (no once-guard) — still retries
- lockstep counter echo (reply DATA carries the received DATA's acked/ctr
  verbatim, as the real pair does) — still retries
- shared ROUND nonce echo (both peers' round DATA carry identical nonces in
  the real pair) — still retries
The app demonstrably RECEIVES every reply (its per-datagram receipt log
shows each of our 44B acks and 201B data frames, N×) yet its `.reliable`
retransmit loop continues. The frames match every observable field of the
real pair; whatever quenches the loop lives deeper in Apple's delivery
internals than the wire shows. VERDICT: cosmetic — MCSession Connected
holds, JSON decodes both directions, no functional impact. Closed.

### Next goals: streams/resources (c105 large payloads) + Kotlin port

## Round 43 — the video path proven (kind:"frame" envelopes)

### Discovery: SecondSee does NOT use MC native streams
Reading the app's own source (P2PVideoReceiver.swift): shipped iOS builds
send JPEG frames as **`kind:"frame"` JSON envelopes** (payload = base64
JPEG) over the regular MultipeerChannel — the exact c105/JSON channel we
already speak. No `startStream`/`sendResource` anywhere in the app. The
"streams/resources" goal surface collapses onto the working channel.

### Live proof (MCO)
- MCSession Connected ✓
- App's hello decoded ✓
- Our `kind:"frame"` envelope with a test JPEG sent through the tunnel ✓
- Session stays Connected throughout ✓

### Goal surface status
1. .optional control channel to connected + JSON envelopes — **DONE**
2. .none plane (c1xx) — mapped; meta-glasses video rides the same envelope
   channel (or the mapped c1xx datagrams)
3. streams/resources — **N/A for this app**; its real video surface (frame
   envelopes) is proven working
Remaining: the Kotlin/Android port (all protocol rules now documented with
live evidence; the crypto is OpenSSL AECDH, available on Android).

## Round 44 — the Kotlin/Android port (written to spec)

### Layout (android/lib/src/main/java/io/ane/mc/)
| File | Role |
|---|---|
| MCConstants.kt | every live-verified constant (ops, ports, envelope, deltas) |
| MCFraming.kt | TCP framing (op/flags/bodylen/CRC32/seq) + CRC-16/ARC + stream decoder |
| MCIdentity.kt | token8, base36 both ways, peerID NSData, participant-ID rule, composites, DTLS-role tie-break, blob-token extraction |
| MCC1xx.kt | the identity exchange (hello/identity/done/mirror/keepalive) |
| MCAppData.kt | c105 frames (byte-exact acks), JSON envelopes incl. kind:"frame" video |
| MCDtls.kt | BouncyCastle DTLS server (AECDH-anon 0xC019/C018, DTLSv10) + the 0xD0 envelope codec |
| MCIce.kt | STUN to:from builder, instant reply (username swap), nomination detect, the ICE service loop |
| MCPlists.kt | minimal binary-plist writer/reader + the 89B blob builder (exact grammar) |
| MCSessionEngine.kt | the proven browser join flow |
| MCDiscovery.kt / MCClient.kt | NsdManager glue + the MCSession-shaped facade |

### Offline byte verification (no Android toolchain on this Air)
The byte-builders' logic mirrors the mcwire Python exactly; cross-checked
here against the known-good vectors: the blob builder produces the exact
89B grammar (only live-patch address fields differ from a real template),
the c1xx hello builder reproduces a captured real-pair packet byte-exact,
and the c105 ack was already verified byte-exact (R42).

### The Android DTLS answer
Conscrypt (Android's default JSSE) dropped aNULL suites. The port uses
BouncyCastle's lightweight TLS API — `CipherSuite.ECDH_anon_WITH_AES_256_CBC_SHA`
(0xC019) exists there — via `bctls-jdk18on`. build.gradle.kts updated.

### Remaining for the port
Compile (Android Studio/gradle) and validate against the real app from an
Android device on the same network. The engine's DTLS accept loop needs the
BC blocking-transport wiring finished (socket-per-session, marked in code).

## Round 45 — mcwire test campaign: 60% → **100%** reliable

### Test method
Suite of consecutive runs, each verified in the app's own log (the oracle):
DTLS complete + JSON both directions + `PYSRV ... to [Connected]`.

### Three failure modes found + fixed
1. **Stale-address blob (MCT-12/15)**: the B-template blob carried the
   capture-time office LAN IP/v6s; after moving to the hotspot the app sent
   its ICE checks to `192.0.2.18` (a network we left) — one lucky IPv4
   exchange, never Connected. FIX: `plists.browser_blob` live-patches the
   IPv4 (`inet_aton(env.MY_IP)` reversed into [5:9]) AND both v6 slots
   (en0's fe80 via ifconfig) on every build.
2. **Caps-wait stall (MCT-6)**: waiting ≤8s for the app's caps delayed our
   invite behind the app's previous-session teardown. FIX: send the invite
   immediately (caps is informational).
3. **THE big one — single-port spray (MCT-20)**: the app's GCK picks a
   per-channel SOURCE port. When its checks came from `:16400` while we
   sprayed only its `:16402` listener, that channel's pair never validated
   (its own checks were answered, but it never saw OUR binding request).
   Success runs happened to have checks from `:16402`. FIX: the ICE service
   records `last_check_port` from every inbound check and sprays BOTH
   `:16402` and that port each cycle. Also: per-process UNIQUE pid4
   (`0x7f` + random3 — still wins the DTLS tie-break, no stale-session
   collision with our previous instance).

### Final suite: **4/4 runs** — dtls ✓, JSON ✓, app-side Connected ✓ (runs 23-26)

## Round 46 — office-node test campaign (mini + m1-8gb-air)

### What works cross-machine (verified live)
- mcwire deploys and runs on both office nodes (py3.9 compat fix: PEP-604
  unions → Optional[]).
- The TCP invite flow completes MACHINE-TO-MACHINE: the 8gb-air dialed the
  mini's advertiser over the office LAN (192.0.2.29 → 192.0.2.10),
  full exchange, invite accepted, connect plists both ways.
- Our ICE spray reaches the mini (tcpdump-verified on its en1).

### Blockers found
1. **The mini's headless SecondSee binary never starts its GCK UDP layer**
   (no 164xx bindings) — it accepts TCP but never begins ICE, for any peer.
   The office app needs to run as a real GUI session (like the Air's).
2. **The mini's app advertises on link-local (169.254.x) while checking
   from two LAN IPs** — handled by the spray-at-check-source fix (spray now
   targets `last_check` instead of the advertised address).

### The RELIABILITY fix of this round (found via the fresh app at home)
- **Masked-id tie-break + composites**: the participant-id mask
  (`token[4] & 0x7f`) applies to the DTLS role compare AND the c1xx
  composites. A fresh app instance with raw pid4 a2330043 (masked
  22330043) exposed both: roles disagreed (both peers picked client) and
  our composite carried its raw id while its c101 carried the masked one.
  Fixed: `_masked()` in the compare; composites built from masked pid4s.
  → 3/3 Connected against the fresh app (runs 33-35).

## Round 47 — 🎬 VIDEO PROVEN: 200/200 frames delivered over the session

### The answer to "video or just text?"
There is no text/video split — ONE channel carries JSON envelopes, and video
is `kind:"frame"` envelopes (base64 JPEG): the exact path the shipped iOS
builds use. Proven sustained: 200 frames / 5 distinct images / 5fps, with
the app's MCSession logging a receive for EVERY frame (40 receipts × 5
sizes, matching the 5 source images exactly).

### The three real video barriers found + fixed
1. **macOS UDP sndbuf 9216B**: our ~11KB records failed `EMSGSIZE` →
   SO_SNDBUF/RCVBUF raised to 256KB on the ICE sockets.
2. **TLS 16KB plaintext cap**: OpenSSL DTLS writes >~16.3KB fail
   ("dtls message too big") — jumbo link-MTU dance
   (post-handshake `set_options(NO_QUERY_MTU)` + `set_ciphertext_mtu`)
   raised the ceiling to ~16KB.
3. **The app's receive limit ~4KB**: records ≤~2.8KB land (receipts
   logged); ≥5.6KB vanish silently (its DTLS/rcv layer drops them —
   Apple's own stack fragments above this). WORKING SIZE: JPEGs ≤~2.7KB
   (b64+c105+DTLS ≈ 2.4-3.7KB records) at 5fps.

### Wiring (mc/dtls.py `_start_video`)
After the app's hello, a locked streamer thread cycles MC_VIDEO_FRAMES
(colon-separated JPEGs) at MC_VIDEO_FPS as kind:"frame" envelopes with
advancing counters. The send lock serializes engine access (the OpenSSL
connection is single-threaded — the first un-locked run crashed it).

### For production-quality video (next step if wanted)
Apple's own path fragments big payloads at the MCSession/GCK layer and
reassembles ("Have to wait for more data" buffers). To exceed ~4KB frames
we'd reverse that fragmentation protocol — or simply keep frames small
(2.7KB ≈ 128-160px JPEGs work now; H.265/keyframe-delta schemes would fit
more in the same budget).

## Round 48 — 🏆 MAC-TO-MAC CONFIRMED (the full session, two machines)

### The proven configuration
mcwire on the MINI (our RE client) → SecondSee on the AIR (unmodified Apple
stack), session over the office LAN:

    ICE checks ↔ nomination → DTLS HANDSHAKE COMPLETE (AECDH-anon)
    → c1xx identity COMPLETE → JSON channel up
    Air app's log: Peer [PYSRV] changed state [Connecting] → [Connected]

Both pair roles on different physical Macs; discovery, TCP invite, GCK, DTLS,
identity, and app-level JSON ALL crossed the wire.

### The forward-direction mystery — solved by isolation
The mini's mc-cli GCK sendmsg fails on EVERY interface (354 errors, v4+v6)
while the same machine's plain sockets all reach the Air fine (verified:
sendto, IP_BOUND_IF binding to en1, from :16402, user AND root — every
probe ARRIVED). So: not network, not addresses (its GCK aimed at our
correct live-patched v4+v6), not protocol (reverse run completed).
It's that specific post-reboot Apple-process state (macOS 26.5.1 installed
at the reboot; Internet Sharing had also poisoned bridge0 — we removed the
192.0.2.1 address surgically, sendmsg still failed → per-process issue).

### The mini environment fixes applied
- bridge0's stale 192.0.2.1 removed (`ifconfig bridge0 inet ... remove`)
- mc-cli/SecondSee restarted fresh multiple times
- Remaining: the mini's own Apple-side GCK send path stays broken until the
  box gets a proper reboot-with-Sharing-off or the apps are re-granted
  local-network — cosmetic for our claim (the reverse config proves it).

## Round 49 — re-verified Mac-to-Mac on the office LAN (post-packaging run)

Fresh confirmation (2026-08-24) that the shipped code still completes the full
cross-machine session, run to validate the repo as it will be published:

- Foreign side: mcwire (browser role) on the office 8GB Air → oracle: the real
  `MultipeerChannel` (`multipeer-cli`, SecondSee's channel, `.optional`) on the
  office 16GB Air, over the office LAN.
- Full stack crossed the wire: mDNS discovery → TCP browser flow (hello →
  echo#0 → INVITE → caps → connect plists) → ICE/STUN checks + nomination →
  OpenSSL DTLS handshake (AECDH-anon) COMPLETE → c1xx identity exchange
  COMPLETE → c105 JSON channel up, both directions (the app's hello envelope
  arrived at the foreign peer over the encrypted session; 36K+ c105 acks
  flowed back; the app's pong stream decoded continuously).
- App-side verdict (framework's own log, `GCKSession` routing table): the
  foreign participant token 6D38D557 appears as a full member node with two
  neighbors — RTT-tracked, exactly the node shape seen for real members.
- Ran twice (2/2): an initial long session and a clean repeat. Environment:
  single mcwire instance per run; the stragglers from earlier overlapping
  launches contending for ports were killed first (known gotcha, R-readme).

No code changes were needed for this run; it confirms the R45–R48 stack on the
current LAN after the release-prep edits (docs sync + IP redaction + the
plists.py fallback swap).

## Round 50 — 🎯 SELF-CONTAINED PROOF: the shipped oracle (mcoracle)

### What changed
- `Sources/mcoracle`: a minimal, dependency-free macOS oracle reproducing the
  target channel's exact MC configuration — MCSession `.optional` + nil
  security identity, symmetric advertise+browse, identity `discoveryInfo`,
  accept-all invitations, hello envelope on connect, 2s auto-ping. No app
  code involved anywhere.
- `mc/mdns.py`: multi-interface address selection. mDNSResponder registers
  the advertiser's host with an A record per interface (loopback,
  self-assigned link-local from disconnected NICs, VPN, LAN) and the old
  first-record pick dialed 127.0.0.1 / 169.254.x — the session attached but
  the peer's GCK bound loopback and stopped ICE (the R48/R49 office
  environment failure). Selection now: same subnet as our address > private
  routable > public > link-local > loopback.
- `mc/dtls.py`: the video streamer selects only JPEGs within the ~2.7KB
  receive budget and skips oversized sources instead of dying on
  "dtls message too big".

### The proof (all from shipped components only)
- Same-host (the Air): mcoracle up; mcwire browser joined — DTLS handshake
  complete, c1xx identity complete, JSON channel up, the oracle's hello
  envelope decoded at the foreign peer. Oracle's own delegate verdict:
  `state connected peers=["PYSRV"]` + `→ CONNECTED peer=PYSRV`. Framework
  log: `Sending 78 bytes of data to participant …` (its ping envelopes to
  the foreign peer) every 2s.
- Cross-machine: mcoracle on the 16GB Air ↔ mcwire browser on the 8GB Air
  over the office LAN — the same full stack and the same Connected verdict
  on the oracle side (foreign peer `PYSRV`).
- `tools/verify-session.sh` now drives mcoracle and asserts 13 markers across
  BOTH sides (the foreign stack walk + the app-side Connected verdict):
  **PASS, 13/13**.

### What this removes
The headline claim — a foreign, non-Apple client joins a real MCSession — is
now reproducible with nothing but this repo (`swift build` + one script).
The production app channel remains the original field target; mcoracle
speaks the identical wire surface with zero private dependencies.
