# mcwire — MultipeerConnectivity wire compatibility, from the outside

Reverse-engineering Apple's MultipeerConnectivity (MC) layer so a **foreign,
non-Apple client can join sessions of an unmodified macOS/iOS app** that uses
`MCSession`.

MC has no documented wire protocol. This project derives it byte-for-byte
from packet captures and live probing, and proves each layer by speaking it
back to the real framework — success is measured **in the Apple peer's own
logs**, up to and including the app-level verdict:
**MCSession: changed state from [Connecting] to [Connected]** for this
foreign peer.

> **Status snapshot (R46–R49) — 100% reliable same-host; Mac-to-Mac
> proven.** The
> whole stack works end-to-end against the unmodified app **4/4 consecutive
> runs** (anonymous DTLS ✓, JSON both directions ✓, the app's own log
> reporting `Connected` ✓), including against a FRESH app instance (the
> masked-id fix). Cross-machine: the FULL session
> completes (mcwire on the mini ↔ the app on the Air — Connected + JSON,
> R48); the mini's own Apple-side peers are OS-broken since its reboot
> (unrelated to the RE; every plain-socket path from that box verified). **Mac-to-Mac CONFIRMED (R48) and re-verified on this
> published tree (R49):** mcwire (browser) on one office Mac ↔ the real
> `MultipeerChannel` (`secondsee-mpc`, `.optional`) on another, full session
> over the LAN — Connected + JSON both directions.
> **Video proven sustained (R47): 200/200 frames
> delivered** — 5 distinct JPEGs cycling at 5fps as `kind:"frame"`
> envelopes, the app's MCSession logging a receipt for every one. Working
> frame budget: JPEGs ≤~2.7KB (bigger single records are silently dropped
> by the app's receive layer; Apple's own stack fragments above that).
> Next: the Kotlin/Android port validation.

## Proof

- **`docs/evidence/R49-live-session.md`** — verbatim record of a live
  Mac-to-Mac session (2026-08-24): mcwire (browser) on one office Mac joined a
  real `.optional` `MultipeerChannel` on another — DTLS handshake complete,
  c1xx identity complete, the app's own `kind:"hello"` JSON arrived at the
  foreign peer, 36k+ acks flowed back, and the framework's own GCKSession log
  shows the foreign participant as a full routing-table member.
- **`tools/verify-session.sh`** — one-command self-check with only this
  repo's components: builds `mcpeer`, drives the full foreign-stack walk
  (discovery → TCP browser flow → plists → ICE start), and asserts each
  marker. `RESULT: PASS` is reproduced on any macOS box.

Run the self-check:

```sh
./tools/verify-session.sh mc-probe      # uses shipped mcpeer oracle
```

## Status

| Layer | Status | Where |
|---|---|---|
| mDNS/Bonjour discovery | **Solved** — a non-Apple advertiser is found and parsed by a real `MCNearbyServiceBrowser` | `mc/mdns.py`, `docs/mc-protocol.md` |
| TCP session handshake (incl. invite-accept gate) | **Solved** — framing, CRC, identity, plist forging; a real app *accepts our invitation* and completes the exchange | `mc/tcp.py`, `docs/d0xx-tls.md` |
| GCK session layer (under MC) | **Decoded + live** — it is ICE/STUN: checks, roles, nomination; the app logged *Connected to participant* for this client | `mc/ice.py`, `docs/d0xx-tls.md` |
| UDP data plane — plaintext (`encryptionPreference = .none`) | **Fully mapped** — `c1xx` family, ports 16401/16402, app-level seq/ack reliability | `docs/mc-protocol.md` |
| UDP data plane — encrypted (`.optional`) | **Crypto solved by delegation (R39)** — GCK's DTLS engine *is* Apple's SSLContext (SecureTransport); the ClientHello suites are Apple-internal IDs, which is why every standard key-schedule guess failed (6432 offline combinations, no winner). This client pipes the handshake through **Apple's own stack** via `tools/gckdtls.swift` (stdin/stdout hex-record bridge): Apple negotiates, keys, and MACs everything, including the Finished that defeated template replays | `mc/dtls.py`, `docs/d0xx-tls.md` |
| Post-DTLS session layer | **Mostly live** — the c1xx identity exchange completes inside the tunnel; c108 heartbeats flow both ways (~5.5 s) over a stable GCK-Connected session; remaining: the app's c103-retransmit/OSPF-LSA last answer for MC-level `Connected` | `mc/c1xx.py`, `docs/d0xx-tls.md` R41 |

## Key findings

- **Two data planes, selected by `encryptionPreference`** (not one protocol):
  - `.none` sessions use the **`c1xx`** family over UDP in **plaintext** — fully mapped.
  - `.optional` sessions use the **`d0xx feff`** family wrapping a **DTLS
    handshake** (ChaCha20-Poly1305 + AES-GCM suites, ECDH P-256) — and they
    encrypt application data **even with a nil identity**. `.optional` also
    **degrades to plaintext** when DTLS fails (sessions complete with
    `DTLS context [0x0]` and carry app data unencrypted).
- **TCP message header:** `op(2B) | flags(2B) | bodylen(4B) | CRC32(4B) | seq(4B) | body`;
  the CRC is `zlib.crc32` of the whole message with bytes 8–11 zeroed —
  verified against every observed message type.
- **Identity is one 8-byte token, everywhere:** the greeting's idString is
  **base36 of the token**, the peerID NSData is `[8B token][1B namelen][name]`,
  and the mDNS instance name is the same base36 token again. The framework
  requires greeting, invite, and Bonjour record to describe the *same* peer —
  the self-referential identity rule, decoded from disassembly, that explains
  every earlier synthetic-invite rejection.
- **Receipts are zero-indexed and per-message** (echo16 = #0 for their hello,
  `73e2f9bb#1` for their invite, `eaeba801#2` for their connect plist). A
  mismatched receipt number is fatal (*Unexpected sequence number*).
- **Under MC sits Apple's private GCK layer — and it is ICE/STUN:** binding
  checks with custom attributes (`8001/8004/8005`, roles `8029/802a`),
  nomination via USE-CANDIDATE + an 87-byte candidate blob.
- **The GCK ICE port allocator is shared and dynamic** (16397–16402 per
  session). Advertising a port in that range makes the peer's GCK bind it as
  a local candidate — its own checks then self-deliver. This client uses
  16401 + 16629 (outside the allocator).
- **The `.optional` crypto plane is *anonymous* DTLS:** the app's own log
  reports certificate length 0 — pure ECDH P-256, nothing to forge.
- **After DTLS, MC runs an OSPF-like session layer:** Hello (flags
  `8000000000000002`) → LSA SN=0 → LSAACK → *Connected*, then ~6 s heartbeats.
- Discovery record: `_<type>._tcp.local.`, instance = **base36 of the peer's
  8-byte token**, host = UUID hostname, TXT `_d` = display name, ephemeral
  TCP port.

## Layout

```
mc/                the foreign client (pure Python, macOS host)
  run.py           CLI: python -m mc.run [--role browser|advert|both]
  framing.py       TCP framing (op|flags|len|CRC32|seq) + stream reassembly
  identity.py      the 8-byte-token identity system (base36, peerID, participant ID)
  plists.py        handshake plist forging + ConnectionData blob patching
  mdns.py          Bonjour advertise/browse (non-Apple discovery stack)
  tcp.py           the two proven TCP invite flows (browser / advertiser role)
  ice.py           the GCK layer: ICE/STUN checks, roles, nomination
  dtls.py          the d0xx DTLS plane, driven by Apple's own SSLContext
                   through the gckdtls bridge subprocess
  env.py           configuration (environment + mc.env; no hardcoded hosts)
  templates/       byte templates from captured real sessions (ground truth)
docs/
  mc-protocol.md   byte-level spec — TCP handshake + plaintext UDP plane
  d0xx-tls.md      encrypted plane + the full RE crack log (round by round)
tools/             capture + analysis harnesses, plus gckdtls.swift — the
                   SSLContext bridge (d0 envelope <-> DTLS record) whose
                   binary Apple's stack runs the crypto in
Sources/mcpeer/    macOS MC CLI oracle: advertise/browse/session with
                   controlled payloads (Swift, links real MultipeerConnectivity)
```

Packet captures are **not shipped**, and LAN addresses in docs/templates are
redacted to the documentation range (`192.0.2.x`, RFC 5737). Payload hex in
`mc/templates/` is verbatim ground truth (may embed a capture-LAN address in
protocol fields). Regenerate evidence for any scenario with `sudo tools/capture-run.sh`.

## Quick start

Two real MC peers as a controllable oracle (the `mcpeer` CLI), then the
foreign client against either:

```sh
# 1. build the oracle (needs macOS + MultipeerConnectivity)
swift build
.build/debug/mcpeer advertise ALICE service=_mc-probe._tcp

# 2. build the SSLContext bridge (does the DTLS crypto; macOS only)
mkdir -p bin && swiftc tools/gckdtls.swift -o bin/gckdtls -framework Security

# 3. the foreign client (needs Python 3.9+)
python3 -m venv .venv
.venv/bin/pip install zeroconf cryptography
.venv/bin/python -m mc.run --service mc-probe        # dual role
.venv/bin/python -m mc.run --role browser            # pure browser
```

Every network parameter is dynamic or overridable — service type, display
name, peer addresses, our address, mDNS host identity (see
[`mc.env.example`](mc.env.example)). **No machine-specific IP, hostname, or
token is hardcoded anywhere.**

To capture a real connecting pair as ground truth:

```sh
sudo tools/capture-run.sh <scenario>      # controlled scenarios -> pcaps + logs
sudo tools/capture-cli-pair.sh            # a REAL connecting pair
```

## How the RE loop works

1. Run two real MC processes (`mcpeer`, or any app's channel) as a
   **controllable oracle**.
2. Capture with `sudo tools/capture-run.sh` (tcpdump + side logs).
3. Reassemble and diff the flows (`tools/`), pin down framing and invariants.
4. Validate hypotheses live from Python (`python -m mc.run`) against the
   running framework — success is the framework accepting the foreign client
   (its own log saying *Invitation accepted*, *Connected to participant*, or
   *DTLSCONNECTED*).

## Open problems

- ~~The DTLS record-protection key schedule~~ — **retired by R39**: the
  suites are Apple-internal SSLContext IDs, so instead of cracking the
  schedule, the handshake is piped through Apple's own stack
  (`tools/gckdtls.swift`). What remains on that plane: validating the
  bridge end-to-end against the live app (handshake → decrypted `d017`
  app data → JSON ping/pong).
- Answer the post-DTLS OSPF Hello/LSA exchange (+ ~6 s heartbeats) to hold a
  stable app-level `connected` session.
- Advertiser-role connect plist is 420B vs the iPhone's 451B — that delta is
  what makes the app arm ICE immediately; byte-diff against a captured iPhone
  plist is the next move.

## Known environmental gotchas (learned the hard way)

- **Python zeroconf custom `.local` hostnames do not resolve from remote
  NSNetService** — the A record is served by the Python process but the
  peer's mDNSResponder doesn't reliably query it. Use the system hostname or
  register the A record with the OS.
- **Daemon threads die when main() exits** — the CLI's blocking loop is
  load-bearing; without it the TCP listener and ICE service silently die.
- **Stale mDNS registrations** from prior runs confuse the peer's browser;
  use token-derived instance names and unregister cleanly.
- **Holding the whole 16380–16409 range** starves the peer's GCK port
  allocator — it gets forced onto ephemeral ports and ICE validation never
  fires. Bind only the ports you advertise.
- **Spraying ICE checks fast drowns validation** — real pairs exchange ~2
  checks; more than ~1/second and the peer's check validation never fires.

## Reverse-engineering note

This project documents the MC **wire protocol** from packet captures and
behavioral testing. It does not redistribute Apple framework code: the
`mcpeer` oracle loads Apple's public `MultipeerConnectivity` only as a
network oracle, and this repo's code and docs are derived from observed
traffic.

## License

MIT — see [LICENSE](LICENSE).
