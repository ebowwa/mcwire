# Live evidence — self-contained proof (R50): the shipped oracle

Round **R50** (2026-08-24): the repo's headline claim — *a foreign, non-Apple
client joins a real `MCSession`* — reproduced using **only this repository's
components**: `mcoracle` (a real `MCSession` `.optional` channel, no app code)
as the oracle and mcwire as the foreign browser.

## Run it yourself

```sh
swift build
./tools/verify-session.sh          # 13 assertions across BOTH sides
```

Latest run on the reference machine:

```
== verify-session: SVC=secondsee-mpc ==
[3/4] oracle up, running mcwire browser x1...
[4/4] checking evidence...
 foreign side (mcwire):
  ✓ mDNS discovery + TCP dial
  ✓ browser flow: hello1
  ✓ peer greeting parsed (identity system)
  ✓ invitation sent
  ✓ connect plist received
  ✓ ICE service armed
  ✓ DTLS handshake complete (AECDH-anon)
  ✓ c1xx identity exchange complete
  ✓ app-level JSON channel up
  ✓ the app's hello JSON envelope decoded
 oracle side (real MCSession):
  ✓ foreign invitation received + accepted
  ✓ MCSession state: connected
  ✓ app-side verdict: foreign peer Connected

passed=13 failed=0
RESULT: PASS — foreign client joined a real MCSession end-to-end
```

## The oracle's own log (verbatim)

```
[oracle] mcoracle up: service=secondsee-mpc peer=<host> enc=optional advertise+browse
[oracle] ▶ INVITE from PYSRV — accepting
[oracle] ● state connecting peers=[]
[oracle] ● state connected peers=["PYSRV"]
[oracle] → CONNECTED peer=PYSRV
[oracle] → hello sent (175B, identity=["model": "mcoracle", ...])
[oracle] → ping sent                        (every ~2s thereafter)
```

The framework's own log during the same session shows the oracle's app data
flowing to the foreign participant:

```
[MCSession] Sending 78 bytes of data to participant <pid>, mode=0.   (every 2s)
```

## The foreign side's log (verbatim, redacted)

```
[mc] connected to advertiser <LAN-IP>:<port> (<inst>._secondsee-mpc._tcp.local.)
[mc] -> hello1 (<inst>+PYSRV)
[mc] <- their greeting: <inst>+<host>
[mc] -> echo16 (receipt #0 for their greeting)
[mc] -> INVITE #1 (...)
[mc] -> caps #2
[mc] <- receipt 73e2f9bb seq=1
[mc] <- their connect plist (blob 89B tok=...)
[mc] -> our connect (tok ..., blob port 16402=peer)
[mc] -> receipt #1 (their plist)
[mc] tokens published to global ICE service
[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)
[c1xx] identity exchange COMPLETE
[app] JSON channel up
[app] <- JSON: {'kind': 'hello', 'v': 1, 'payload': '<b64 identity>', 'id': '<uuid>'}
```

## Cross-machine (same shipped components, two physical Macs)

mcoracle on one office Mac, mcwire browser on another, over the LAN: the same
full stack and the same oracle-side verdict (`→ CONNECTED peer=PYSRV`),
matching the earlier app-channel run recorded in
[`R49-live-session.md`](R49-live-session.md).

## Scope note

The oracle's `didReceive data` callback surfaces the channel's own messages;
the foreign peer's c105 data frames are received and receipted at the
framework's transport layer (logged per-frame) but do not yet surface as
app-level deliveries — the documented "hello-retry quench" open item
(`docs/d0xx-tls.md` R42, unchanged by R50).