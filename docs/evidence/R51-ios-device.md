# Live evidence — iOS device (R51): foreign client joins a real iPhone MCSession

Round **R51** (2026-08-24, office LAN): the iOS half of the repo's claim,
closed on physical hardware. The oracle is the shipped `ios/mcoracle` app (a
real `MCSession` `.optional` channel) running on an **iPhone 13 mini
(iPhone14,4)**; the foreign client is mcwire running on Mac(s). Both joins
below were live sessions; the phone-side verdict was read off the oracle's
on-screen log.

## Foreign side (mcwire, verbatim, redacted)

Same-Mac join:

```
[mc] connected to advertiser 192.0.2.89:54726 (3l0el499ubi6a._secondsee-mpc._tcp.local.)
[mc] -> hello1 (2kwfp32l5t0x3+PYSRV)
[mc] <- their greeting: 3l0el499ubi6a+iPhone (token eba77f98453662c2)
[mc] -> echo16 (receipt #0 for their greeting)
[mc] -> INVITE #1 (sender=a9b1d4647fd222e7)
[mc] -> caps #2
[mc] <- receipt 73e2f9bb seq=1
[mc] <- their connect plist (blob 121B tok=3018a7b4)   # iOS blob: 121B vs the Mac oracle's 89B
[mc] -> our connect (tok ..., blob port 16402=peer)
[mc] -> receipt #1 (their plist)
[mc] tokens published to global ICE service
[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)
[c1xx] identity exchange COMPLETE
[app] JSON channel up
[app] <- JSON: {'kind': 'hello', 'id': '815F8A8E-…',
                'payload': 'eyJwbGF0Zm9ybSI6ImlPUyIsIm1vZGVsIjoiaVBob25lMTQsNCIsIm5hbWUiOiJpUGhvbmUifQ=='}
[app] <- JSON: {'kind': 'ping', 'id': '839D771E-…', 'payload': '', 'v': 1}
[app] -> c105 ack 44B (encrypted)          (every ping ACKed; our data frames flow back)
```

The hello payload decodes to `{"platform":"iOS","model":"iPhone14,4",
"name":"iPhone"}` — the iPhone's own identity envelope, delivered to the
foreign peer over the encrypted session; the 2s `kind:"ping"` stream is the
oracle's auto-ping timer.

Cross-machine join (mcwire on a second office Mac, over the LAN):

```
[mc] <- their greeting: 3l0el499ubi6a+iPhone (token eba77f98453662c2)
[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)
[app] JSON channel up
[app] <- JSON: {'v': 1, 'payload': 'eyJtb2RlbCI6ImlQaG9uZTE0LDQiLCJwbGF0Zm9ybSI6ImlPUyIsIm5hbWUiOiJpUGhvbmUifQ==',
                'kind': 'hello', 'id': '0A567DBA-…'}
```

## Oracle side (the iPhone's on-screen log, user-verified)

```
[oracle] up: service=secondsee-mpc peer=iPhone enc=optional advertise+browse
[oracle] ▶ INVITE from PYSRV — accepting
[oracle] ● state connected peers=["PYSRV"]
[oracle] → CONNECTED peer=PYSRV
[oracle] → hello sent (…B)
[oracle] → ping sent          (every 2s)
```

## Reproduce it

See [`ios/README.md`](../../ios/README.md): build/install the app on any
iPhone (iOS 14+ local-network permission required on first launch), keep it
foregrounded on the same LAN, then from a Mac:

```sh
.venv/bin/python -m mc.run --role browser --service secondsee-mpc
```

## Note for the wire record

The iPhone's connect blob is **121B** vs the Mac oracle's 89B — iOS carries
more interface addresses in its ConnectionData. The session completes
without special-casing; the size delta is a fresh ground-truth data point
for the address-segment grammar (recorded in `docs/d0xx-tls.md` R51).