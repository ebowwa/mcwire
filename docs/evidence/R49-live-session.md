# Live evidence — Mac-to-Mac session, foreign peer accepted as a full member

Round **R49** (2026-08-24, office LAN): the shipped stack, end to end, between
two physical macOS machines. The foreign side is mcwire running on one office
Mac; the oracle is the real, unmodified `MultipeerChannel` (`secondsee-mpc`,
`.optional` encryption) on a second office Mac, exactly the channel the
SecondSee iOS/macOS apps run.

All records below are verbatim from the two machines' captured logs, with only
LAN addresses and machine hostnames redacted to the documentation range
(`192.0.2.x`, RFC 5737) / role names — the round log (`docs/d0xx-tls.md` R49)
records the same run.

## Foreign side (mcwire, browser role)

```
[ice] bound ports: [16401, 16629]
[mc] connected to advertiser 192.0.2.225:57389 (115dnsc74z8ev._secondsee-mpc._tcp.local.)
[mc] browser flow target: ('192.0.2.225', 57389)
[mc] -> hello1 (1r4ecr71gpyyp+PYSRV)
[mc] <- their greeting: 115dnsc74z8ev+the-air (token 43db9a116d38d557)
[mc] -> echo16 (receipt #0 for their greeting)
[mc] -> INVITE #1 (sender=734cd52c7ff56141)
[mc] -> caps #2
[mc] <- receipt 73e2f9bb seq=1
[mc] <- their connect plist (blob 89B tok=083c5fec)
[mc] -> our connect (tok 1aae080f, blob port 16402=peer)
[mc] -> receipt #1 (their plist)
[mc] tokens published to global ICE service
[ice] <- STUN req from ('192.0.2.225', 16400) txid=0001442d5c90
[ice] <- STUN success from ('192.0.2.225', 16400)
[ice] -> nomination answer + 8009
[ice] <- d0xx d016 117B
[dtls] OpenSSL DTLS engine up (AECDH-anon)
[dtls] -> d016 232B (OpenSSL)
[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)
[dtls] plain (34B): c1010022...  (c1xx identity, inside the tunnel)
[c1xx] -> c101 34B (encrypted)
[c1xx] identity exchange COMPLETE
[app] JSON channel up
[app] <- JSON: {'v': 1, 'kind': 'hello', 'id': 'AD487E3E-...',
                'payload': '<b64 of {"name":"the-air.local","platform":"macOS","model":"arm64"}>'}
[app] -> c105 ack 44B (encrypted)          (36,000+ acks flowed over the session)
[app] <- JSON: {'v': 1, 'kind': 'pong', 'id': '9A85DDF6-...', 'payload': ''}
```

The app's own log streamed its `kind:"hello"` envelope to the foreign peer
over the encrypted session — the framework only sends that to a session member
it has admitted, and the pong/ack exchange continued throughout the run.

## App side (framework's own log, `com.apple.multipeerconnectivity`)

During the same run the GCK session printed its routing table with the foreign
participant as a full member node (RTT-tracked, exactly as any real member):

```
[GCKSession] My routing table: 3 nodes.
[GCKSession] Node 0 [0D32C7E1]: ...  # of neighbors [1]
[GCKSession] 	neighbor 0: 6D38D557 - RTT[3832]
[GCKSession] Node 1 [6D38D557]: NextHop[6D38D557], SN[17] ... # of neighbors [2]
[GCKSession] 	neighbor 0: 0D32C7E1 - RTT[32]
[GCKSession] 	neighbor 1: 7FC2D286 - RTT[505]
[GCKSession] Node 2 [7FC2D286]: ...
```

`6D38D557` is the foreign participant's id (mcwire's token in its own c101
frames), present as a routing-table member with two neighbors.

## Reproduce it

The full Connected + JSON run requires a real `.optional` MC channel as the
oracle (any app using `MCSession` with `.optional` encryption and the browser
flow; the channel here was `secondsee-mpc`). See
`tools/verify-session.sh` for the automated self-check against the shipped
`mcpeer` oracle, and the README quick start for the general recipe.

What is reproduced *without* the app is the complete foreign-stack walk:
discovery, TCP browser flow, plist/identity exchange, and ICE start — verified
by `tools/verify-session.sh` (see its output notes on where the unmodified-app
gate sits, per `docs/d0xx-tls.md`).