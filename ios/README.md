# mcoracle (iOS) — the proof oracle, device edition

A real `MCSession` channel running on iOS, so the mcwire foreign client (on a
Mac) can join a session hosted by an actual iPhone — the iOS half of the
repo's claim. Same behavior as the macOS oracle (`Sources/mcoracle`):
`.optional` encryption, nil security identity, symmetric advertise+browse,
identity `discoveryInfo`, accept-all invitations, hello envelope on connect,
2s auto-ping — with an on-screen event log so the oracle-side verdict
(`→ CONNECTED peer=PYSRV`) is visible on the device itself.

## Build & install

```sh
cd ios
xcodegen generate                      # produces mcoracle.xcodeproj
open mcoracle.xcodeproj                # set YOUR team in Signing & Capabilities
# or headless:
xcodebuild -project mcoracle.xcodeproj -scheme mcoracle \
  -destination 'generic/platform=iOS' DEVELOPMENT_TEAM=<YOUR_TEAM> build
xcrun devicectl device install app --device <UDID> \
  <DerivedData path>/Debug-iphoneos/mcoracle.app
xcrun devicectl device process launch --device <UDID> local.mcwire.mcoracle
```

Requirements:

- **iOS 14+ local-network keys** are already in the generated Info.plist
  (`NSBonjourServices`: `_secondsee-mpc._tcp`, `_mc-probe._tcp`;
  `NSLocalNetworkUsageDescription`). On first launch iOS shows the Local
  Network permission prompt — **tap Allow**, or Bonjour is blocked.
- Keep the app **foregrounded** (MultipeerConnectivity suspends in the
  background).
- The phone must be on the same LAN as the mcwire host (Wi-Fi).

## Run the proof

With the app running on the phone (log shows `up: service=secondsee-mpc …`),
from any Mac on the same LAN:

```sh
.venv/bin/python -m mc.run --role browser --service secondsee-mpc
```

Success on the Mac side:

```
[mc] <- their greeting: <inst>+iPhone (token …)
[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)
[c1xx] identity exchange COMPLETE
[app] JSON channel up
[app] <- JSON: {'kind': 'hello', … 'payload': '<b64 of {"platform":"iOS",…}>'}
```

and on the phone:

```
▶ INVITE from PYSRV — accepting
● state connected peers=["PYSRV"]
→ CONNECTED peer=PYSRV
→ hello sent (…B)
→ ping sent      (every 2s)
```

The recorded run (iPhone 13 mini, both same-Mac and cross-Mac joins) is in
[`docs/evidence/R51-ios-device.md`](../docs/evidence/R51-ios-device.md).