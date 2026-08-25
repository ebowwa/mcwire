// mcoracle — a minimal, self-contained MultipeerConnectivity test peer.
//
// Purpose: an oracle that reproduces the *behavior* of a real modern
// MultipeerConnectivity channel (the wire surface the mcwire foreign client
// targets), with zero dependency on any app code:
//
//   . advertise AND browse simultaneously on one service type (symmetric,
//     either side can initiate — the same shape real apps use)
//   . MCSession with encryptionPreference .optional and nil security
//     identity (the default modern app channel)
//   . a non-nil identity dictionary in the Bonjour advertisement
//     (discoveryInfo), like production channels publish
//   . accepts every invitation, invites every discovered peer
//   . on connect: sends its identity as a `hello` JSON envelope, then
//     auto-pings every ~2s (the peer should pong); logs every event
//
// It deliberately does NOT use MultipeerKit or any other library — the
// envelope is the small JSON shape used by the channel under test:
//   {"v":1,"kind":<string>,"id":<uuid>,"payload":<base64 or "">}
//
// Build & run (needs macOS + MultipeerConnectivity):
//   swift build
//   .build/debug/mcoracle [service-type]     # default: secondsee-mpc
//
// Interactive commands on stdin: status | ping | frame | quit.
//
// Log lines that matter for verification (mcwire-side evidence):
//   ● state       connected(peerCount: N)   peers=[...]
//   📨 <kind> <bytes>B from <peer>           (a JSON envelope arrived)
//   → CONNECTED peer=<name>  (the "waiting" state for the app's own log)

import Foundation
import MultipeerConnectivity

@MainActor
final class Oracle: NSObject {
    let serviceType: String
    let peerID: MCPeerID
    let identity: [String: String]
    var session: MCSession?
    var advertiser: MCNearbyServiceAdvertiser?
    var browser: MCNearbyServiceBrowser?
    var connectedPeers: [MCPeerID] = []
    var framesReceived = 0
    var bytesReceived = 0
    var pingTimer: Timer?

    init(serviceType: String) {
        self.serviceType = serviceType
        let name = Host.current().localizedName ?? "Mac"
        self.peerID = MCPeerID(displayName: name)
        // Mirrors the channel under test: platform + name advertised in the
        // Bonjour record, and carried in the greeting `hello` envelope.
        self.identity = ["platform": "mcoracle", "name": name]
        super.init()
    }

    func start() {
        let s = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .optional)
        s.delegate = self
        session = s

        let adv = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: identity, serviceType: serviceType)
        adv.delegate = self
        self.advertiser = adv
        adv.startAdvertisingPeer()

        let br = MCNearbyServiceBrowser(peer: peerID, serviceType: serviceType)
        br.delegate = self
        self.browser = br
        br.startBrowsingForPeers()

        log("mcoracle up: service=\(serviceType) peer=\(peerID.displayName) enc=optional advertise+browse")
    }

    func stop() {
        advertiser?.stopAdvertisingPeer(); advertiser = nil
        browser?.stopBrowsingForPeers(); browser = nil
        pingTimer?.invalidate(); pingTimer = nil
        session?.disconnect(); session = nil
        connectedPeers = []
    }

    // MARK: sending

    func envelope(kind: String, payload: Data = Data()) -> Data? {
        let id = UUID().uuidString.uppercased()
        let obj: [String: Any] = payload.isEmpty
            ? ["v": 1, "kind": kind, "id": id, "payload": ""]
            : ["v": 1, "kind": kind, "id": id, "payload": payload.base64EncodedString()]
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return nil }
        return data
    }

    func send(_ data: Data, reliable: Bool = true) {
        guard let session, !connectedPeers.isEmpty else { return }
        try? session.send(data, toPeers: connectedPeers, with: reliable ? .reliable : .unreliable)
    }

    func sendHello() {
        let info = ["model": "mcoracle", "name": peerID.displayName + ".local", "platform": "macOS"]
        guard let payload = try? JSONSerialization.data(withJSONObject: info),
              let env = envelope(kind: "hello", payload: payload) else { return }
        send(env)
        log("→ hello sent (\(env.count)B, identity=\(info))")
    }

    func sendPing() {
        guard let env = envelope(kind: "ping") else { return }
        send(env)
        log("→ ping sent")
    }

    func sendFrame() {
        // A tiny solid-color JPEG so `frame` exercises the same path the
        // video envelopes use (kind:"frame", base64 JPEG payload).
        let w = 64, h = 64
        guard let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
        ) else { return }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        NSColor(calibratedRed: 0.2, green: 0.7, blue: 0.3, alpha: 1).setFill()
        NSRect(x: 0, y: 0, width: w, height: h).fill()
        NSGraphicsContext.restoreGraphicsState()
        guard let jpeg = rep.representation(using: .jpeg, properties: [:]) else { return }
        guard let env = envelope(kind: "frame", payload: jpeg) else { return }
        send(env)
        log("→ frame sent (\(jpeg.count)B jpeg)")
    }

    // MARK: logging

    func log(_ msg: String) {
        print("[oracle] \(msg)")
        fflush(stdout)
    }
}

extension Oracle: MCSessionDelegate {
    nonisolated func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        Task { @MainActor in
            switch state {
            case .connected:
                if !connectedPeers.contains(peerID) { connectedPeers.append(peerID) }
                log("● state connected peers=\(connectedPeers.map(\.displayName))")
                log("→ CONNECTED peer=\(peerID.displayName)")
                if pingTimer == nil {
                    pingTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
                        Task { @MainActor in self?.sendPing() }
                    }
                }
                sendHello()
            case .connecting:
                log("● state connecting peers=\(connectedPeers.map(\.displayName))")
            case .notConnected:
                connectedPeers.removeAll { $0 == peerID }
                log("● state disconnected peers=\(connectedPeers.map(\.displayName))")
            @unknown default:
                break
            }
        }
    }

    nonisolated func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        Task { @MainActor in
            framesReceived += 1
            bytesReceived += data.count
            // decode the JSON envelope to log its kind
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let kind = obj["kind"] as? String {
                log("📨 \(kind) \(data.count)B from \(peerID.displayName) (frame #\(framesReceived))")
                if kind == "pong" {
                    log("→ pong received (round-trip alive)")
                }
            } else {
                log("📨 raw \(data.count)B from \(peerID.displayName)")
            }
        }
    }

    nonisolated func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    nonisolated func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    nonisolated func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
    nonisolated func session(_ session: MCSession, peer peerID: MCPeerID, didReceiveCertificate certificate: [Any]?, fromPeer certificateHandler: @escaping (Bool) -> Void) {
        certificateHandler(true)
    }
}

extension Oracle: MCNearbyServiceAdvertiserDelegate {
    nonisolated func advertiser(_ advertiser: MCNearbyServiceAdvertiser,
                                didReceiveInvitationFromPeer peerID: MCPeerID,
                                withContext context: Data?,
                                invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        Task { @MainActor in
            log("▶ INVITE from \(peerID.displayName) — accepting")
            invitationHandler(true, session)
        }
    }
    nonisolated func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
        Task { @MainActor in log("✗ advertise error: \(error.localizedDescription)") }
    }
}

extension Oracle: MCNearbyServiceBrowserDelegate {
    nonisolated func browser(_ browser: MCNearbyServiceBrowser,
                             foundPeer peerID: MCPeerID,
                             withDiscoveryInfo info: [String: String]?) {
        Task { @MainActor in
            log("▶ peerFound \(peerID.displayName) info=\(info ?? [:])")
            guard let session else { return }
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10)
        }
    }
    nonisolated func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        Task { @MainActor in log("◀ peerLost \(peerID.displayName)") }
    }
    nonisolated func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {
        Task { @MainActor in log("✗ browse error: \(error.localizedDescription)") }
    }
}

@main
enum OracleApp {
    @MainActor
    static func main() {
        let svc = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "secondsee-mpc"
        let oracle = Oracle(serviceType: svc)
        oracle.start()

        // stdin commands
        let stdin = FileHandle.standardInput
        let src = DispatchSource.makeReadSource(fileDescriptor: stdin.fileDescriptor, queue: .global())
        src.setEventHandler {
            let data = stdin.availableData
            guard !data.isEmpty else { return }
            let line = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            Task { @MainActor in
                switch line.lowercased() {
                case "status":
                    oracle.log("state=\(oracle.connectedPeers.count) connected peers=\(oracle.connectedPeers.map(\.displayName)) frames=\(oracle.framesReceived) bytes=\(oracle.bytesReceived)")
                case "ping": oracle.sendPing()
                case "frame": oracle.sendFrame()
                case "quit", "exit", "q":
                    oracle.stop(); exit(0)
                default:
                    oracle.log("? unknown command (status | ping | frame | quit)")
                }
            }
        }
        src.resume()

        RunLoop.main.run()
    }
}