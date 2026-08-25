// mcoracle (iOS) — the self-contained proof oracle, device edition.
//
// Same behavior as Sources/mcoracle (macOS): a real MCSession channel with
// .optional encryption and a nil security identity, symmetric
// advertise+browse on one service type, identity discoveryInfo, accept-all
// invitations, a `hello` JSON envelope on connect, and a 2s auto-ping.
//
// It exists so the foreign client (mcwire, on a Mac) can join a REAL iOS
// MCSession — the iOS half of the repo's claim, proven on actual hardware.
//
// Everything is mirrored to both the on-screen log and NSLog (so
// `xcrun devicectl device process launch --console` streams it live).

import Foundation
import MultipeerConnectivity
import SwiftUI

@MainActor
final class IosOracle: NSObject, ObservableObject {
    let serviceType: String
    let peerID: MCPeerID
    let identity: [String: String]

    @Published var lines: [String] = []
    @Published var connectedCount = 0
    @Published var running = false

    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var connectedPeers: [MCPeerID] = []
    private var pingTimer: Timer?

    init(serviceType: String) {
        self.serviceType = serviceType
        let name = UIDevice.current.name
        self.peerID = MCPeerID(displayName: name)
        self.identity = ["platform": "iOS", "name": name]
        super.init()
    }

    // MARK: lifecycle

    func start() {
        stop()

        let s = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .optional)
        s.delegate = self
        session = s

        let adv = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: identity, serviceType: serviceType)
        adv.delegate = self
        advertiser = adv
        adv.startAdvertisingPeer()

        let br = MCNearbyServiceBrowser(peer: peerID, serviceType: serviceType)
        br.delegate = self
        browser = br
        br.startBrowsingForPeers()

        running = true
        log("up: service=\(serviceType) peer=\(peerID.displayName) enc=optional advertise+browse")
    }

    func stop() {
        advertiser?.stopAdvertisingPeer(); advertiser = nil
        browser?.stopBrowsingForPeers(); browser = nil
        pingTimer?.invalidate(); pingTimer = nil
        session?.disconnect(); session = nil
        connectedPeers = []
        connectedCount = 0
        running = false
    }

    // MARK: envelopes (same shape as the macOS oracle / target channel)

    func envelope(kind: String, payload: Data = Data()) -> Data? {
        let obj: [String: Any] = payload.isEmpty
            ? ["v": 1, "kind": kind, "id": UUID().uuidString.uppercased(), "payload": ""]
            : ["v": 1, "kind": kind, "id": UUID().uuidString.uppercased(), "payload": payload.base64EncodedString()]
        return try? JSONSerialization.data(withJSONObject: obj)
    }

    func send(_ data: Data) {
        guard let session, !connectedPeers.isEmpty else { return }
        try? session.send(data, toPeers: connectedPeers, with: .reliable)
    }

    func sendHello() {
        let info = ["model": modelIdentifier(), "name": peerID.displayName, "platform": "iOS"]
        guard let payload = try? JSONSerialization.data(withJSONObject: info),
              let env = envelope(kind: "hello", payload: payload) else { return }
        send(env)
        log("→ hello sent (\(env.count)B)")
    }

    func sendPing() {
        guard let env = envelope(kind: "ping") else { return }
        send(env)
        log("→ ping sent")
    }

    private func modelIdentifier() -> String {
        var sysinfo = utsname()
        uname(&sysinfo)
        return withUnsafeBytes(of: &sysinfo.machine) { raw in
            raw.prefix(while: { $0 != 0 }).map { String(UnicodeScalar($0)) }.joined()
        }
    }

    // MARK: logging

    func log(_ msg: String) {
        let line = "[oracle] \(msg)"
        print(line)
        NSLog("%@", line)
        Task { @MainActor in
            lines.append(line)
            if lines.count > 400 { lines.removeFirst(lines.count - 400) }
        }
    }
}

extension IosOracle: MCSessionDelegate {
    nonisolated func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        Task { @MainActor in
            switch state {
            case .connected:
                if !connectedPeers.contains(peerID) { connectedPeers.append(peerID) }
                connectedCount = connectedPeers.count
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
                connectedCount = connectedPeers.count
                log("● state disconnected peers=\(connectedPeers.map(\.displayName))")
            @unknown default:
                break
            }
        }
    }

    nonisolated func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        Task { @MainActor in
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let kind = obj["kind"] as? String {
                log("📨 \(kind) \(data.count)B from \(peerID.displayName)")
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

extension IosOracle: MCNearbyServiceAdvertiserDelegate {
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

extension IosOracle: MCNearbyServiceBrowserDelegate {
    nonisolated func browser(_ browser: MCNearbyServiceBrowser,
                             foundPeer peerID: MCPeerID,
                             withDiscoveryInfo info: [String: String]?) {
        Task { @MainActor in
            log("▶ peerFound \(peerID.displayName)")
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

// MARK: - UI

struct ContentView: View {
    @StateObject private var oracle = IosOracle(serviceType: "secondsee-mpc")

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Text("mcoracle")
                    .font(.headline.monospaced())
                Spacer()
                Text(oracle.running ? "service \(oracle.serviceType)" : "stopped")
                    .font(.caption.monospaced())
                    .foregroundStyle(oracle.running ? .green : .secondary)
                Text("peers \(oracle.connectedCount)")
                    .font(.caption.monospaced().bold())
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background((oracle.connectedCount > 0 ? Color.green : Color.gray).opacity(0.25))
                    .clipShape(Capsule())
            }
            .padding(.horizontal)

            HStack(spacing: 12) {
                Button(oracle.running ? "Restart" : "Start") { oracle.start() }
                    .buttonStyle(.borderedProminent)
                Button("Stop") { oracle.stop() }
                    .buttonStyle(.bordered)
                    .disabled(!oracle.running)
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(oracle.lines.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(i)
                        }
                    }
                    .padding(.horizontal)
                }
                .background(Color.black.opacity(0.92))
                .onChange(of: oracle.lines.count) { _ in
                    if let last = oracle.lines.indices.last { proxy.scrollTo(last, anchor: .bottom) }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .padding(.horizontal)
        }
        .padding(.vertical)
        .onAppear { oracle.start() }
    }
}

@main
struct McoracleApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}