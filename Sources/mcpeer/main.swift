import Foundation
import MultipeerConnectivity

// ---------------------------------------------------------------------------
// mcpeer — a minimal MultipeerConnectivity prober for wire-protocol RE.
//
//   mcpeer advertise <type> [--name N] [--bytes N] [--payload HEX] [--info k=v,...]
//   mcpeer browse    <type> [--name N] [--bytes N] [--payload HEX] [--no-invite]
//                          [--period S] [--required|--optional]
//
// Builds plaintext sessions by default (nil security identity + .none),
// matching the typical `MCSession(peer:)` app. --required exercises the
// identity handshake path (with a nil identity) for grammar coverage.
// --optional mirrors the typical modern app channel (`.optional` data-plane
// encryption — the plane mcwire's DTLS browser flow is validated against),
// still with a nil security identity.
// ---------------------------------------------------------------------------

let defaultType = "mc-probe"
let defaultPeriod = 1.0

struct Opts {
    var mode = ""
    var type = defaultType
    var name = ""
    var payloadBytes = [UInt8]()
    var payloadHex = ""
    var bytes = 0
    var sizes = [Int]()
    var period = defaultPeriod
    var invite = true
    var required = false
    var optional = false
    var info = [String: String]()
}

func usage() -> Never {
    print("""
    usage:
      mcpeer advertise <type> [--name N] [--bytes N] [--payload HEX] [--info k=v,...] [--required]
      mcpeer browse    <type> [--name N] [--bytes N] [--payload HEX] [--period S] [--no-invite] [--required|--optional]
    """)
    exit(2)
}

func parseArgs(_ args: [String]) -> Opts {
    var o = Opts()
    var rest = args
    guard rest.count >= 2 else { usage() }
    o.mode = rest[0]
    o.type = rest[1]
    rest.removeFirst(2)
    var i = 0
    while i < rest.count {
        let a = rest[i]
        switch a {
        case "--name": i += 1; o.name = rest[i]
        case "--bytes": i += 1; o.bytes = Int(rest[i]) ?? 0
        case "--sizes":
            i += 1
            o.sizes = rest[i].split(separator: ",").compactMap { Int($0) }
        case "--payload":
            i += 1; o.payloadHex = rest[i]
        case "--period": i += 1; o.period = Double(rest[i]) ?? defaultPeriod
        case "--info":
            i += 1
            for pair in rest[i].split(separator: ",") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 { o.info[String(kv[0])] = String(kv[1]) }
            }
        case "--no-invite": o.invite = false
        case "--required": o.required = true
        case "--optional": o.optional = true
        default: usage()
        }
        i += 1
    }
    if o.name.isEmpty {
        o.name = "mcpeer-\(Host.current().localizedName ?? "host")-\(ProcessInfo.processInfo.processIdentifier)"
    }
    if !o.payloadHex.isEmpty {
        var out = [UInt8]()
        var h = o.payloadHex
        while h.count >= 2 {
            out.append(UInt8(h.prefix(2), radix: 16) ?? 0)
            h = String(h.dropFirst(2))
        }
        o.payloadBytes = out
    } else if !o.sizes.isEmpty {
        o.payloadBytes = []  // size cycling handled in send loop
    } else if o.bytes > 0 {
        // recognizable repeating pattern for grammar extraction
        o.payloadBytes = (0..<o.bytes).map { UInt8($0 % 16) }
    } else {
        o.payloadBytes = [0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03]
    }
    return o
}

struct Log {
    static func t(_ msg: String) {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        print("[\(f.string(from: Date()))] \(msg)", terminator: "\n")
        fflush(stdout)
    }
}

final class Prober: NSObject {
    let opts: Opts
    let peerID: MCPeerID
    var advertiser: MCNearbyServiceAdvertiser?
    var browser: MCNearbyServiceBrowser?
    var session: MCSession?
    var sendTimer: Timer?
    var connectedPeers = [MCPeerID]()
    var sentCount = 0

    init(opts: Opts) {
        self.opts = opts
        self.peerID = MCPeerID(displayName: opts.name)
        super.init()
        let enc: MCEncryptionPreference = opts.optional ? .optional
            : (opts.required ? .required : .none)
        let s = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: enc)
        s.delegate = self
        self.session = s
    }

    func start() {
        if opts.mode == "advertise" {
            let adv = MCNearbyServiceAdvertiser(peer: peerID,
                                                discoveryInfo: opts.info.isEmpty ? nil : opts.info,
                                                serviceType: opts.type)
            adv.delegate = self
            self.advertiser = adv
            adv.startAdvertisingPeer()
            Log.t("ADVERTISE type=\(opts.type) info=\(opts.info) name=\(opts.name) enc=\(opts.optional ? "optional" : (opts.required ? "required" : "none"))")
        } else {
            let br = MCNearbyServiceBrowser(peer: peerID, serviceType: opts.type)
            br.delegate = self
            self.browser = br
            br.startBrowsingForPeers()
            Log.t("BROWSE type=\(opts.type) name=\(opts.name) invite=\(opts.invite)")
        }
    }

    func startSendingIfConnected() {
        guard sendTimer == nil, !connectedPeers.isEmpty, let session = session else { return }
        let sizes = opts.sizes
        let bytes = opts.payloadBytes
        Log.t("SEND-LOOP start: \(sizes.isEmpty ? "\(bytes.count)" : "cycle \(sizes)") bytes every \(opts.period)s to \(connectedPeers.map { $0.displayName })")
        let timer = Timer(timeInterval: opts.period, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            var data: Data
            if sizes.isEmpty {
                data = Data(bytes)
            } else {
                let n = sizes[self.sentCount % sizes.count]
                data = Data((0..<n).map { UInt8($0 % 16) })
            }
            for peer in self.connectedPeers {
                do {
                    try session.send(data, toPeers: [peer], with: .reliable)
                    self.sentCount += 1
                    if self.sentCount <= 3 || self.sentCount % 10 == 0 {
                        Log.t("SEND #\(self.sentCount) to \(peer.displayName): \(data.count) bytes")
                    }
                } catch {
                    Log.t("SEND-FAIL to \(peer.displayName): \(error)")
                }
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        sendTimer = timer
    }
}

extension Prober: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser,
                    didReceiveInvitationFromPeer peerID: MCPeerID,
                    withContext context: Data?,
                    invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        Log.t("INVITE from \(peerID.displayName) context=\(context.map { "\($0.count)B" } ?? "nil")")
        invitationHandler(true, session)
    }

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
        Log.t("ADVERTISE-ERROR: \(error)")
    }
}

extension Prober: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser,
                 foundPeer peerID: MCPeerID,
                 withDiscoveryInfo info: [String: String]?) {
        Log.t("FOUND peer=\(peerID.displayName) info=\(info ?? [:])")
        if opts.invite, let session = session {
            Log.t("INVITING \(peerID.displayName)")
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
        }
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        Log.t("LOST peer=\(peerID.displayName)")
    }

    func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {
        Log.t("BROWSE-ERROR: \(error)")
    }
}

extension Prober: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        Log.t("STATE \(peerID.displayName): \(state.rawValue)")
        switch state {
        case .connected:
            if !connectedPeers.contains(where: { $0 == peerID }) { connectedPeers.append(peerID) }
            startSendingIfConnected()
        case .notConnected:
            connectedPeers.removeAll { $0 == peerID }
        default:
            break
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        let head = data.prefix(64).map { String(format: "%02x", $0) }.joined()
        Log.t("DATA from=\(peerID.displayName) len=\(data.count) hex=\(head)")
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {
        Log.t("STREAM from=\(peerID.displayName) name=\(streamName)")
    }

    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String,
                 fromPeer peerID: MCPeerID, with progress: Progress) {
        Log.t("RESOURCE-START from=\(peerID.displayName) name=\(resourceName)")
    }

    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String,
                 fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {
        Log.t("RESOURCE-END from=\(peerID.displayName) name=\(resourceName) url=\(localURL?.path ?? "nil") err=\(String(describing: error))")
    }

    func session(_ session: MCSession, peer peerID: MCPeerID, didReceiveCertificate certificate: [Any]?, fromPeer certificateHandler: @escaping (Bool) -> Void) {
        Log.t("CERT from=\(peerID.displayName) count=\(certificate?.count ?? -1)")
        certificateHandler(true)
    }

    func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        Log.t("CERT2 from=\(peerID.displayName) count=\(certificate?.count ?? -1)")
        certificateHandler(true)
    }
}

let opts = parseArgs(Array(CommandLine.arguments.dropFirst()))
let prober = Prober(opts: opts)
prober.start()
RunLoop.main.run()