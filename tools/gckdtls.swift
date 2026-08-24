// gckdtls.swift — SSLContext DTLS brain for the MC foreign client.
//
// stdin:  hex(Apple d0-envelope record) per line  (from the app)
// stdout: hex(Apple d0-envelope record) per line  (for the app)
//
// Converts each d0-envelope to a standard DTLS record for SSLContext, drives
// SSLHandshake, converts SSLWrite output back to d0-envelopes. Apple's own
// stack does ALL crypto (incl. the Finished MAC that defeated templates).
//
// Apple envelope : d0 | type | feff | epoch(2) | seq(4) | len(2) | payload
// DTLS 1.0 record: type | feff | epoch(2) | seq(6) | len(2) | payload
//
// Build: swiftc gckdtls.swift -o /tmp/gckdtls -framework Security
// Test:  echo <hex-of-app-ch> | /tmp/gckdtls

import Foundation

@_silgen_name("SSLCreateContext") func SSLCreateContextC(_ a: UnsafeMutableRawPointer?, _ side: Int32, _ typ: Int32) -> UnsafeMutableRawPointer?
@_silgen_name("SSLSetIOFuncs") func SSLSetIOFuncsC(_ ctx: UnsafeMutableRawPointer, _ r: @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?) -> Int32, _ w: @convention(c) (UnsafeMutableRawPointer?, UnsafeRawPointer?, UnsafeMutablePointer<Int>?) -> Int32) -> Int32
@_silgen_name("SSLSetConnection") func SSLSetConnectionC(_ ctx: UnsafeMutableRawPointer, _ c: UnsafeMutableRawPointer?) -> Int32
@_silgen_name("SSLSetEnabledCiphers") func SSLSetEnabledCiphersC(_ ctx: UnsafeMutableRawPointer, _ s: UnsafePointer<UInt16>, _ n: Int) -> Int32
@_silgen_name("SSLSetSessionOption") func SSLSetSessionOptionC(_ ctx: UnsafeMutableRawPointer, _ o: Int32, _ v: Bool) -> Int32
@_silgen_name("SSLSetDatagramHelloCookie") func SSLSetDatagramHelloCookieC(_ ctx: UnsafeMutableRawPointer, _ c: UnsafeRawPointer, _ n: Int) -> Int32
@_silgen_name("SSLHandshake") func SSLHandshakeC(_ ctx: UnsafeMutableRawPointer) -> Int32
@_silgen_name("SSLRead") func SSLReadC(_ ctx: UnsafeMutableRawPointer, _ b: UnsafeMutableRawPointer, _ n: Int, _ got: UnsafeMutablePointer<Int>) -> Int32
@_silgen_name("SSLWrite") func SSLWriteC(_ ctx: UnsafeMutableRawPointer, _ b: UnsafeRawPointer, _ n: Int, _ put: UnsafeMutablePointer<Int>) -> Int32
@_silgen_name("SSLGetNegotiatedCipher") func SSLGetNegotiatedCipherC(_ ctx: UnsafeMutableRawPointer, _ o: UnsafeMutablePointer<UInt16>) -> Int32

let ERR_WOULDBLOCK: Int32 = -9841
let ERR_AUTH_COMPLETED: Int32 = -9817   // errSSLPeerAuthCompleted (0.8+)
let ERR_SERVER_AUTH: Int32 = -9844      // errSSLServerAuthCompleted

// ---- envelope codec ----
func appleToDTLS(_ a: [UInt8]) -> [UInt8]? {
    // The Apple envelope is EXACTLY: 0xd0 + a standard DTLS record
    // (type ver epoch seq6 len payload) — byte-for-byte the record with a
    // one-byte marker prefix. Decoded from 14B real headers vs our failed
    // 12B re-pack (which shifted the payload 2B -> app "13 bytes short").
    guard a.count >= 14, a[0] == 0xd0 else { return nil }
    return Array(a[1...])
}

func dtlsToApple(_ d: [UInt8]) -> [UInt8]? {
    guard d.count >= 13, d[1] == 0xfe else { return nil }
    return [0xd0] + d
}

// ---- record pumps ----
final class Brain {
    var inbound: [[UInt8]] = []       // DTLS records waiting for SSLRead
    var outboundLock = NSLock()
    var outbound: [[UInt8]] = []      // DTLS records SSLWrite produced
    var plainOut: [UInt8] = []
}

let brain = Brain()

func readCb(_ conn: UnsafeMutableRawPointer?, _ data: UnsafeMutableRawPointer?, _ len: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let next = brain.inbound.first else { len?.pointee = 0; return ERR_WOULDBLOCK }
    let n = min(next.count, len!.pointee)
    memcpy(data!, next, n)
    if n == next.count { brain.inbound.removeFirst() }
    else { brain.inbound[0] = Array(next[n...]) }
    len!.pointee = n
    return 0
}
func writeCb(_ conn: UnsafeMutableRawPointer?, _ data: UnsafeRawPointer?, _ len: UnsafeMutablePointer<Int>?) -> Int32 {
    let rec = Array(UnsafeRawBufferPointer(start: data!, count: len!.pointee))
    brain.outboundLock.lock()
    brain.outbound.append(rec)
    brain.outboundLock.unlock()
    return 0
}

// ---- setup ----
// Role from argv: "client" makes US initiate (the DTLS role is decided by
// participant-ID comparison: LOWER token-last4 = client; our ID is random,
// so it flips per session and the Python side picks the role).
let isClient = CommandLine.arguments.count > 1 && CommandLine.arguments[1] == "client"
guard let ctx = SSLCreateContextC(nil, isClient ? 1 : 0, 1) else { // client=1 server=0, datagram=1
    print("ctx fail"); exit(1)
}
_ = SSLSetSessionOptionC(ctx, 2, true)   // allowAnyRoot
_ = SSLSetSessionOptionC(ctx, 0, true)   // breakOnServerAuth
var suites: [UInt16] = [0xC019, 0xC018, 0x006D, 0x003A, 0x006C, 0x0034,
                        0xC02F, 0xC027, 0xC02B, 0xC023, 0xC013, 0xC014]
let sst = suites.withUnsafeBufferPointer { SSLSetEnabledCiphersC(ctx, $0.baseAddress!, suites.count) }
if sst != 0 { print("# enabledCiphers status \(sst)") }
_ = SSLSetDatagramHelloCookieC(ctx, [0x12, 0x34, 0x56, 0x78], 4)
_ = SSLSetIOFuncsC(ctx, readCb, writeCb)
_ = SSLSetConnectionC(ctx, UnsafeMutableRawPointer(bitPattern: 0x1)) // opaque

func pump() {
    // drain SSLWrite output as d0-envelopes. ONE SSLWrite callback = ONE
    // datagram, which may carry MULTIPLE glued DTLS records (a flight —
    // e.g. SKE+HD arrive glued). Split on record headers: each record gets
    // its OWN apple envelope, or the peer's parser desyncs by exactly 13
    // bytes (one embedded record header — diagnosed from the app's
    // "No packets available (13 bytes requested)" loop).
    brain.outboundLock.lock()
    let out = brain.outbound
    brain.outbound.removeAll()
    brain.outboundLock.unlock()
    for datagram in out {
        var off = 0
        while off + 13 <= datagram.count {
            let rec = Array(datagram[off...])
            let len = (Int(rec[11]) << 8) | Int(rec[12])
            let total = 13 + len
            if rec.count < total { break }              // truncated — skip
            let single = Array(datagram[off ..< off + total])
            if let apple = dtlsToApple(single) {
                print(apple.map { String(format: "%02x", $0) }.joined())
                fflush(stdout)
            }
            off += total
        }
    }
}

// main loop: line per inbound apple record
if isClient {
    // kick off: one handshake round emits our ClientHello via the write tap
    let _ = SSLHandshakeC(ctx)
    pump()
}
while let line = readLine() {
    let hex = line.trimmingCharacters(in: .whitespaces)
    guard hex.count > 0, hex.count % 2 == 0 else { continue }
    var bytes: [UInt8] = []
    var i = hex.startIndex
    while i < hex.endIndex {
        let j = hex.index(i, offsetBy: 2)
        guard let v = UInt8(hex[i..<j], radix: 16) else { break }
        bytes.append(v)
        i = j
    }
    // command: "send <hex>" = write plaintext through the tunnel
    if hex.hasPrefix("send ") {
        var pt: [UInt8] = []
        var i2 = hex.index(hex.startIndex, offsetBy: 5)
        while i2 < hex.endIndex {
            let j2 = hex.index(i2, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let v = UInt8(hex[i2..<j2], radix: 16) else { break }
            pt.append(v); i2 = j2
        }
        var put = 0
        let ws = SSLWriteC(ctx, pt, pt.count, &put)
        pump()
        if ws != 0 { print("# send status \(ws)"); fflush(stdout) }
        continue
    }
    guard let dtls = appleToDTLS(bytes) else {
        print("# not a d0 record: \(hex.prefix(16))"); fflush(stdout); continue
    }
    brain.inbound.append(dtls)
    // drive handshake (multiple rounds for multi-message output)
    for _ in 0..<3 {
        let st = SSLHandshakeC(ctx)
        pump()
        if st == 0 { print("# handshake complete"); fflush(stdout); break }
        if st != ERR_WOULDBLOCK && st != ERR_AUTH_COMPLETED && st != ERR_SERVER_AUTH {
            print("# hs status \(st)"); fflush(stdout); break
        }
    }
    // after handshake: try draining any app-data (SSLRead)
    var buf = [UInt8](repeating: 0, count: 65536)
    var got = 0
    let rs = SSLReadC(ctx, &buf, buf.count, &got)
    if got > 0 {
        print("plain " + Data(buf[0..<got]).map { String(format: "%02x", $0) }.joined())
        fflush(stdout)
    }
    if rs != 0 && rs != ERR_WOULDBLOCK { print("# read status \(rs)"); fflush(stdout) }
}
var neg: UInt16 = 0
_ = SSLGetNegotiatedCipherC(ctx, &neg)
print(String(format: "# negotiated 0x%04x", neg))
