#!/usr/bin/env python3
"""decode_mc.py — structured decode of MCSession wire protocol from captures.

Decodes:
  TCP handshake: opcode messages (0x07d0/0x0898/0x0834) + NSKeyedArchiver
  plists (MCNearbyServiceConnectionDataKey / InviteIDKey / ...).
  UDP session channel: hello/ack (0x0001/0x0101), data+ack (0xc1xx),
  8-byte peer tokens, sequence counters, embedded message framing.

Usage: decode_mc.py caps/<scenario>
"""
import sys, glob, os, plistlib
from scapy.all import rdpcap, TCP, IP, Raw, UDP

OP_HELLO, OP_INVITE, OP_CERT = 0x07d0, 0x0898, 0x0834

def reassembled_flows(pcap):
    pkts = rdpcap(pcap)
    flows = {}
    for p in pkts:
        if IP not in p or TCP not in p or Raw not in p: continue
        ip, t = p[IP], p[TCP]
        key = tuple(sorted([(ip.src, t.sport), (ip.dst, t.dport)]))
        d = 0 if (ip.src, t.sport) == key[0] else 1
        flows.setdefault(key, [[], []])[d].append((t.seq, bytes(p[Raw].load)))
    out = {}
    for key, dirs in flows.items():
        streams = []
        for segs in dirs:
            buf = bytearray(); exp = None
            for seq, data in sorted(segs):
                if exp is None: buf.extend(data); exp = seq + len(data)
                elif seq == exp: buf.extend(data); exp += len(data)
            streams.append(bytes(buf))
        out[key] = streams
    return out

def split_messages(stream):
    msgs = []; i = 0; n = len(stream); cur = bytearray(); cur_op = None
    while i < n:
        op = (stream[i] << 8 | stream[i+1]) if i + 1 < n else None
        if op in (OP_HELLO, OP_INVITE, OP_CERT) and len(cur) > 0:
            msgs.append((cur_op, bytes(cur))); cur = bytearray()
        if op in (OP_HELLO, OP_INVITE, OP_CERT):
            cur_op = op; cur.extend(stream[i:i+2]); i += 2
        else:
            cur.append(stream[i]); i += 1
    if cur: msgs.append((cur_op or 0, bytes(cur)))
    return msgs

def dump_plist(payload):
    try:
        obj = plistlib.loads(payload)
        print("      plist keys:")
        for k, v in obj.items():
            if isinstance(v, (bytes, bytearray)):
                print(f"        {k}: <NSData {len(v)}B> {bytes(v)[:64].hex()}")
            else:
                print(f"        {k}: {v!r}")
    except Exception as e:
        print(f"      (plist parse failed: {e})")

def show_tcp(scenario):
    print(f"\n########## TCP HANDSHAKE ({scenario}) ##########")
    for pcap in sorted(glob.glob(os.path.join(scenario, "*.pcap"))):
        flows = reassembled_flows(pcap)
        for key, (a, b) in flows.items():
            for tag, stream in (("ADV->BRW", a), ("BRW->ADV", b)):
                for op, m in split_messages(stream):
                    if op == OP_CERT and len(m) > 20 and b"bplist00" in m:
                        print(f"[{os.path.basename(pcap)}] {tag} op=0x{op:04x} len={len(m)} payload={m[16:].hex()[:32]}...")
                        dump_plist(m[16:])
                    elif len(m) <= 64:
                        print(f"[{os.path.basename(pcap)}] {tag} op=0x{op:04x} len={len(m)} {m.hex()}")

def udp_datagrams(pcap):
    out = []
    for p in rdpcap(pcap):
        if IP not in p or UDP not in p or Raw not in p: continue
        ip, u = p[IP], p[UDP]
        if u.sport in (16401, 16402) or u.dport in (16401, 16402):
            out.append((p.time, ip.src, u.sport, bytes(u.payload)))
    return sorted(out)

def show_udp(scenario):
    print(f"\n########## UDP SESSION CHANNEL ({scenario}) ##########")
    for pcap in sorted(glob.glob(os.path.join(scenario, "*.pcap"))):
        ds = udp_datagrams(pcap)
        for t, src, sp, d in ds:
            print(f"[{os.path.basename(pcap)}] t+{t-1787005100:7.3f} :{sp} len={len(d):3d} {d.hex()}")
        if ds:
            return

if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "caps/plain-none"
    show_tcp(scenario)
    show_udp(scenario)