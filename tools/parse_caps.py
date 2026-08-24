#!/usr/bin/env python3
"""parse_caps.py — extract the MCSession TCP wire format from captured pcaps.

Reads a capture-run.sh output dir (caps/<scenario>/*.pcap), reassembles
bidirectional TCP flows on each interface, and prints per-flow hex dumps.
Heuristic pass: flags packet boundaries by locating our known 33-byte payload
pattern (00 01 02 ... 0f 00 01 ...) inside each direction, which brackets the
per-message framing overhead.

Usage: parse_caps.py <capsdir>
"""
import sys, os, glob
from scapy.all import rdpcap, TCP, IP, Raw

PAYLOAD_MARK = bytes(i % 16 for i in range(33))  # mcpeer --bytes 33 pattern

def flows_from(pcap):
    pkts = rdpcap(pcap)
    flows = {}
    for p in pkts:
        if IP not in p or TCP not in p or Raw not in p:
            continue
        ip = p[IP]
        t = p[TCP]
        key = tuple(sorted([(ip.src, t.sport), (ip.dst, t.dport)]))
        dirkey = 0 if (ip.src, t.sport) == min(key) else 1
        flows.setdefault(key, [[], []])[dirkey].append((float(p.time), bytes(p[Raw].load)))
    return flows

def analyze(capsdir):
    for pcap in sorted(glob.glob(os.path.join(capsdir, "*.pcap"))):
        flows = flows_from(pcap)
        if not flows:
            continue
        print(f"\n========== {os.path.basename(pcap)} — {len(flows)} TCP flow(s) ==========")
        for key, (a, b) in flows.items():
            if not a and not b:
                continue
            print(f"  flow {key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]} "
                  f"(A→B {sum(len(x) for _, x in a)}B in {len(a)} seg, B→A {sum(len(x) for _, x in b)}B in {len(b)} seg)")
            for side, segs in (("A→B", a), ("B→A", b)):
                for t, data in segs:
                    tag = " <payload>" if PAYLOAD_MARK in data else ""
                    shown = data[:64].hex()
                    if len(data) > 64:
                        shown += f"...(+{len(data)-64}B)"
                    print(f"    {side} t={t:9.3f} len={len(data):5d} {shown}{tag}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: parse_caps.py <capsdir>")
        sys.exit(1)
    analyze(sys.argv[1])