#!/usr/bin/env python3
"""dump_udp.py — dump every datagram of the MC session UDP channel and locate
the app payload (mcpeer pattern) inside it, so the per-datagram envelope can
be split into header vs message framing.

Usage: dump_udp.py caps/<scenario>
"""
import sys, glob, os
from scapy.all import rdpcap, UDP, IP, Raw

PAYLOAD_MARK = bytes(i % 16 for i in range(33))  # 33B app payload pattern

def udp_flows(pcap):
    flows = {}
    for p in rdpcap(pcap):
        if IP not in p or UDP not in p or Raw not in p:
            continue
        ip, u = p[IP], p[UDP]
        key = tuple(sorted([(ip.src, u.sport), (ip.dst, u.dport)]))
        flows.setdefault(key, []).append((p.time, bytes(u.payload)))
    return flows

def analyze(capsdir):
    for pcap in sorted(glob.glob(os.path.join(capsdir, "*.pcap"))):
        flows = udp_flows(pcap)
        if not flows:
            continue
        print(f"\n===== {os.path.basename(pcap)} =====")
        for key, segs in sorted(flows.items(), key=lambda kv: sum(len(s) for _, s in kv[1]), reverse=True):
            tot = sum(len(s) for _, s in segs)
            if tot < 200:
                continue  # skip tiny/mDNS noise flows
            print(f"flow {key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}  {len(segs)} pkts {tot}B")
            for t, data in sorted(segs):
                mark_off = data.find(PAYLOAD_MARK)
                tag = f"  <-- app-33B payload at offset {mark_off}" if mark_off >= 0 else ""
                print(f"  t+{t-1787005100:7.3f} len={len(data):4d} {data.hex()}{tag}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: dump_udp.py caps/<scenario>")
        sys.exit(1)
    analyze(sys.argv[1])