#!/usr/bin/env python3
"""analyze_mc.py — reassemble MCSession TCP flows from pcaps and segment them.

MC flows are identified by 2-byte opcode prefixes (0x07d0, 0x0898, 0x0834).
Full per-direction byte streams are rebuilt from TCP sequence numbers so
message boundaries are exact (segments merge / split across packets).

Usage: analyze_mc.py caps/<scenario> [--hex]
"""
import sys, os, glob
from scapy.all import rdpcap, TCP, IP, Raw

MC_OPS = {0x07d0, 0x0898, 0x0834}

def reassembled_flows(pcap):
    """Return {key: [b"A->B bytes", b"B->A bytes"]} for MC-looking flows."""
    pkts = rdpcap(pcap)
    flows = {}
    for p in pkts:
        if IP not in p or TCP not in p or Raw not in p:
            continue
        ip, t = p[IP], p[TCP]
        key = tuple(sorted([(ip.src, t.sport), (ip.dst, t.dport)]))
        d = 0 if (ip.src, t.sport) == key[0] else 1
        flows.setdefault(key, [[], []])
        flows[key][d].append((t.seq, bytes(p[Raw].load)))
    out = {}
    for key, dirs in flows.items():
        streams = []
        for segs in dirs:
            buf = bytearray()
            expected = None
            for seq, data in sorted(segs):
                if expected is None or seq > expected:
                    # gap or first packet — append as-is
                    buf.extend(data)
                elif seq < expected:
                    continue  # retransmission
                else:
                    buf.extend(data)
                expected = seq + len(data)
            streams.append(bytes(buf))
        if any(s[:2] in (b"\x07\xd0", b"\x08\x98", b"\x08\x34") for s in streams):
            out[key] = streams
    return out

def split_messages(stream, ops=MC_OPS):
    """Heuristic message split: every 2-byte opcode that starts a new message
    is recognized as 08xx/07d0; all other bytes belong to the current message."""
    msgs = []
    i = 0
    n = len(stream)
    cur = bytearray()
    cur_op = None
    while i < n:
        op = stream[i] << 8 | stream[i+1] if i + 1 < n else None
        if op in ops and len(cur) > 0:
            msgs.append((cur_op, bytes(cur)))
            cur = bytearray()
        if op in ops:
            cur_op = op
            cur.extend(stream[i:i+2])
            i += 2
        else:
            cur.append(stream[i])
            i += 1
    if cur:
        msgs.append((cur_op or (0,), bytes(cur)))
    return msgs

def show(stream, tag, hexdump=False):
    msgs = split_messages(stream)
    print(f"  -- {tag}: {len(stream)}B total, {len(msgs)} message(s) --")
    for op, m in msgs:
        head = m if len(m) <= 96 else m[:96] + b"...(+%dB)" % (len(m) - 96)
        dec = ""
        if b"bplist00" in m:
            dec = " <PLIST>"
        elif b"+" in m and op == 0x07d0:
            dec = " <hello token+name>"
        print(f"    op=0x{op:04x} len={len(m):4d} {head!r}{dec}")

def analyze(capsdir):
    for pcap in sorted(glob.glob(os.path.join(capsdir, "*.pcap"))):
        flows = reassembled_flows(pcap)
        if not flows:
            continue
        print(f"\n===== {os.path.basename(pcap)} =====")
        for key, (a, b) in flows.items():
            print(f"flow {key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}")
            show(a, "A->B")
            show(b, "B->A")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: analyze_mc.py caps/<scenario>")
        sys.exit(1)
    analyze(sys.argv[1])