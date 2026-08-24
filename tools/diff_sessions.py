#!/usr/bin/env python3
"""diff_sessions.py — compare two capture dirs (caps vs caps2) to find which
MCSession wire bytes are per-session VARIABLE (must be regenerated per peer)
vs INVARIANT (can ship as template).

Usage: diff_sessions.py caps caps2
"""
import sys, plistlib
from decode_mc import reassembled_flows, split_messages

def collect(scen):
    out = []
    import glob, os
    for pcap in glob.glob(os.path.join(scen, "*", "lo0.pcap")) + glob.glob(os.path.join(scen, "lo0.pcap")):
        for key, (a, b) in reassembled_flows(pcap).items():
            if not a.startswith(b"\x07\xd0"):
                continue
            for tag, stream in (("ADV", a), ("BRW", b)):
                for op, m in split_messages(stream):
                    if op == 0x0834 and len(m) > 100 and b"bplist00" in m:
                        out.append((tag, m[16:]))
    return out

def diff(a_dir, b_dir):
    A, B = collect(a_dir), collect(b_dir)
    if not A or not B:
        print("need two captures with plist messages (run capture-run.sh twice)")
        return
    for (tA, pA), (tB, pB) in zip(A, B):
        objA = plistlib.loads(pA)
        objB = plistlib.loads(pB)
        print(f"\n--- {tA} plist: session A vs B ---")
        for k in sorted(set(objA) | set(objB)):
            va, vb = objA.get(k), objB.get(k)
            same = va == vb
            if isinstance(va, bytes):
                print(f"  {k}: {'SAME' if same else 'DIFF'} "
                      f"A={va[:32].hex()}{'…' if len(va) > 32 else ''} "
                      f"B={vb[:32].hex()}{'…' if len(vb) > 32 else ''}")
            else:
                print(f"  {k}: {'SAME' if same else 'DIFF'} A={va!r} B={vb!r}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: diff_sessions.py caps caps2")
        sys.exit(1)
    diff(sys.argv[1], sys.argv[2])