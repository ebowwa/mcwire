#!/bin/bash
# capture-cli-pair.sh — capture a REAL app-stack (multipeer-cli) pair that
# reaches .connected, so we can diff the connect-path against our synthetic
# client. Requires root (BPF). Usage: sudo ./capture-cli-pair.sh [outdir]
set -u
cd "$(dirname "$0")/.."
OUT="${1:-caps-cli}"
# The target app's headless MC runner (multipeer-cli). Point MULTIPEER_CLI at
# your locally built binary, or leave the default relative checkout path:
CLI="${MULTIPEER_CLI:-../secondsee/clients/publishers/swift/macos/.build/debug/multipeer-cli}"
if [ ! -x "$CLI" ] && [ -z "${MULTIPEER_CLI:-}" ]; then
  CLI="$(cd "../secondsee/clients/publishers/swift/macos" && swift build --product multipeer-cli 2>/dev/null >/dev/null; pwd)/.build/debug/multipeer-cli"
fi
mkdir -p "$OUT"
PIDS=()
stop_cap() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; PIDS=(); }
for IF in lo0 en0 awdl0; do
    [ -n "$(ifconfig "$IF" 2>/dev/null)" ] && { tcpdump -i "$IF" -s 0 -w "$OUT/$IF.pcap" 'udp or tcp' >/dev/null 2>&1 & PIDS+=($!); }
done
sleep 1
"$CLI" < /dev/null > "$OUT/cliA.log" 2>&1 & A=$!
sleep 2
"$CLI" < /dev/null > "$OUT/cliB.log" 2>&1 & B=$!
sleep 15
kill $A $B 2>/dev/null
stop_cap
echo "done -> $OUT"
echo "connected state seen:"
grep -h "connected(" "$OUT"/cli?.log | head -4