#!/bin/bash
# capture-run.sh — run controlled MC sessions while capturing raw traffic.
# Requires root for BPF capture. Run as:  sudo ./tools/capture-run.sh [outdir]
# Runs three scenarios (~15s each): plaintext, plaintext+discoveryInfo, encryption-required.
set -u
cd "$(dirname "$0")/.."
OUT="${1:-caps}"
BIN=.build/debug/mcpeer
mkdir -p "$OUT"
PIDS=()
if [ "$(id -u)" = 0 ]; then TCPDUMP=tcpdump; else TCPDUMP="sudo -n tcpdump"; fi

stop_capture() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; PIDS=(); }

run_scenario() {
    local name="$1"; shift
    local dir="$OUT/$name"
    mkdir -p "$dir"
    echo "===== scenario: $name ====="
    for IF in lo0 en0 en1 awdl0; do
        if ifconfig "$IF" >/dev/null 2>&1; then
            $TCPDUMP -i "$IF" -s 0 -w "$dir/$IF.pcap" 'tcp or udp' >/dev/null 2>&1 &
            PIDS+=($!)
            echo "  capturing $IF"
        fi
    done
    sleep 1
    "$BIN" advertise mc-probe --name ALICE --bytes 33 --period 0.5 "$@" > "$dir/alice.log" 2>&1 &
    local APID=$!
    sleep 2
    "$BIN" browse mc-probe --name BOB --bytes 33 --period 0.5 > "$dir/bob.log" 2>&1 &
    local BPID=$!
    sleep 12
    kill $APID $BPID 2>/dev/null
    stop_capture
    sleep 1
    echo "  saved -> $dir/  (bob saw: $(grep -c FOUND "$dir/bob.log" 2>/dev/null) FOUND, connected: $(grep -c 'STATE.*2' "$dir/bob.log" 2>/dev/null))"
}

run_scenario plain-none
run_scenario plain-info  --info "k1=v1,k2=v2"
run_scenario required    --required
echo "ALL DONE -> $OUT"
ls -R "$OUT" | sed -n '1,60p'