#!/bin/bash
# verify-session.sh — one-command proof that the foreign client (mcwire)
# joins a REAL MultipeerConnectivity session, using only this repo's
# components (mcoracle: a real MCSession/.optional channel).
#
# Asserts BOTH sides:
#   foreign side (mcwire):   discovery -> TCP browser flow -> ICE ->
#                            DTLS handshake COMPLETE -> c1xx identity
#                            COMPLETE -> JSON channel up (app's hello
#                            envelope decoded)
#   oracle side  (mcoracle): MCSession state connected + the app's own
#                            "→ CONNECTED peer=PYSRV" verdict
#
# Usage:  ./tools/verify-session.sh [service-type]   (default secondsee-mpc)
# Env:    MCWIRE_PY to override the python interpreter
# Needs:  macOS + Xcode toolchain (swift build) + python3 (venv auto-created)
set -u
SVC="${1:-secondsee-mpc}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORACLE_LOG=$(mktemp -t mcoracle)
CLIENT_LOG=$(mktemp -t mcwire)
RUNS="${MCWIRE_RUNS:-1}"

echo "== verify-session: SVC=$SVC =="

# 1. python env (repo venv auto-provisioned)
PYBIN="${MCWIRE_PY:-}"
if [ -z "$PYBIN" ]; then
    if [ ! -x "$ROOT/.venv/bin/python" ]; then
        echo "[1/4] creating repo venv (zeroconf/cryptography/pyOpenSSL)..."
        python3 -m venv "$ROOT/.venv" || exit 1
        "$ROOT/.venv/bin/pip" install -q zeroconf cryptography pyopenssl || exit 1
    fi
    PYBIN="$ROOT/.venv/bin/python"
fi
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

# 2. build the oracle
echo "[2/4] building mcoracle (real MCSession, .optional)..."
(cd "$ROOT" && swift build >/dev/null 2>&1)
ORACLE="$ROOT/.build/debug/mcoracle"
if [ ! -x "$ORACLE" ]; then echo "FAIL: mcoracle build"; exit 1; fi

# 3. run oracle + foreign client
echo "[3/4] oracle up, running mcwire browser x$RUNS..."
"$ORACLE" "$SVC" > "$ORACLE_LOG" 2>&1 &
ORACLE_PID=$!
trap 'kill $ORACLE_PID 2>/dev/null' EXIT
sleep 2
grep -q "mcoracle up" "$ORACLE_LOG" || { echo "FAIL: oracle did not start"; cat "$ORACLE_LOG"; exit 1; }

for r in $(seq 1 "$RUNS"); do
    "$PYBIN" -u -m mc.run --role browser --service "$SVC" >> "$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
    sleep 30
    kill $CLIENT_PID 2>/dev/null; wait $CLIENT_PID 2>/dev/null
done

# 4. assert both sides' evidence
echo "[4/4] checking evidence..."
ok=0; fail=0
chk() { if grep -q -e "$1" "$2"; then ok=$((ok+1)); echo "  ✓ $3"; else fail=$((fail+1)); echo "  ✗ $3"; fi; }

echo " foreign side (mcwire):"
chk "connected to advertiser" "$CLIENT_LOG" "mDNS discovery + TCP dial"
chk "-> hello1"               "$CLIENT_LOG" "browser flow: hello1"
chk "their greeting"          "$CLIENT_LOG" "peer greeting parsed (identity system)"
chk "-> INVITE #1"            "$CLIENT_LOG" "invitation sent"
chk "their connect plist"     "$CLIENT_LOG" "connect plist received"
chk "tokens published to global ICE service" "$CLIENT_LOG" "ICE service armed"
chk "HANDSHAKE COMPLETE"      "$CLIENT_LOG" "DTLS handshake complete (AECDH-anon)"
chk "identity exchange COMPLETE" "$CLIENT_LOG" "c1xx identity exchange complete"
chk "JSON channel up"         "$CLIENT_LOG" "app-level JSON channel up"
chk "kind': 'hello'"          "$CLIENT_LOG" "the app's hello JSON envelope decoded"

echo " oracle side (real MCSession):"
chk "INVITE from PYSRV"       "$ORACLE_LOG" "foreign invitation received + accepted"
chk "state connected peers="  "$ORACLE_LOG" "MCSession state: connected"
chk "CONNECTED peer=PYSRV"    "$ORACLE_LOG" "app-side verdict: foreign peer Connected"

echo
echo "passed=$ok failed=$fail"
echo "logs: oracle=$ORACLE_LOG client=$CLIENT_LOG"
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS — foreign client joined a real MCSession end-to-end"
else
    echo "RESULT: FAIL"
    exit 1
fi