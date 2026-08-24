#!/bin/bash
# verify-session.sh — automated self-check that mcwire walks the full foreign
# stack against the shipped mcpeer oracle.
#
# Proves (with only this repo's components):
#   mDNS discovery -> TCP browser flow (hello/echo/INVITE/caps/connect
#   plists/receipts) -> identity/ICE start on the advertised ports.
# Note: MC-level Connected requires the unmodified app's .optional channel
# (see docs/evidence/R49-live-session.md, docs/d0xx-tls.md) — the walk below
# validates everything up to that gate, and the oracle's own log shows the
# foreign peer's INVITE arriving (its first acceptance step).
#
# Usage:  ./tools/verify-session.sh [service-type]
#         (service type defaults to mc-probe; run from the repo root)
set -u
SVC="${1:-mc-probe}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORACLE_LOG=$(mktemp -t mcpeer-oracle)
CLIENT_LOG=$(mktemp -t mcwire-client)
PYBIN="${MCWIRE_PY:-}"
if [ -z "$PYBIN" ]; then
    if [ -x "$ROOT/.venv/bin/python" ]; then
        PYBIN="$ROOT/.venv/bin/python"
    else
        echo "creating repo venv (zeroconf/cryptography/pyOpenSSL)..."
        python3 -m venv "$ROOT/.venv" || exit 1
        "$ROOT/.venv/bin/pip" install -q zeroconf cryptography pyopenssl || exit 1
        PYBIN="$ROOT/.venv/bin/python"
    fi
fi
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

echo "== verify-session: SVC=$SVC =="

# 1. build the oracle (needs macOS + MultipeerConnectivity)
echo "[1/4] building mcpeer oracle..."
(cd "$ROOT" && swift build >/dev/null 2>&1)
ORACLE="$ROOT/.build/debug/mcpeer"
if [ ! -x "$ORACLE" ]; then echo "FAIL: mcpeer build"; exit 1; fi

# 2. start the oracle (advertiser)
echo "[2/4] starting oracle (advertise $SVC)..."
"$ORACLE" advertise "$SVC" --name ORACLE > "$ORACLE_LOG" 2>&1 &
ORACLE_PID=$!
trap 'kill $ORACLE_PID 2>/dev/null' EXIT
sleep 2
grep -q "ADVERTISE type=$SVC" "$ORACLE_LOG" || { echo "FAIL: oracle did not advertise"; exit 1; }

# 3. run the foreign client (browser role)
echo "[3/4] running mcwire (browser) from $PYBIN..."
"$PYBIN" -u -m mc.run --role browser --service "$SVC" > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 30
kill $CLIENT_PID 2>/dev/null; wait $CLIENT_PID 2>/dev/null

# 4. assert the stack markers
echo "[4/4] checking evidence..."
ok=0; fail=0
chk() { if grep -q -e "$1" "$2"; then ok=$((ok+1)); echo "  ✓ $1"; else fail=$((fail+1)); echo "  ✗ $1"; fi; }
chk "connected to advertiser" "$CLIENT_LOG"
chk "-> hello1" "$CLIENT_LOG"
chk "their greeting" "$CLIENT_LOG"
chk "-> echo16" "$CLIENT_LOG"
chk "-> INVITE #1" "$CLIENT_LOG"
chk "-> caps #2" "$CLIENT_LOG"
chk "their connect plist" "$CLIENT_LOG"
chk "our connect" "$CLIENT_LOG"
chk "tokens published to global ICE service" "$CLIENT_LOG"
chk "bound ports" "$CLIENT_LOG"
chk "INVITE from PYSRV" "$ORACLE_LOG"

echo
echo "passed=$ok failed=$fail"
echo "logs: oracle=$ORACLE_LOG client=$CLIENT_LOG"
[ "$fail" -eq 0 ] && echo "RESULT: PASS" || { echo "RESULT: FAIL (see docs/evidence/R49-live-session.md for the full-app run)"; exit 1; }
