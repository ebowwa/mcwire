#!/bin/bash
# dns-sd-lookup.sh — observe MC's real Bonjour records WITHOUT root.
# Usage: ./dns-sd-lookup.sh <type> [instance]
# Without instance: browse (-B) for 8s to list service instances, then -L the first.
TYPE="$1"; INST="$2"
if [ -z "$TYPE" ]; then echo "usage: $0 <service-type> [instance-name]"; exit 1; fi
if [ -z "$INST" ]; then
    echo "== browse _${TYPE}._tcp for 8s =="
    timeout 8 dns-sd -B "_${TYPE}._tcp" local 2>&1 | grep -v "Timestamp" &
    BPID=$!
    sleep 3
    INST=$(ps aux | grep "[d]ns-sd -B" >/dev/null; :)
    wait "$BPID"
    # second pass: capture the instance name cleanly
    INST=$(timeout 8 dns-sd -B "_${TYPE}._tcp" local 2>/dev/null | awk '/Add/{print $4; exit}')
    echo "instance=$INST"
fi
if [ -n "$INST" ]; then
    echo "== lookup ${INST}._${TYPE}._tcp =="
    timeout 8 dns-sd -L "$INST" "_${TYPE}._tcp" local 2>&1 | grep -v "Timestamp"
fi