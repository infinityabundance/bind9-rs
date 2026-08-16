#!/bin/sh
# harness.sh — court CLI-DIG-0003 (IDN behavior; libidn2-enabled oracle).
#
# Usage: harness.sh <oracle|rust>

set -eu

side=$1
court_dir=$(dirname "$0")
runner="$court_dir/../common/run-dig.sh"
responder="$court_dir/../common/dns-responder.py"
port=5333

# The IDN court compares against the libidn2-enabled oracle build and pins
# a UTF-8 locale (see common/run-dig.sh for the locale archaeology).
export ORACLE_IMAGE=oracle-bind-9.20.26-idn
export LANG=C.UTF-8

log=$(mktemp)
trap 'rm -f "$log"; if [ -n "${rpid:-}" ]; then kill "$rpid" 2>/dev/null || true; wait "$rpid" 2>/dev/null || true; fi' EXIT

python3 "$responder" "$port" "$log" &
rpid=$!
sleep 0.5

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
q = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + b'\x00\x00\x01\x00\x01'
try:
    s.sendto(q, ('127.0.0.1', $port))
    s.recvfrom(512)
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

sh "$runner" "$side" "$court_dir/inputs/cases.txt"

echo "### RESPONDER QUERY LOG"
cat "$log"
