#!/bin/sh
# harness.sh — court CLI-DIG-0002
#
# Starts the deterministic responder on 127.0.0.1:5333, runs the dig cases
# against it, then stops it.  The oracle side uses --network host.
#
# Usage: harness.sh <oracle|rust>

set -eu

side=$1
court_dir=$(dirname "$0")
runner="$court_dir/../common/run-dig.sh"
responder="$court_dir/../common/dns-responder.py"
port=5333

log=$(mktemp)
trap 'rm -f "$log"; if [ -n "${rpid:-}" ]; then kill "$rpid" 2>/dev/null || true; wait "$rpid" 2>/dev/null || true; fi' EXIT

python3 "$responder" "$port" "$log" &
rpid=$!
# Give the previous side's responder (if any) time to release the port.
sleep 0.5

# Wait for the responder to accept UDP.
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

# Emit the responder's outbound-query log as the last record so query-path
# parity is visible in the capture.
echo "### RESPONDER QUERY LOG"
cat "$log"
