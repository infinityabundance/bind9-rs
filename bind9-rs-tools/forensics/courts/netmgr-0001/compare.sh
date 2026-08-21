#!/bin/sh
# compare.sh — NETMGR-0001: byte-exact stdout + stderr + exit comparison.
set -eu
court="$(dirname "$0")"
cid=$(basename "$court")

o_out="$court/captures/oracle/stdout.txt"
r_out="$court/captures/rust/stdout.txt"
o_err="$court/captures/oracle/stderr.txt"
r_err="$court/captures/rust/stderr.txt"
o_exit="$court/captures/oracle/exit.txt"
r_exit="$court/captures/rust/exit.txt"

fail=0
cmp -s "$o_out" "$r_out" || fail=1
cmp -s "$o_err" "$r_err" || fail=1
cmp -s "$o_exit" "$r_exit" || fail=1

if [ "$fail" -eq 0 ]; then
    rm -f "$court/residuals/summary.json"
    echo "0 residuals"
    exit 0
fi

python3 - "$court" << 'PYEOF'
import json, os, sys
court = sys.argv[1]
cid = os.path.basename(court)
def lines(p):
    try:
        return open(p, "rb").read().splitlines()
    except FileNotFoundError:
        return []
pairs = [
    ("stdout", "captures/oracle/stdout.txt", "captures/rust/stdout.txt"),
    ("stderr", "captures/oracle/stderr.txt", "captures/rust/stderr.txt"),
    ("exit",   "captures/oracle/exit.txt",   "captures/rust/exit.txt"),
]
residuals = []
for surface, op, rp in pairs:
    o = lines(os.path.join(court, op))
    r = lines(os.path.join(court, rp))
    n = max(len(o), len(r))
    for i in range(n):
        a = o[i] if i < len(o) else b""
        b = r[i] if i < len(r) else b""
        if a != b:
            residuals.append({
                "schema_version": 1,
                "residual_id": f"{cid}-{surface.upper()}-{i + 1:04d}",
                "kind": "line-mismatch",
                "description": f"line {i + 1} of {surface} differs",
                "oracle": a.decode("utf-8", "replace"),
                "rust": b.decode("utf-8", "replace"),
            })
os.makedirs(os.path.join(court, "residuals"), exist_ok=True)
with open(os.path.join(court, "residuals", "summary.json"), "w") as f:
    json.dump({
        "schema_version": 1,
        "court_id": cid,
        "count": len(residuals),
        "residuals": residuals,
    }, f, indent=2)
print(f"{len(residuals)} residuals")
# Dependency-court pattern: the comparator writes the §13 residuals and
# exits 0 so the bind9-court runner's compare_custom() reads
# residuals/summary.json and reports them; a green run removes the file.
sys.exit(0)
PYEOF
