#!/bin/sh
# compare.sh — CAP-PROBE-0001: byte-exact stdout comparison.
set -eu
oracle="$(dirname "$0")/captures/oracle/stdout.txt"
rust="$(dirname "$0")/captures/rust/stdout.txt"
if cmp -s "$oracle" "$rust"; then
    rm -f "$(dirname "$0")/residuals.json"
    echo "0 residuals"
    exit 0
fi
python3 - "$(dirname "$0")" << 'PYEOF'
import json, os, sys
court = sys.argv[1]
o = open(os.path.join(court, "captures/oracle/stdout.txt")).read().splitlines()
r = open(os.path.join(court, "captures/rust/stdout.txt")).read().splitlines()
n = max(len(o), len(r))
residuals = []
cid = os.path.basename(court)
for i in range(n):
    a = o[i] if i < len(o) else ""
    b = r[i] if i < len(r) else ""
    if a != b:
        residuals.append({
            "schema_version": 1,
            "residual_id": f"RESIDUAL-{cid}-{i + 1:04d}",
            "court_id": cid,
            "kind": "TEXT",
            "oracle_raw": a,
            "rust_raw": b,
            "classification": "unknown",
            "explanation": "",
        })
with open(os.path.join(court, "residuals.json"), "w") as f:
    json.dump(residuals, f, indent=2)
print(f"{len(residuals)} residuals")
sys.exit(0)
PYEOF
