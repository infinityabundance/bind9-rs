#!/bin/sh
# compare-dig.sh — shared dig-court comparator with documented normalization.
#
# Normalization rules (each reason documented; the raw values stay in
# captures/oracle|rust/stdout.txt, §13):
#   NONDETERMINISTIC-1: DNS transaction ID in the `->>HEADER<<-` line and
#                       the +qr send block (`id: N`).
#   NONDETERMINISTIC-2: wall-clock `;; Query time: N msec`.
#   NONDETERMINISTIC-3: `;; WHEN: <locale date>`.
#   NONDETERMINISTIC-4: `; COOKIE: <16 hex>` client cookie in the +qr send
#                       block: dig generates a per-process 8-byte cookie from
#                       OS entropy (dighost.c `isc_nonce_buf(cookie_secret)`
#                       + `compute_cookie`); raw values are preserved in the
#                       captures; the invariant tested is `^[0-9a-f]{16}$`.
#   NONDETERMINISTIC-5: YAML `query_time`/`response_time` (`!!timestamp`
#                       ISO8601 with milliseconds): wall-clock values, raw
#                       in the captures; normalized to `!!timestamp <ts>`.
#   NONDETERMINISTIC-6: YAML `CLIENT: <16 hex>`: the same per-process client
#                       cookie as NONDETERMINISTIC-4; normalized to
#                       `CLIENT: <client>`.
#
# Usage: compare-dig.sh <court-dir>

set -eu
python3 - "$1" << 'PYEOF'
import json
import os
import re
import sys

court = sys.argv[1]


def read(side):
    with open(os.path.join(court, "captures", side, "stdout.txt"),
              encoding="utf-8", errors="replace") as f:
        return f.read()


def norm(t):
    lines = []
    in_dump = False
    for line in t.splitlines():
        if in_dump and re.match(r"^[0-9a-f]{2} [0-9a-f]{2} ", line):
            # NONDETERMINISTIC-1 also applies to the hex dump BIND prints for
            # a bad packet: its first two bytes are the random DNS ID, which
            # shows up in both the hex fields and the printable-ASCII column.
            line = re.sub(r"^[0-9a-f]{2} [0-9a-f]{2} ", "nn nn ", line)
            if len(line) > 59:
                line = line[:57] + ".." + line[59:]
            in_dump = False
        elif line.startswith(";; Got bad packet:"):
            in_dump = True
        t = line
        t = re.sub(r"id: \d+", "id: N", t)
        t = re.sub(r";; Query time: \d+ msec", ";; Query time: N msec", t)
        t = re.sub(r";; Query time: \d+ usec", ";; Query time: N usec", t)
        t = re.sub(r";; WHEN: .*", ";; WHEN: <date>", t)
        t = re.sub(r"; COOKIE: [0-9a-f]{16}", "; COOKIE: <cookie>", t)
        # NONDETERMINISTIC-5: YAML timestamps (wall clock, ms precision).
        t = re.sub(r"!!timestamp \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
                   "!!timestamp <ts>", t)
        # NONDETERMINISTIC-6: the YAML CLIENT cookie field.
        t = re.sub(r"CLIENT: [0-9a-f]{16}", "CLIENT: <client>", t)
        lines.append(t)
    return "\n".join(lines)
    # Note: the bad-packet dump's *first* line is "N bytes" (deterministic);
    # the hexdump lines follow.  A dump whose first line is a "N bytes" line
    # preceded by ";; Got bad packet:" is normalized above.


no, nr = norm(read("oracle")), norm(read("rust"))
res_path = os.path.join(court, "residuals.json")
if no == nr:
    if os.path.exists(res_path):
        os.unlink(res_path)
    print("0 residuals")
    sys.exit(0)

ol, rl = no.splitlines(), nr.splitlines()
n = max(len(ol), len(rl))
residuals = []
cid = os.path.basename(court)
for i in range(n):
    a = ol[i] if i < len(ol) else ""
    b = rl[i] if i < len(rl) else ""
    if a != b:
        residuals.append({
            "schema_version": 1,
            "residual_id": f"RESIDUAL-{cid}-{i + 1:04d}",
            "court_id": cid,
            "kind": "TEXT",
            "oracle_raw": a,
            "rust_raw": b,
            "normalized_oracle": None,
            "normalized_rust": None,
            "classification": "unknown",
            "explanation": "",
            "minimized_reproducer": None,
            "regression_invariant": None,
        })
with open(res_path, "w") as f:
    json.dump(residuals, f, indent=2)
print(f"{len(residuals)} residuals")
sys.exit(0)
PYEOF
