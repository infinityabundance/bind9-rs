#!/usr/bin/env python3
"""per-case diff for the CLI-DIG courts: split both captures on the
'### CASE n:' markers and report, per case, the first differing normalized
lines.  Normalization mirrors compare-dig.sh (ids, query time, WHEN,
client cookie)."""
import os
import re
import sys

court_dir = sys.argv[1]
max_cases = int(sys.argv[2]) if len(sys.argv) > 2 else 10**9


def read(side):
    with open(os.path.join(court_dir, "captures", side, "stdout.txt"),
              encoding="utf-8", errors="replace") as f:
        return f.read()


def norm(t):
    lines = []
    in_dump = False
    for line in t.splitlines():
        if in_dump and re.match(r"^[0-9a-f]{2} [0-9a-f]{2} ", line):
            line = re.sub(r"^[0-9a-f]{2} [0-9a-f]{2} ", "nn nn ", line)
            if len(line) > 59:
                line = line[:57] + ".." + line[59:]
            in_dump = False
        elif line.startswith(";; Got bad packet:"):
            in_dump = True
        t = line
        t = re.sub(r"id: \d+", "id: N", t)
        t = re.sub(r";; Query time: \d+ (msec|usec)", ";; Query time: N", t)
        t = re.sub(r";; WHEN: .*", ";; WHEN: <date>", t)
        t = re.sub(r"; COOKIE: [0-9a-f]{16}", "; COOKIE: <cookie>", t)
        lines.append(t)
    return "\n".join(lines)


def cases(t):
    out = {}
    cur = None
    for line in t.splitlines():
        m = re.match(r"^### CASE (\d+):", line)
        if m:
            cur = int(m.group(1))
            out[cur] = [line]
        elif cur is not None:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


o = cases(norm(read("oracle")))
r = cases(norm(read("rust")))
for k in sorted(set(o) & set(r)):
    if k > max_cases:
        break
    if o[k] == r[k]:
        continue
    ol, rl = o[k].splitlines(), r[k].splitlines()
    n = max(len(ol), len(rl))
    diffs = []
    for i in range(n):
        a = ol[i] if i < len(ol) else "<EOF>"
        b = rl[i] if i < len(rl) else "<EOF>"
        if a != b:
            diffs.append((i + 1, a, b))
    print(f"=== CASE {k}: {diffs[0][1][:50]!r}")
    for i, a, b in diffs[:6]:
        print(f"  L{i} O: {a[:90]!r}")
        print(f"  L{i} R: {b[:90]!r}")
