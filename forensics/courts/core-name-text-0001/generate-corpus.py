#!/usr/bin/env python3
"""generate-corpus.py — deterministic corpus generator for court
CORE-NAME-TEXT-0001 (and the wire court).

The corpus is generated from a fixed seed-free enumeration so the fixture is
reproducible: every byte value 0..255 appears inside a label via \\DDD
decimal escapes, plus hand-written edge cases from the archaeology
(lib/dns/name.c dns_name_fromtext).

Regenerate with: python3 generate-corpus.py > inputs/names.txt
"""

import sys

cases = []

# Hand-written edge cases (archaeology-derived).
cases += [
    ".",
    "example.com.",
    "www",
    "ExAmPle.COM.",
    "www.example.com",
    "@",
    "a..b",
    ".a.",
    "a.",
    ".a",
    "a..",
    "..",
    "\\.",
    "\\097.example.",
    "\\010.example.",
    "\\000.example.",
    "\\127.example.",
    "\\255.example.",
    "\\256.example.",
    "\\999.example.",
    "a\\",
    "a\\1",
    "a\\12",
    "a\\123",
    "a\\.b.example.",
    "a\\;b\\@c\\$d\\(e\\)f.example.",
    "a\\\"b.example.",
    "a\\\\b.example.",
    "a-b_c0.example.",
    "-leading.example.",
    "trailing-.example.",
    "0123456789.example.",
    "xn--bcher-kva.example.",
    "a" * 63 + ".example.",
    "a" * 64 + ".example.",
    "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61 + ".",
    "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62 + ".",
    "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".",
    "\\" + "0".join([]) + "065.example.",
    "\\065",  # decimal 65 = 'A'
    "\\097" * 30 + ".example.",
]

# Byte sweep: every byte 0..255 as a \\DDD decimal escape, standalone and
# embedded.  Byte 0 is allowed (the archaeology showed \\000 is accepted).
for b in range(256):
    esc = f"\\{b:03d}"
    cases.append(esc + ".example.")
    cases.append("x" + esc + "y.example.")

# Escape-of-every-printable and special handling.
for c in ".\"\\()$@; '~!*+=<>[]{}|^`#&%-_":
    cases.append("pre\\" + c + "post.example.")

# Origin-relative semantics.
cases += [
    "www",
    "a.b",
    "a.b.",
]

# Deduplicate while preserving order.
seen = set()
out = []
for c in cases:
    if c not in seen:
        seen.add(c)
        out.append(c)

for c in out:
    print(c)
