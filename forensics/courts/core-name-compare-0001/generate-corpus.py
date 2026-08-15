#!/usr/bin/env python3
"""generate-corpus.py — deterministic pair corpus for CORE-NAME-COMPARE-0001.

Regenerate with: python3 generate-corpus.py > inputs/pairs.txt
"""


def esc(label: bytes) -> str:
    # Present label bytes via decimal escapes so every octet survives text.
    out = []
    for b in label:
        if b in b'."\\()$@; ' or b < 0x21 or b > 0x7e:
            out.append(f"\\{b:03d}")
        else:
            out.append(chr(b))
    return "".join(out)


names = [
    ".",
    "com.",
    "example.com.",
    "www.example.com.",
    "a.b.example.com.",
    "z.com.",
    "a.example.com.",
    "b.example.com.",
    "org.",
    "example.org.",
    "ExAmPle.COM.",
    "WWW.Example.COM.",
    "net.",
    "co.uk.",
    "example.co.uk.",
    "a.b.c.d.e.f.example.com.",
    "example.",
    "EXAMPLE.",
    "\\065.example.",   # A.example.
    "\\097.example.",   # a.example.
]

pairs = []
for a in names:
    for b in names:
        pairs.append(f"{a}|{b}")

# Case-folded pairs with non-ASCII octets.
octets = [b"\\000", b"\\127", b"\\128", b"\\255", b"\\065", b"\\097"]
for x in octets:
    for y in octets:
        pairs.append(f"{x}.example.|{y}.example.")

# Subdomain/contains boundary pairs.
pairs += [
    "com.|com.",
    "com.|example.com.",
    "example.com.|com.",
    "a.example.com.|example.com.",
    "example.com.|a.example.com.",
    "a.b.c.|a.b.",
    "a.b.|a.b.c.",
    "x.y.z.|a.b.c.",
    "example.com.|example.com.",
]

seen = set()
out = []
for p in pairs:
    if p not in seen:
        seen.add(p)
        out.append(p)
for p in out:
    print(p)
