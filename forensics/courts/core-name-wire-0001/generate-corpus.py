#!/usr/bin/env python3
"""generate-corpus.py — deterministic corpus generator for court
CORE-NAME-WIRE-0001.

Each line: "<hex-wire> <offset>".  Hand-written cases from the archaeology
(dns_name_fromwire in lib/dns/name.c 9.20.26) plus systematic sweeps:

- valid names of every label count and length;
- every reserved length octet 64..191;
- pointer cases: valid back-pointers, chains, pointer-into-own-segment,
  forward pointers, self-pointers, loops;
- truncations at every position of a representative name;
- names exceeding 255 octets.

Regenerate with: python3 generate-corpus.py > inputs/wire.txt
"""


def h(b):
    return "".join(f"{x:02x}" for x in b)


cases = []

# Root and simple names.
cases.append(("00", 0))
cases.append((h([1, ord("a"), 0]), 0))
cases.append((h([3]) + "www".encode().hex() + h([0]), 0))
cases.append((h([3]) + "www".encode().hex() + h([7]) + "example".encode().hex() + h([3]) + "com".encode().hex() + h([0]), 0))
cases.append((h([63]) + (b"a" * 63).hex() + h([0]), 0))
cases.append((h([63]) + (b"a" * 63).hex() + h([63]) + (b"a" * 63).hex() + h([63]) + (b"a" * 63).hex() + h([61]) + (b"a" * 61).hex() + h([0]), 0))
# 4x63 = 256 octets > 255.
cases.append((h([63]) + (b"a" * 63).hex() + h([63]) + (b"a" * 63).hex() + h([63]) + (b"a" * 63).hex() + h([63]) + (b"a" * 63).hex() + h([0]), 0))
# Label lengths 64..191 (reserved prefixes).
for n in [0x40, 0x41, 0x7f, 0x80, 0x81, 0xbf]:
    cases.append((h([n]) + "abc".encode().hex(), 0))
# Empty label inside a name.
cases.append((h([1, ord("a"), 0, 1, ord("b"), 0]), 0))

# Compression: valid pointers.
# "a.b.c." at 0, pointer at 8 to 2.
cases.append((h([1, ord("a"), 1, ord("b"), 1, ord("c"), 0, 1, ord("x")]) + h([0xC0, 2]), 8))
# pointer to the root name (offset 6).
cases.append((h([1, ord("a"), 1, ord("b"), 1, ord("c"), 0, 1, ord("x")]) + h([0xC0, 6]), 8))
# chain: x -> b.c. -> c.
cases.append((h([1, ord("a"), 1, ord("b"), 1, ord("c"), 0, 1, ord("x")]) + h([0xC0, 2, 1, ord("y")]) + h([0xC0, 4]), 11))
# Pointer used as a full name.
cases.append((h([1, ord("a"), 1, ord("b"), 0]) + h([0xC0, 0]), 5))
# Pointer to the first label of a longer name (suffix compression).
cases.append((h([1, ord("a"), 1, ord("b"), 0]) + h([0xC0, 0]), 5))

# Malformed pointers (BIND: pointer >= marker → BADPOINTER).
cases.append(("c000", 0))          # self-pointer
cases.append(("c002c000", 0))      # two-pointer loop
cases.append((h([1, ord("a"), 0xC0, 0]), 0))    # pointer to 0 == segment start
cases.append((h([1, ord("a"), 0xC0, 1]), 0))    # pointer into the label body
cases.append((h([1, ord("a"), 0xC0, 2]), 2))    # pointer to own position
cases.append((h([1, ord("a"), 0xC0, 4, 1, ord("b"), 0]), 0))  # forward pointer
cases.append((h([1, ord("a"), 0xC0, 5]), 2))    # forward from offset 2
cases.append((h([1, ord("a"), 1, ord("b"), 0, 0xC0, 2]), 5))  # ptr to segment start after jump? (ptr at 5 to 2; segment started at 5 → 2 < 5 OK; target parse: 2: 1,b then 4: 0 root)
cases.append((h([1, ord("a"), 1, ord("b"), 0, 0xC0, 4]), 5))  # ptr to 4 (the root of a.b.) → segment 5; 4 < 5 OK → name = root? (parse at 4: 0 → root)

# Truncation sweep: every non-empty prefix of a representative name.
rep = h([3]) + "www".encode().hex() + h([7]) + "example".encode().hex() + h([3]) + "com".encode().hex() + h([0])
for i in range(1, len(rep) // 2):
    cases.append((rep[: i * 2], 0))

# Truncated pointer cases.
cases.append(("c0", 0))
cases.append((h([1, ord("a"), 0xC0]), 0))
cases.append((h([3]) + "www".encode().hex() + h([7]) + "example".encode().hex() + h([3]) + "com".encode().hex(), 0))  # no root

# Offsets beyond the buffer.
cases.append((h([0]), 1))
cases.append((h([1, ord("a"), 0]), 5))
cases.append((h([3]) + "www".encode().hex() + h([0]), 99))

# Pointer target parsing out-of-bounds: pointer at end of buffer.
cases.append((h([1, ord("a"), 0, 0xC0, 0]), 3))  # ptr at 3 to 0; buffer has 4 bytes; parse at 3: c0 00 → target 0 < 3 OK → a. consumed 5? buffer len 4 → consumed 5 > len? BIND: name parsed via target segment 0..2 then root at 2.
cases.append((h([1, ord("a"), 0, 0xC0, 0]), 4))  # ptr at 4: out of buffer → unexpected end

# Deduplicate, keep order.
seen = set()
out = []
for wire, off in cases:
    key = (wire, off)
    if key not in seen:
        seen.add(key)
        out.append(f"{wire} {off}")

for line in out:
    print(line)
