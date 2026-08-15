#!/usr/bin/env python3
"""generate-corpus.py — deterministic name-render corpus for RENDER-COMPRESS-*.

Regenerate with: python3 generate-corpus.py > inputs/names.txt

The corpus is a *sequence* of names rendered into one shared message buffer
with a persistent compressor — order matters.  It exercises:

- suffix chains (a name followed by a longer name sharing its suffix);
- repeated names (full-name pointer);
- case variants (case-insensitive matching by default; DNS_COMPRESS_CASE);
- single-label names and the root;
- escaped octets (\\DDD decimal escapes);
- deep names;
- names near the 255-octet wire limit;
- more than 48 distinct names, so the 64-slot default table hits its 75%
  load cap while the 1024-slot DNS_COMPRESS_LARGE table does not
  (observable difference in later names' compression).
"""


def esc(label: bytes) -> str:
    out = []
    for b in label:
        if b in b'."\\()$@; ' or b < 0x21 or b > 0x7e:
            out.append(f"\\{b:03d}")
        else:
            out.append(chr(b))
    return "".join(out)


def main():
    names = []

    # Suffix chains — the classic compression relationships.
    chains = [
        ["example.com."],
        ["www.example.com.", "mail.example.com.", "a.www.example.com."],
        ["org."],
        ["example.org.", "deep.a.b.c.example.org."],
        ["net."],
        ["co.uk.", "example.co.uk.", "www.example.co.uk."],
        ["example.net.", "ns1.example.net.", "ns2.example.net."],
    ]
    for c in chains:
        names.extend(c)

    # Repeated names and case variants.
    names += [
        "example.com.",
        "EXAMPLE.COM.",
        "ExAmPlE.CoM.",
        "example.com.",
        "WWW.EXAMPLE.COM.",
        "www.example.com.",
    ]

    # Single labels and the root.
    names += ["com.", "org.", "net.", "info.", ".", "com.", "localhost."]

    # Escaped octets.
    names += [
        "\\065.example.",     # A.example.
        "\\097.example.",     # a.example.
        "\\000.example.",     # NUL octet in a label
        "\\127.example.",
        "\\128.example.",     # high bit set
        "\\255.example.",
        "semi\\059colon.example.",
        "space\\032name.example.",
    ]

    # Deep names.
    names += [
        "a.b.c.d.e.f.g.h.example.com.",
        "1.2.3.4.5.6.7.8.example.org.",
        "x.y.z.w.v.u.t.s.r.q.p.example.net.",
    ]

    # Long names approaching the 255-octet wire limit.
    long_label = "l" * 60
    names += [
        f"{long_label}.{long_label}.{long_label}.example.com.",
        f"{long_label}.{long_label}.{long_label}.{long_label}.org.",
    ]

    # A large fan-out of distinct names sharing the ".test." suffix — enough
    # (with the above) to exceed the 48-entry load cap of the small table.
    for i in range(0, 100):
        names.append(f"host{i:03d}.test.")

    # Suffix-sharing after the fan-out: these must compress against the
    # earlier names when the table still accepts entries.
    names += [
        "host007.test.",
        "www.host007.test.",
        "final.example.com.",
    ]

    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    for n in out:
        print(n)


if __name__ == "__main__":
    main()
