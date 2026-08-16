#!/usr/bin/env python3
"""generate-corpus.py — deterministic RDATA corpus for WIRE-RDATA-0001.

Regenerate with: python3 generate-corpus.py > inputs/cases.txt

Each line is `<type-mnemonic> <rdata text>`.  The corpus covers the
implemented type set (A, AAAA, NS, CNAME, PTR, SOA, MX, TXT, SRV, MINFO,
RP, unknown) plus deliberately malformed cases whose error codes are part
of the surface: out-of-range values, truncated fields, bad escapes, bad
hex, wrong field counts, and RFC 3597 `\\#` forms.
"""


def main():
    cases = []

    # A
    cases += [
        "A 192.0.2.1",
        "A 0.0.0.0",
        "A 255.255.255.255",
        "A 1.2.3.4",
        "A 192.0.2.256",       # out of range
        "A 192.0.2",           # too few octets
        "A 1.2.3.4.5",         # too many octets
        "A 1.2.3.4.extra",     # trailing garbage
        "A 1.2.3.4.",
        "A not-an-address",
        "A 1.2.3.04",          # leading zero octet
    ]

    # AAAA
    cases += [
        "AAAA 2001:db8::1",
        "AAAA ::",
        "AAAA ::1",
        "AAAA 2001:db8:0:0:0:0:2:1",
        "AAAA 2001:db8::2:1",
        "AAAA fe80::1%eth0",   # zone index (BIND result code is the surface)
        "AAAA 12345::1",       # out-of-range hextet
        "AAAA 1:2:3:4:5:6:7:8:9",  # too many hextets
        "AAAA not-ipv6",
        "AAAA 2001:db8:::1",   # double separator
        "AAAA ::ffff:192.0.2.1",  # v4-mapped
    ]

    # NS / CNAME / PTR (single-name types)
    for t in ["NS", "CNAME", "PTR"]:
        cases += [
            f"{t} ns1.example.com.",
            f"{t} ns1.example.com",      # relative, resolved vs root
            f"{t} .",
            f"{t} a.b.c.d.e.f.g.h.i.j.k.l.example.net.",
        ]
    cases += [
        "NS ns1.example.com..",   # empty label
        "NS ..example.com.",
        "CNAME \\097.example.com.",  # 'a' escaped
        "PTR in-addr.arpa.",
    ]

    # SOA
    cases += [
        "SOA ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300",
        "SOA ns1.example.com. hostmaster.example.com. 0 0 0 0 0",
        "SOA ns1.example.com. hostmaster.example.com. 4294967295 2147483647 2147483647 2147483647 2147483647",
        "SOA ns1.example.com. hostmaster.example.com. 4294967296 1 1 1 1",  # serial overflow
        "SOA ns1.example.com. hostmaster.example.com. -1 1 1 1 1",          # negative serial
        "SOA ns1.example.com. hostmaster.example.com. 1 2 3 4",             # too few fields
        "SOA ns1.example.com. hostmaster.example.com. 1 2 3 4 5 6",         # too many fields
        "SOA ns1.example.com. hostmaster 1 2 3 4 5",                        # relative mname
    ]

    # MX
    cases += [
        "MX 10 mail.example.com.",
        "MX 0 example.com.",
        "MX 65535 example.com.",
        "MX 65536 example.com.",   # preference overflow
        "MX -1 example.com.",
        "MX 10",                   # missing name
        "MX 10 20 30",             # extra field
    ]

    # TXT
    cases += [
        "TXT \"hello\"",
        "TXT \"hello\" \"world\"",
        "TXT \"\"",
        "TXT hello",
        "TXT \"with \\\"quotes\\\"\"",
        "TXT \"with \\097 escapes\"",
        "TXT \"with ; comment chars\"",
        "TXT \"a\" \"b\" \"c\" \"d\" \"e\"",
        "TXT \\000",               # NUL octet via escape
        "TXT \"unterminated",
        "TXT \\097\\098\\099",
        "TXT \"dots.in.string\"",
    ]

    # SRV
    cases += [
        "SRV 1 2 5060 sip.example.com.",
        "SRV 0 0 0 example.com.",
        "SRV 65535 65535 65535 example.com.",
        "SRV 65536 0 0 example.com.",   # priority overflow
        "SRV 0 0 65536 example.com.",   # port overflow
        "SRV 0 0 -1 example.com.",
        "SRV 1 2 5060",                 # missing target
    ]

    # MINFO / RP (two-name types)
    cases += [
        "MINFO rmbox.example.com. embx.example.com.",
        "MINFO . .",
        "RP admin.example.com. txt.example.com.",
        "RP . .",
        "RP admin.example.com.",        # missing second name
    ]

    # Unknown types (RFC 3597 generic form)
    cases += [
        "TYPE65280 \\# 4 01020304",
        "TYPE65280 \\# 0",
        "TYPE65280 \\# 4 0102030405",    # hex length mismatch
        "TYPE65280 \\# 4 0102",          # too few hex digits
        "TYPE65280 \\# 4 zz0102",        # non-hex
        "TYPE65280 \\# 65535 01",        # length beyond buffer
        "TYPE0 \\# 1 00",
        "TYPE123 \\# 2 00ff",
        "TYPE65280 \\#",                 # missing length
        # Known types via the generic form: validated as real wire data
        # (rdata_validate), and rendered with the type's own totext.
        "TYPE1 \\# 4 01020304",
        "TYPE1 \\# 1 00",                # too short for A
        "TYPE1 \\# 5 0102030405",        # too long for A
        "TYPE16 \\# 1 00",               # empty TXT string
        "TYPE16 \\# 0",                  # zero-length TXT rdata
        "TYPE2 \\# 1 00",                # NS with garbage
        "TYPE6 \\# 22 01 02 03 04",      # SOA truncated
        "TYPE65280 \\# 0 00",            # token after \# 0
        # TXT \# special case: only a following number makes it generic
        "TXT \\# hello",
        "TXT \\# 2 00ff",
        "TXT \\#",
        # TTL-unit counters in SOA fields (bind_ttl syntax)
        "SOA ns1.example.com. hostmaster.example.com. 1 1h 2 3 4",
        "SOA ns1.example.com. hostmaster.example.com. 1 2w3d 2 3 4",
        "SOA ns1.example.com. hostmaster.example.com. 1 10000w 2 3 4",  # total overflow
        "SOA ns1.example.com. hostmaster.example.com. 1 4294967296 2 3 4",  # group overflow
        "SOA ns1.example.com. hostmaster.example.com. 1 1h2 2 3 4",   # plain after unit
        "SOA ns1.example.com. hostmaster.example.com. 1 x 2 3 4",     # non-digit counter
    ]

    seen = set()
    out = []
    for c in cases:
        if c not in seen:
            seen.add(c)
            out.append(c)
    for c in out:
        print(c)


if __name__ == "__main__":
    main()
