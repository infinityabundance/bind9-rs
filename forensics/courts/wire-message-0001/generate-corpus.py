#!/usr/bin/env python3
"""generate-corpus.py — WIRE-MESSAGE-0001 court corpus.

One wire-format DNS message per line (lowercase hex).  The battery covers
the `dns_message_parse` / `dns_message_render` surface courted by
WIRE-MESSAGE-0001: header fields, question semantics, per-section record
semantics (merging, singletons, class rules, question-only types, name
compression incl. pointers into the header), EDNS OPT placement and option
validation, TSIG/SIG(0)/TKEY placement, RRSIG covers, NSEC3 owner names,
dynamic-update meta classes, truncation and trailing garbage.  Every case
round-trips parse → render → reparse in the probe transcript.

Deterministic: no randomness, no timestamps.
"""

import struct

def name(labels):
    out = b""
    for lab in labels.split("."):
        if lab:
            out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"

def header(qd=0, an=0, ns=0, ar=0, flags=0, ident=0x1234):
    return struct.pack("!HHHHHH", ident, flags, qd, an, ns, ar)

def rr(ptr, rtype, rclass, ttl, rdata):
    return struct.pack("!HHHI", ptr, rtype, rclass, ttl) + struct.pack("!H", len(rdata)) + rdata

def q(labels, qtype=1, qclass=1):
    return name(labels) + struct.pack("!HH", qtype, qclass)

def opt(udp=4096, ext=0, ver=0, do=0, z=0, options=b""):
    ttl = ((ext & 0xff) << 24) | ((ver & 0xff) << 16) | ((do & 1) << 15) | (z & 0x7fff)
    return name("") + struct.pack("!HHIH", 41, udp, ttl, len(options)) + options

def o(code, data):
    return struct.pack("!HH", code, len(data)) + data

cases = []
Q = name("www.example.com")
Q2 = name("other.example.com")

# ---------------------------------------------------------------------------
# Header battery
# ---------------------------------------------------------------------------
for ident in (0x0000, 0x1234, 0xbeef, 0xffff):
    cases.append(header(ident=ident))
# opcodes 0..15 (qd=1 so the message is otherwise well-formed)
for op in range(16):
    cases.append(header(qd=1, flags=op << 11) + q("example.com"))
# rcodes 0..15
for rc in range(16):
    cases.append(header(qd=1, flags=rc) + q("example.com"))
# individual flag bits and combos
for fl in (0x8000, 0x0400, 0x0200, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010,
           0x8400, 0x86b0, 0x8ff0, 0x8000 | 0x0100 | 0x0080):
    cases.append(header(qd=1, flags=fl) + q("example.com"))
# section counts
for n in (0, 1, 2, 3):
    cases.append(header(qd=1, an=n, ns=n, ar=n) + q("example.com"))
cases.append(header(qd=65535) + q("example.com"))
# short messages
cases.append(b"")
cases.append(b"\x12\x34")
cases.append(header()[:11])

# ---------------------------------------------------------------------------
# Question battery
# ---------------------------------------------------------------------------
cases.append(header(qd=1) + q("example.com"))
cases.append(header(qd=1) + q("a.b.c.d.e.f.g.h.i.j.k.l.example.com"))
cases.append(header(qd=1) + q("www.example.com", 1, 1))
# qd=2 dup -> recoverable; same name diff type -> success; diff names -> recoverable
cases.append(header(qd=2) + q("example.com", 1, 1) + q("example.com", 1, 1))
cases.append(header(qd=2) + q("example.com", 1, 1) + q("example.com", 28, 1))
cases.append(header(qd=2) + q("example.com", 1, 1) + q("example.com", 1, 3))
cases.append(header(qd=2) + q("example.com", 1, 1) + q("other.example.com", 1, 1))
cases.append(header(qd=3) + q("example.com", 1, 1) + q("example.com", 28, 1) + q("example.com", 16, 1))
# update/notify class rules
for op in (4, 5):
    for cl in (254, 255):
        cases.append(header(qd=1, flags=op << 11) + q("example.com", 1, cl))
cases.append(header(qd=1, flags=5 << 11) + q("example.com", 1, 3))
cases.append(header(qd=1, flags=4 << 11) + q("example.com", 1, 254))
# question classes
for cl in (0, 1, 2, 3, 4, 5, 254, 255, 1000, 65535):
    cases.append(header(qd=1) + q("example.com", 1, cl))
# question types
for t in (0, 1, 28, 251, 252, 253, 254, 255, 128, 249, 65533, 65000):
    cases.append(header(qd=1) + q("example.com", t, 1))
# question name compression: pointer to the header (offset < 12) and loops
cases.append(header(qd=1) + name("a") + b"\xc0\x00" + struct.pack("!HH", 1, 1))
cases.append(header(qd=1) + b"\xc0\x0c" + struct.pack("!HH", 1, 1))
# truncated questions
cases.append(header(qd=1) + name("example.com") + b"\x00")
cases.append(header(qd=1) + name("example.com") + b"\x00\x01")
cases.append(header(qd=1) + b"\x63" + b"a" * 62 + b"\x00")
# empty-label name
cases.append(header(qd=1) + b"\x00" + struct.pack("!HH", 1, 1))

# ---------------------------------------------------------------------------
# Section battery
# ---------------------------------------------------------------------------
BASE = header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1)
# one record of each proven type
cases.append(BASE + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01"))
cases.append(BASE + rr(0xC00C, 28, 1, 300, b"\x20\x01\x0d\xb8" + b"\x00" * 12))
cases.append(BASE + rr(0xC00C, 2, 1, 300, name("ns1.example.com")))
cases.append(BASE + rr(0xC00C, 5, 1, 300, name("www.example.com")))
cases.append(BASE + rr(0xC00C, 12, 1, 300, name("www.example.com")))
cases.append(BASE + rr(0xC00C, 39, 1, 300, name("www.example.com")))
soa = name("ns1.example.com") + name("hostmaster.example.com") + struct.pack("!IIIII", 1, 2, 3, 4, 5)
cases.append(BASE + rr(0xC00C, 6, 1, 300, soa))
cases.append(BASE + rr(0xC00C, 15, 1, 300, struct.pack("!H", 10) + name("mail.example.com")))
cases.append(BASE + rr(0xC00C, 16, 1, 300, b"\x05hello\x05world"))
cases.append(BASE + rr(0xC00C, 33, 1, 300, struct.pack("!HHH", 1, 2, 3) + name("target.example.com")))
cases.append(BASE + rr(0xC00C, 14, 1, 300, name("a.example.com") + name("b.example.com")))
cases.append(BASE + rr(0xC00C, 17, 1, 300, name("a.example.com") + name("b.example.com")))
cases.append(BASE + rr(0xC00C, 65000, 1, 300, b"\xde\xad\xbe\xef"))
cases.append(BASE + rr(0xC00C, 3, 1, 300, name("www.example.com")))
cases.append(BASE + rr(0xC00C, 4, 1, 300, name("www.example.com")))
# rdata with an internal compressed name (pointer into the message)
cases.append(BASE + rr(0xC00C, 2, 1, 300, b"\xc0\x0c"))
# name compression: pointer to the question name; to an earlier answer name
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01") + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x02"))
cases.append(header(qd=1, an=2, flags=0x8180) + q("www.example.com", 1, 1)
             + name("a.b.example.com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x01"
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x02"))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1)
             + b"\xc0\x0c" + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x01")
# pointer into the header: offsets 0, 3, 11
for off in (0, 3, 11):
    cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1)
                 + bytes([0xc0, off]) + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x01")
# forward pointer (target after the pointer position)
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1)
             + name("a.example.com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x01")
# record crossing the buffer end
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\xc0\x0c" + b"\x00\x01")
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\xc0\x0c" + b"\x00\x01\x00\x01")
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x01\x2c")
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x05" + b"\xc0\x00\x02\x01")
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\x03www")
# class mismatch -> recoverable; class ANY -> ok; update opcode -> ok; meta exempt
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 1, 3, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 1, 255, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 3, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 41, 1232, 0, b""))
# rdclass established from the first record when there is no question
cases.append(header(an=2, flags=0x8180) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01") + rr(0xC00C, 1, 3, 300, b"\xc0\x00\x02\x02"))
cases.append(header(an=2, flags=0x8180) + rr(0xC00C, 1, 3, 300, b"\xc0\x00\x02\x01") + rr(0xC00C, 1, 3, 300, b"\xc0\x00\x02\x02"))
# question-only types in non-question sections
for t in (251, 252, 253, 254, 255):
    cases.append(BASE + rr(0xC00C, t, 1, 300, b""))
# singletons: CNAME / SOA / DNAME
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 5, 1, 300, name("x.example.com")) + rr(0xC00C, 5, 1, 300, name("x.example.com")))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 5, 1, 300, name("x.example.com")) + rr(0xC00C, 5, 1, 300, name("y.example.com")))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 5, 1, 300, name("X.Example.Com")) + rr(0xC00C, 5, 1, 300, name("x.example.com")))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 6, 1, 300, soa) + rr(0xC00C, 6, 1, 300, soa))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 6, 1, 300, soa) + rr(0xC00C, 6, 1, 300, name("ns1.example.com") + name("hostmaster.example.com") + struct.pack("!IIIII", 9, 9, 9, 9, 9)))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 39, 1, 300, name("x.example.com")) + rr(0xC00C, 39, 1, 300, name("y.example.com")))
# merging: same name, multiple types; same type, multiple rdata; TTL minimized
cases.append(header(qd=1, an=3, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 28, 1, 300, b"\x20\x01\x0d\xb8" + b"\x00" * 12)
             + rr(0xC00C, 16, 1, 300, b"\x03abc"))
cases.append(header(qd=1, an=3, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 1, 1, 100, b"\xc0\x00\x02\x02")
             + rr(0xC00C, 1, 1, 200, b"\xc0\x00\x02\x03"))
cases.append(header(qd=1, an=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 16, 1, 300, b"\x03abc") + rr(0xC00C, 16, 1, 100, b"\x03def"))
# case-insensitive name merging
cases.append(header(qd=1, an=2, flags=0x8180) + q("Www.Example.Com", 1, 1)
             + name("Www.Example.Com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x01"
             + rr(0xC00C, 1, 1, 100, b"\xc0\x00\x02\x02"))
# additional-section pass ordering (A/AAAA first, then RRSIG/DNSKEY, then rest)
cases.append(header(qd=1, ar=4, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 16, 1, 300, b"\x03abc")
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 46, 1, 300, struct.pack("!HBBIIIH", 1, 8, 2, 3600, 0x64, 0x64, 1) + name("example.com") + b"\x01")
             + rr(0xC00C, 2, 1, 300, name("ns1.example.com")))
# trailing garbage accepted
cases.append(header(qd=1) + q("example.com", 1, 1) + b"\xde\xad\xbe\xef\x00")
cases.append(header(qd=1, an=1) + q("example.com", 1, 1) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01") + b"\xff" * 7)

# ---------------------------------------------------------------------------
# EDNS OPT battery
# ---------------------------------------------------------------------------
cases.append(header(ar=1) + opt())
cases.append(header(ar=1) + opt(udp=0))
cases.append(header(ar=1) + opt(udp=65535))
cases.append(header(ar=1) + opt(ext=1))
cases.append(header(ar=1) + opt(ext=0x12))
cases.append(header(ar=1) + opt(ext=0xff))
cases.append(header(ar=1) + opt(ver=0))
cases.append(header(ar=1) + opt(ver=1))
cases.append(header(ar=1) + opt(ver=0xff))
cases.append(header(ar=1) + opt(do=1))
cases.append(header(ar=1) + opt(z=0x7fff))
cases.append(header(ar=1) + opt(z=0x4000))  # CO bit
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + opt())
cases.append(header(qd=1, ar=1, flags=0x0280) + q("example.com", 1, 1) + opt())  # TC + OPT: renderend reset
cases.append(header(qd=1, an=1, ar=1, flags=0x0280) + q("example.com", 1, 1) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01") + opt())
# OPT placement errors
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + opt())
cases.append(header(qd=1, ns=1, flags=0x8180) + q("example.com", 1, 1) + opt())
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + name("opt.example.com") + struct.pack("!HHIH", 41, 4096, 0, 0))
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + name("www.example.com") + struct.pack("!HHIH", 41, 4096, 0, 0))
cases.append(header(qd=1, ar=2, flags=0x8180) + q("example.com", 1, 1) + opt() + opt())
cases.append(header(qd=1, ar=2, flags=0x8180) + q("example.com", 1, 1) + opt(udp=1232) + opt(udp=4096))
cases.append(header(qd=1, ar=2, flags=0x8180) + q("example.com", 1, 1) + opt() + opt(options=o(10, b"\x01" * 8)))
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + opt(options=o(10, b"\x01" * 8)) + b"\x00" + struct.pack("!HH", 41, 4096) + struct.pack("!I", 0) + struct.pack("!H", 0))
# OPT options: valid shapes
cases.append(header(ar=1) + opt(options=o(1, b"\x00" * 18)))                       # LLQ
cases.append(header(ar=1) + opt(options=o(2, b"\x00" * 4)))                        # UL
cases.append(header(ar=1) + opt(options=o(2, b"\x00" * 8)))                        # UL
cases.append(header(ar=1) + opt(options=o(3, b"nsid")))                            # NSID
cases.append(header(ar=1) + opt(options=o(5, b"\x01")))                            # DAU
cases.append(header(ar=1) + opt(options=o(6, b"\x01")))                            # DHU
cases.append(header(ar=1) + opt(options=o(7, b"\x01")))                            # N3U
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x18\x00\xc0\x00\x02")))    # ECS v4 /24
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x02\x40\x00\x20\x01\x0d\xb8\x00\x00")))  # ECS v6 /64
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x00\x00\x00")))                # ECS family 0
cases.append(header(ar=1) + opt(options=o(9, b"")))                                # EXPIRE request
cases.append(header(ar=1) + opt(options=o(9, b"\x00\x00\x00\x01")))                # EXPIRE response
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 8)))                       # COOKIE client
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 16)))                      # COOKIE client+server
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 40)))                      # COOKIE max
cases.append(header(ar=1) + opt(options=o(11, b"")))                               # TCP keepalive
cases.append(header(ar=1) + opt(options=o(11, b"\x00\x64")))
cases.append(header(ar=1) + opt(options=o(12, b"\x00" * 16)))                      # PAD
cases.append(header(ar=1) + opt(options=o(13, b"\x00")))                           # CHAIN
cases.append(header(ar=1) + opt(options=o(14, b"\x00\x01\x00\x02")))               # KEY_TAG
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03\x68\x69")))               # EDE
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03\x68\x69\xc3\xa9")))       # EDE utf8
cases.append(header(ar=1) + opt(options=o(16, b"\x00\x01")))                       # CLIENT_TAG
cases.append(header(ar=1) + opt(options=o(17, b"\x00\x01")))                       # SERVER_TAG
cases.append(header(ar=1) + opt(options=o(18, b"\x00")))                           # REPORT_CHANNEL
cases.append(header(ar=1) + opt(options=o(19, b"\x00\x00\x00\x01")))               # ZONEVERSION
cases.append(header(ar=1) + opt(options=o(65001, b"\xde\xad\xbe\xef")))            # experimental
cases.append(header(ar=1) + opt(options=o(65001, b"")))
cases.append(header(ar=1) + opt(options=o(0, b"")))                                # reserved code 0
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 8) + o(8, b"\x00\x01\x18\x00\xc0\x00\x02") + o(65001, b"\xab")))
# OPT options: invalid shapes (hard OPTERR / UNEXPECTEDEND)
cases.append(header(ar=1) + opt(options=o(1, b"\x00" * 17)))                       # LLQ wrong length
cases.append(header(ar=1) + opt(options=o(2, b"\x00" * 5)))                        # UL wrong length
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x18\x00")))                # ECS truncated
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x03\x18\x00\xc0")))            # ECS bad family
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x21\x00\xc0")))            # ECS prefix > 32
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x17\x01\xc0\x00\x02")))    # ECS scope > 32
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x18\x00\xc0")))            # ECS addrbytes mismatch
cases.append(header(ar=1) + opt(options=o(8, b"\x00\x01\x19\x00\xc0\x00\x02\xff")))  # ECS trailing bits set
cases.append(header(ar=1) + opt(options=o(9, b"\x00\x00\x00")))                    # EXPIRE wrong length
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 7)))                       # COOKIE wrong length
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 15)))
cases.append(header(ar=1) + opt(options=o(10, b"\x01" * 41)))
cases.append(header(ar=1) + opt(options=o(14, b"\x00")))                           # KEY_TAG odd
cases.append(header(ar=1) + opt(options=o(14, b"")))                               # KEY_TAG empty
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03")))                       # EDE too short
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03\xff")))                   # EDE bad utf8
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03\xef\xbb\xbf\x68")))       # EDE BOM
cases.append(header(ar=1) + opt(options=o(15, b"\x00\x03\xed\xa0\x80")))           # EDE surrogate (accepted!)
cases.append(header(ar=1) + opt(options=o(16, b"\x00")))                           # CLIENT_TAG wrong length
cases.append(header(ar=1) + opt(options=o(17, b"\x00\x00\x00")))                   # SERVER_TAG wrong length
cases.append(header(ar=1) + opt(options=b"\x00\x0a\x00\x08\x01"))                  # option length overruns rdata
cases.append(header(ar=1) + opt(options=b"\x00\x0a\x00"))                          # truncated option header
cases.append(header(ar=1) + opt(options=b"\x00"))                                  # truncated option header (1 byte)

# ---------------------------------------------------------------------------
# TSIG battery
# ---------------------------------------------------------------------------
tsig_rdata = name("hmac-sha256.") + struct.pack("!Q", 0x0102030405060708)[2:] + struct.pack("!HH", 300, 0) + b"" + struct.pack("!HHH", 0x1234, 0, 0)
tsig_root = b"\x00" + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_rdata)) + tsig_rdata
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + tsig_root)
cases.append(header(qd=1, an=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01") + tsig_root)
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 250, 1) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_rdata)) + tsig_rdata)
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_rdata)) + tsig_rdata)
cases.append(header(qd=1, ns=1, flags=0x8180) + q("example.com", 1, 1) + tsig_root)
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + name("tsig.example.com") + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_rdata)) + tsig_rdata)
# TSIG rdata with a MAC
tsig_mac = name("hmac-sha256.") + struct.pack("!Q", 0x0102030405060708)[2:] + struct.pack("!HH", 300, 0) + struct.pack("!H", 16) + b"\x11" * 16 + struct.pack("!HHH", 0x1234, 0, 0)
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_mac)) + tsig_mac)
# TSIG rdata errors: truncated algorithm name, truncated fields
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", 5) + name("a") + b"\x00")
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 250, 255) + struct.pack("!I", 0) + struct.pack("!H", len(tsig_rdata) + 4) + tsig_rdata + b"\x00\x00\x00\x00")

# ---------------------------------------------------------------------------
# SIG(0) / RRSIG battery
# ---------------------------------------------------------------------------
sig0_rdata = struct.pack("!HBBIIIH", 0, 0, 0, 0, 0, 0, 0) + b"\x00" + b"\x11" * 8
sig0_root = b"\x00" + struct.pack("!HH", 24, 255) + struct.pack("!I", 0) + struct.pack("!H", len(sig0_rdata)) + sig0_rdata
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + sig0_root)
cases.append(header(qd=1, ar=2, flags=0x8180) + q("example.com", 1, 1) + sig0_root + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + q("example.com") + struct.pack("!HH", 24, 255) + struct.pack("!I", 0) + struct.pack("!H", len(sig0_rdata)) + sig0_rdata)
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 24, 255) + struct.pack("!I", 0) + struct.pack("!H", len(sig0_rdata)) + sig0_rdata)
# SIG(0) with nonzero covers and matching class
sig_covers = struct.pack("!HBBIIIH", 1, 0, 0, 0, 0, 0, 0) + b"\x00" + b"\x11" * 8
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 24, 255) + struct.pack("!I", 0) + struct.pack("!H", len(sig_covers)) + sig_covers)
# RRSIG valid / covers meta / covers unknown
for covered in (1, 2, 6, 41, 200, 251, 0, 65533):
    rrsig = struct.pack("!HBBIIIH", covered, 8, 2, 3600, 0x64, 0x64, 12345) + name("example.com") + b"\x01"
    cases.append(BASE + rr(0xC00C, 46, 1, 3600, rrsig))
# RRSIG labels mismatch -> hard FORMERR
rrsig_badlabels = struct.pack("!HBBIIIH", 1, 8, 5, 3600, 0x64, 0x64, 12345) + name("example.com") + b"\x01"
cases.append(BASE + rr(0xC00C, 46, 1, 3600, rrsig_badlabels))
# RRSIG empty signature -> hard FORMERR
rrsig_nosig = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 0x64, 0x64, 12345) + name("example.com")
cases.append(BASE + rr(0xC00C, 46, 1, 3600, rrsig_nosig))
# RRSIG truncated
cases.append(BASE + rr(0xC00C, 46, 1, 3600, b"\x00\x01\x08"))
# RRSIG compressed signer -> DISALLOWED (hard)
rrsig_comp = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 0x64, 0x64, 12345) + b"\xc0\x0c" + b"\x01"
cases.append(BASE + rr(0xC00C, 46, 1, 3600, rrsig_comp))
# SIG(0) truncated rdata -> hard
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + b"\x00" + struct.pack("!HH", 24, 255) + struct.pack("!I", 0) + struct.pack("!H", 10) + b"\x00" * 10)

# ---------------------------------------------------------------------------
# NSEC3 battery
# ---------------------------------------------------------------------------
nsec3_owner = name("ABCDEFGHIJKLMNOPQRSTUV0123456789.example.com")
nsec3_ok = bytes([1, 0, 0, 0, 0, 20]) + bytes([0x11] * 20) + bytes([0, 1, 0x60])
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, nsec3_ok))
# bad owner (not base32hex) -> hard BADOWNERNAME
cases.append(BASE + rr(0xC00C, 50, 1, 3600, nsec3_ok))
# owner with lowercase base32hex -> BADOWNERNAME
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + name("abcdefghijklmnopqrstuv0123456789.example.com") + struct.pack("!HH", 50, 1) + struct.pack("!I", 3600) + struct.pack("!H", len(nsec3_ok)) + nsec3_ok)
# NSEC3 with salt / odd hash lengths
nsec3_salt = bytes([1, 0, 0, 0, 2, 0xde, 0xad, 20]) + bytes([0x11] * 20) + bytes([0, 1, 0x60])
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, nsec3_salt))
for hlen in (1, 2, 3, 4, 39):
    nsec3_h = bytes([0, 0, 0, 0, 0, hlen]) + bytes(range(1, hlen + 1)) + bytes([0, 1, 0x60])
    cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, nsec3_h))
# NSEC3 malformed: bad salt len, bad hash len for SHA1, bad typemap, empty typemap
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 2, 0xde, 20]) + bytes([0x11] * 20) + bytes([0, 1, 0x60])))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 0, 19]) + bytes([0x11] * 19) + bytes([0, 1, 0x60])))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 0, 20]) + bytes([0x11] * 20) + bytes([0, 2, 0, 1, 0x60])))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 0, 20]) + bytes([0x11] * 20) + bytes([0, 1, 0])))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 0, 20]) + bytes([0x11] * 20)))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, bytes([1, 0, 0, 0, 0, 20]) + bytes([0x11] * 20) + bytes([1, 1, 0x60])))
# NSEC3 in authority + additional
cases.append(header(qd=1, ns=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, nsec3_ok))
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 50, 1, 3600, nsec3_ok))

# ---------------------------------------------------------------------------
# TKEY battery
# ---------------------------------------------------------------------------
tkey_rdata = name("gss-tsig.") + struct.pack("!IIHH", 0, 0, 3, 0) + struct.pack("!HH", 0, 0)
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 249, 1, 0, tkey_rdata))
cases.append(header(qd=1, ns=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 249, 1, 0, tkey_rdata))
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 249, 1, 0, tkey_rdata))
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 249, 1) + rr(0xC00C, 249, 1, 0, tkey_rdata))
tkey_key = name("gss-tsig.") + struct.pack("!IIHH", 0, 0, 3, 0) + struct.pack("!H", 4) + b"\xde\xad\xbe\xef" + struct.pack("!H", 4) + b"\x01\x02\x03\x04"
cases.append(header(qd=1, ar=1, flags=0x8180) + q("example.com", 1, 1) + rr(0xC00C, 249, 1, 0, tkey_key))

# ---------------------------------------------------------------------------
# Dynamic update battery (opcode 5)
# ---------------------------------------------------------------------------
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 254, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 255, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 28, 255, 300, b"\x20\x01\x0d\xb8" + b"\x00" * 12))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 5, 254, 300, name("other.example.com")))
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 5, 254, 300, b""))     # rdlen 0 -> meta, ok
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 254, 300, b""))     # rdlen 0 -> meta, ok
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 16, 255, 300, b""))    # rdlen 0 -> meta, ok
cases.append(header(qd=1, an=2, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 254, 300, b"") + rr(0xC00C, 1, 254, 300, b""))
cases.append(header(qd=1, ns=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 255, 300, b""))     # UPDATE section (AUTHORITY)
cases.append(header(qd=1, ns=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 255, 300, b"\xc0\x00\x02\x01"))
cases.append(header(qd=1, ns=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 1, 254, 300, b"\xc0\x00\x02\x01"))  # NONE in UPDATE -> message class
cases.append(header(qd=1, ns=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 5, 254, 300, b""))

# ---------------------------------------------------------------------------
# RRSIG with class NONE (class-agnostic rdata, gated totext)
# ---------------------------------------------------------------------------
rrsig3 = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 0x64, 0x64, 12345) + name("example.com") + b"\x01"
cases.append(header(qd=1, an=1, flags=0x2800) + q("example.com", 1, 1) + rr(0xC00C, 46, 254, 3600, rrsig3))

# ---------------------------------------------------------------------------
# Multiple sections at once, mixed
# ---------------------------------------------------------------------------
cases.append(header(qd=1, an=1, ns=1, ar=2, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 2, 1, 300, name("ns1.example.com"))
             + rr(0xC00C, 15, 1, 300, struct.pack("!H", 10) + name("mail.example.com"))
             + opt())
cases.append(header(qd=1, an=2, ns=1, ar=1, flags=0x8180) + q("www.example.com", 1, 1)
             + rr(0xC00C, 5, 1, 3600, name("www.example.com"))
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 6, 1, 3600, soa)
             + tsig_root)

# ---------------------------------------------------------------------------
# Merge-heavy messages (the render re-emits each rdata as its own record)
# ---------------------------------------------------------------------------
cases.append(header(qd=1, an=4, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x02")
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x03")
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x04"))
cases.append(header(qd=1, an=4, flags=0x8180) + q("example.com", 1, 1)
             + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01")
             + name("a.example.com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x02"
             + name("b.example.com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x03"
             + name("c.example.com") + struct.pack("!HH", 1, 1) + struct.pack("!I", 300) + struct.pack("!H", 4) + b"\xc0\x00\x02\x04")

# question-only question type with an answer
cases.append(header(qd=1, an=1, flags=0x8180) + q("example.com", 251, 1) + rr(0xC00C, 1, 1, 300, b"\xc0\x00\x02\x01"))

for c in cases:
    assert len(c.hex()) % 2 == 0, c
out = "\n".join(c.hex() for c in cases)
print(out)
