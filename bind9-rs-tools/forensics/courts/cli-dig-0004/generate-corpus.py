#!/usr/bin/env python3
"""generate-corpus.py — CLI-DIG-0004 corpus: the dig option matrix and
rendering surface against the deterministic scripted responder.

Covers the observable surface beyond CLI-DIG-0001..0003: the +flag matrix
(EDNS options, query flags, sections, short forms, units, formats), the
masterfile-style rendering (+multiline, +nottl, +noclass, +ttlunits,
+onesoa, +unknownformat, +expandaaaa, +split, +header-only, +identify,
+yaml), the EDNS negotiation/cookie/version paths, opcode/qid, transport
variants, the removed-option diagnostics, and the bad-packet/besteffort
paths.  Deterministic: the responder serves fixed records on 127.0.0.1:5333.
"""

cases = []


def add(line):
    cases.append(line)


# --- masterfile-style rendering ------------------------------------------
add("@127.0.0.1 -p 5333 example.com +multiline")
add("@127.0.0.1 -p 5333 example.com SOA +multiline")
add("@127.0.0.1 -p 5333 example.com MX +multiline")
add("@127.0.0.1 -p 5333 example.com TXT +multiline")
add("@127.0.0.1 -p 5333 multi.example.com TXT +multiline")
add("@127.0.0.1 -p 5333 any.example.com ANY +multiline")
add("@127.0.0.1 -p 5333 long.example.com +multiline")
add("@127.0.0.1 -p 5333 example.com +nottl")
add("@127.0.0.1 -p 5333 example.com +noclass")
add("@127.0.0.1 -p 5333 example.com +nottl +noclass")
add("@127.0.0.1 -p 5333 example.com +ttlunits")
add("@127.0.0.1 -p 5333 example.com +multiline +nottl")
add("@127.0.0.1 -p 5333 example.com +multiline +ttlunits")
add("@127.0.0.1 -p 5333 example.com +onesoa")
add("@127.0.0.1 -p 5333 example.com +onesoa +multiline")
add("@127.0.0.1 -p 5333 nonexistent.example.com +onesoa")
add("@127.0.0.1 -p 5333 example.com +unknownformat")
add("@127.0.0.1 -p 5333 example.com AAAA +expandaaaa")
add("@127.0.0.1 -p 5333 example.com +short +expandaaaa")
add("@127.0.0.1 -p 5333 example.com AAAA +short +expandaaaa")
add("@127.0.0.1 -p 5333 example.com +header-only")
add("@127.0.0.1 -p 5333 example.com +noall +header-only")
add("@127.0.0.1 -p 5333 example.com +identify")
add("@127.0.0.1 -p 5333 example.com a.example.com +identify")
add("@127.0.0.1 -p 5333 example.com +yaml")
add("@127.0.0.1 -p 5333 example.com SOA +yaml")
add("@127.0.0.1 -p 5333 example.com +yaml +short")
add("@127.0.0.1 -p 5333 example.com -u")
add("@127.0.0.1 -p 5333 example.com +short +multiline")
add("@127.0.0.1 -p 5333 example.com SOA +short +multiline")

# --- unknown-type rendering + split --------------------------------------
add("@127.0.0.1 -p 5333 example.com -t TYPE65280")
add("@127.0.0.1 -p 5333 example.com -t TYPE65280 +unknownformat")
add("@127.0.0.1 -p 5333 example.com -t TYPE65280 +split=16")
add("@127.0.0.1 -p 5333 example.com -t TYPE65280 +short")

# --- DNSSEC / DO ---------------------------------------------------------
add("@127.0.0.1 -p 5333 dnssec.example.com +dnssec")
add("@127.0.0.1 -p 5333 dnssec.example.com +do")
add("@127.0.0.1 -p 5333 dnssec.example.com +dnssec +short")
add("@127.0.0.1 -p 5333 dnssec.example.com +dnssec +multiline")
add("@127.0.0.1 -p 5333 dnssec.example.com +nodnssec")

# --- EDNS options --------------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +nsid")
add("@127.0.0.1 -p 5333 example.com +expire")
add("@127.0.0.1 -p 5333 example.com +keepalive")
add("@127.0.0.1 -p 5333 example.com +padding=64")
add("@127.0.0.1 -p 5333 example.com +subnet=192.0.2.0/24")
add("@127.0.0.1 -p 5333 example.com +subnet=2001:db8::/32")
add("@127.0.0.1 -p 5333 example.com +ednsopt=NSID")
add("@127.0.0.1 -p 5333 example.com +ednsopt=65001:01020304")
add("@127.0.0.1 -p 5333 example.com +ednsopt=3:0102")
add("@127.0.0.1 -p 5333 example.com +noednsopt")
add("@127.0.0.1 -p 5333 example.com +edns=0")
add("@127.0.0.1 -p 5333 example.com +edns=1")
add("@127.0.0.1 -p 5333 example.com +edns=2")
add("@127.0.0.1 -p 5333 example.com +edns=0 +ednsflags=0x8000")
add("@127.0.0.1 -p 5333 example.com +edns=0 +ednsflags=0x4000")
add("@127.0.0.1 -p 5333 example.com +edns=0 +ednsflags=0xffff")
add("@127.0.0.1 -p 5333 example.com +noedns")
add("@127.0.0.1 -p 5333 example.com +bufsize=512")
add("@127.0.0.1 -p 5333 example.com +bufsize=4096 +qr")
add("@127.0.0.1 -p 5333 example.com +qr")
add("@127.0.0.1 -p 5333 example.com +qr +noall +answer")

# --- cookie paths --------------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +cookie")
add("@127.0.0.1 -p 5333 example.com +cookie=0102030405060708")
add("@127.0.0.1 -p 5333 example.com +nocookie")
add("@127.0.0.1 -p 5333 badcookie.example.com")
add("@127.0.0.1 -p 5333 badcookie.example.com +badcookie")
add("@127.0.0.1 -p 5333 badcookie.example.com +nobadcookie")
add("@127.0.0.1 -p 5333 badcookie.example.com +showbadcookie")

# --- query flags ---------------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +aaonly +qr")
add("@127.0.0.1 -p 5333 example.com +adflag +qr")
add("@127.0.0.1 -p 5333 example.com +cdflag +qr")
add("@127.0.0.1 -p 5333 example.com +tcflag +qr")
add("@127.0.0.1 -p 5333 example.com +zflag +qr")
add("@127.0.0.1 -p 5333 example.com +raflag +qr")
add("@127.0.0.1 -p 5333 example.com +coflag +qr")
add("@127.0.0.1 -p 5333 example.com +noaaonly +noadflag +nocdflag +nozflag +qr")

# --- opcode / qid --------------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +opcode=UPDATE +qr")
add("@127.0.0.1 -p 5333 example.com +opcode=NOTIFY +qr")
add("@127.0.0.1 -p 5333 example.com +opcode=3 +qr")
add("@127.0.0.1 -p 5333 example.com +opcode=QUERY +qr")
add("@127.0.0.1 -p 5333 example.com +qid=4660 +qr")

# --- sections / comments / stats toggles ---------------------------------
add("@127.0.0.1 -p 5333 example.com +nocomments")
add("@127.0.0.1 -p 5333 example.com +nostats")
add("@127.0.0.1 -p 5333 example.com +nocmd")
add("@127.0.0.1 -p 5333 example.com +noall")
add("@127.0.0.1 -p 5333 example.com +all")
add("@127.0.0.1 -p 5333 example.com +noall +question")
add("@127.0.0.1 -p 5333 example.com +noall +answer +authority +additional")
add("@127.0.0.1 -p 5333 example.com +comments +noanswer +noquestion")
add("@127.0.0.1 -p 5333 example.com +rrcomments")

# --- class / type / name forms -------------------------------------------
add("@127.0.0.1 -p 5333 version.bind CH TXT")
add("@127.0.0.1 -p 5333 version.bind -c CH -t TXT")
add("@127.0.0.1 -p 5333 example.com -c IN -t A")
add("@127.0.0.1 -p 5333 -q example.com -t A")
add("@127.0.0.1 -p 5333 example.com A AAAA MX TXT")
add("@127.0.0.1 -p 5333 example.com a.example.com")

# --- transport / retry / timeout -----------------------------------------
add("@127.0.0.1 -p 5333 example.com +tcp +multiline")
add("@127.0.0.1 -p 5333 example.com +vc")
add("@127.0.0.1 -p 5333 example.com +tcp +keepopen a.example.com")
add("@127.0.0.1 -p 5333 example.com +retry=1")
add("@127.0.0.1 -p 5333 example.com +tries=0")
add("@127.0.0.1 -p 5333 example.com +time=0")
add("@127.0.0.1 -p 5333 example.com +timeout=2")
add("@127.0.0.1 -p 5333 -4 -p 5333 example.com")
add("@127.0.0.1 -p 5333 -6 example.com")

# --- search / misc no-ops -------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +search")
add("@127.0.0.1 -p 5333 example.com +nosearch")
add("@127.0.0.1 -p 5333 example.com +ndots=1")
add("@127.0.0.1 -p 5333 example.com +fuzztime=2")
add("@127.0.0.1 -p 5333 example.com +domain=example.com")
add("@127.0.0.1 -p 5333 example.com +showsearch")
add("@127.0.0.1 -p 5333 example.com +showbadvers")
add("@127.0.0.1 -p 5333 example.com +cl")

# --- EDNS negotiation / bad packet / besteffort ---------------------------
add("@127.0.0.1 -p 5333 opcodemismatch.example.com +qr")
add("@127.0.0.1 -p 5333 badvers.example.com +edns=1")
add("@127.0.0.1 -p 5333 ednsneg.example.com")
add("@127.0.0.1 -p 5333 ednsneg.example.com +noedns")
add("@127.0.0.1 -p 5333 malformed.example.com")
add("@127.0.0.1 -p 5333 malformed.example.com +besteffort")

# --- removed options ------------------------------------------------------
add("@127.0.0.1 -p 5333 example.com +sigchase")
add("@127.0.0.1 -p 5333 example.com +topdown")
add("@127.0.0.1 -p 5333 example.com +mapped")
add("@127.0.0.1 -p 5333 example.com +trusted-key")

# --- unreachable server (no-servers paths) --------------------------------
add("@127.0.0.1 -p 1 example.com")
add("@127.0.0.1 -p 1 example.com +tcp")

print("\n".join(cases))
