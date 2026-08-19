# Lore Archive — dig CLI (addendum §29)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.  Court:
CLI-DIG-0004 (the 125-case option/output matrix over the scripted
responder) unless noted.

## DNS-LORE-0017 — the BADVERS retry compares the *merged* rcode, so the RFC 6891 wire form never matches

`recv_done` retries EDNS-version negotiation with
`msg->rcode == dns_rcode_badvers` — and `dns_rcode_badvers` is 16, the
value the *merged* 12-bit rcode takes only when the OPT TTL's ext-rcode
byte is 1 with a zero header rcode (`(1 << 4) | 0`).  The common RFC 6891
wire encoding puts 0x10 in the TTL byte (`(0x10 << 4) | 0 = 256`), which
never equals 16: no retry, and the header line prints `status: ?256`
(dns_rcode_totext only knows 0..15).  dig's `+edns=1`/`+edns=2` against a
BADVERS server therefore shows the `?256` response once and stops; only a
server that encodes BADVERS as TTL-byte 1 triggers
`;; BADVERS, retrying with EDNS version N.`.  Courts: CLI-DIG-0004 cases
51/52 (`?256`, no retry) and 114 (retry).

## DNS-LORE-0018 — `+tcp` is per-lookup: it mutates the current lookup, and later names clone the untouched default

`plus_option` writes `lookup->tcp_mode`/`tcp_mode_set` on the *current*
lookup (the one created by the most recent name, or the default lookup
before any name).  A later name clones the default lookup, whose tcp_mode
was never touched — so `dig example.com +tcp +keepopen a.example.com`
sends example.com over TCP and a.example.com over **UDP**.  The `;;
SERVER: ... (TCP)/(UDP)` stats line and the responder query log both show
the split.  The same rule governs `+vc`, `+notcp`, and the AXFR/IXFR/ANY
TCP forcing (`if (!tcp_mode_set) tcp_mode = true`).  Court: CLI-DIG-0004
case 98.

## DNS-LORE-0019 — `+padding` includes the 4-byte PAD option header in the alignment math, and an aligned message gets an empty PAD

dighost.c reserves a 0-length PAD option at build time
(`opts[i].length = 0`); `dns_message_renderend` then computes
`padsize = padding - ((used + reserved) % padding)` where `used` already
contains that 4-byte header, fills the payload, and patches the option and
OPT lengths.  A message that is already aligned gets `padsize = 0` — the
empty PAD option remains in the OPT (dig prints `; PADDING:` with no
suffix).  For `example.com +padding=64` the query is 52 bytes of
header+question+OPT-with-cookie, plus 4 for the PAD header = 56, so the
payload is 8 bytes (total 64) — not 12, which the naive
`padding - (size % padding)` without the header would give.  Court:
CLI-DIG-0004 case 43 (`; PADDING: (8 bytes)`, `;; MSG SIZE rcvd: 107`).

## DNS-LORE-0020 — the cookie echo is verified against the *sent* bytes, and `+cookie=####` replaces the random client cookie

`process_cookie` compares the response's first 8 cookie octets against the
bytes this process actually sent: the `+cookie=hex` override when given,
else the per-process random cookie (`sent = l->cookie ?: cookie`).  A
`+cookie=0102030405060708` query whose server echoes those bytes plus a
server cookie therefore prints `(good)` — the override, not the random
cookie, is the reference.  The mismatch warning
(`;; Warning: Client COOKIE mismatch`) is printed from `recv_done`
*before* the message (so before the greeting), is gated on `+comments`,
and marks the option `(bad)`; only a verified echo is carried forward into
the next query of the lookup.  Courts: CLI-DIG-0004 cases 62 (override
echoed → `(good)`, no warning) and 64/65 (mismatched fixture → `(bad)` +
warning).

## DNS-LORE-0021 — the `+noedns` FORMERR warning is informational only in 9.20.26

The `;; WARNING: EDNS query returned status FORMERR - retry with '+noedns'`
line (dig.c printmessage, gated on `edns != -1`, no OPT in the response,
FORMERR or NOTIMP) is a *hint*: recv_done has no FORMERR requeue path in
9.20.26, so the query is not actually re-sent.  The hint text is built as
`"%s+noedns"` with the prefix `"+nodnssec "` when `+dnssec` is on, so the
message reads `'+nodnssec +noedns'` in that case.  Courts: CLI-DIG-0004
cases 21 (`+header-only` → FORMERR) and 115 (`ednsneg.example.com`).

## DNS-LORE-0022 — the query OPT flags are assembled by subtraction, not addition

setup_lookup builds the 16-bit EDNS flag word as
`flags = ednsflags; flags &= ~(DO|CO); if (dnssec) flags |= DO; if
(coflag) flags |= CO;` — so `+ednsflags=0x8000` does **not** set the DO
bit (it is stripped and not re-added, because `dnssec` is false), while
`+coflag` and `+dnssec` set CO/DO regardless of ednsflags.  The rendered
OPT therefore shows `flags: co` only for `+coflag`, `flags: do` only for
`+dnssec`, and the leftover ednsflags bits print as the `; MBZ: 0x%.4x`
segment of the `; EDNS: version: 0, flags:...` line.  Court: CLI-DIG-0004
cases 53-55 (`+ednsflags`), 74 (`+coflag`).

## DNS-LORE-0023 — dig's rcode display only knows 0..15; BADVERS/BADCOOKIE render as `?N`

`rcode_totext` (dig.c) calls `dns_rcode_totext`, which consults only the
`rcodes` table — the 0..15 mnemonics plus RESERVED11..15.  The
ERCODENAMES BADVERS/BADCOOKIE entries live in a second table that the
12-bit display path never uses, so the merged rcodes 16 (BADVERS with
ext-byte 1) and 23 (BADCOOKIE) print as the bare number, and dig's
all-digits check prefixes `?`: `?16`, `?23`, and `?256` for the standard
BADVERS wire form.  Court: CLI-DIG-0004 cases 51/52 (`status: ?256`).

## DNS-LORE-0024 — opcode section names: UPDATE renames all sections, NOTIFY renames none

`dns_message_sectiontotext` switches on `msg->opcode`:
`dns_opcode_update` prints ZONE/PREREQUISITE/UPDATE for the
question/answer/authority sections (additional stays ADDITIONAL); every
other opcode — including NOTIFY — keeps QUESTION/ANSWER/AUTHORITY.  The
opcode name table is the full 16 entries (QUERY IQUERY STATUS RESERVED3
NOTIFY UPDATE RESERVED6..15), so `+opcode=UPDATE` is 5, `+opcode=NOTIFY`
is 4, and `+opcode=3` is RESERVED3.  Courts: CLI-DIG-0004 cases 76-79.

## DNS-LORE-0025 — the multiline rdata linebreak is "\n" + indent to the rdata column, and RRSIG wraps the `( ... )` form

The DSTYLE_MULTILINE linebreak is built once per message by
`totext_ctx_init`: `"\n"` plus `indent()` to the style's rdata column (32
for dig's multiline style → `\n\t\t\t\t`).  SOA prints
`%-10lu ; <name>` fields with ` (<verbose units>)` on the timers;
`totext_rrsig` emits `" ("` after the original TTL, then expiration /
time-signed / key tag / signer on the next line, then the base64
signature at `width - 2` (30) with the same linebreak, then `" )"`.
Only types whose totext consults DNS_STYLEFLAG_MULTILINE wrap (RRSIG,
SIG, SOA, DNSKEY, DS, NSEC3, ...); others stay single-line.  Courts:
CLI-DIG-0004 cases 2 (SOA) and 38 (RRSIG).

## DNS-LORE-0026 — under `-6` an IPv4 literal resolves to its v4-mapped form and is skipped with warnings, exit 0

With `-6`, `getaddresses` resolves an IPv4 literal through the AF_INET6
path and gets `::ffff:127.0.0.1`; `start_tcp`/`start_udp` skip every
v4-mapped address with `;; Skipping mapped address '<addr>'` and, when no
address survives, print `;; No acceptable nameservers` and cancel the
lookup with exit code 0 (no greeting is ever printed — the warnings come
from the transport setup, not printmessage).  Court: CLI-DIG-0004 case
104.

## DNS-LORE-0027 — the counts line prints the *header* counts, which survive a best-effort parse failure

dig prints `msg->counts[...]` — the section counts from the message
header, not the number of successfully parsed records.  A malformed
answer record (e.g. an A with 3-byte rdata) under BESTEFFORT therefore
still shows `ANSWER: 1` while the answer section renders nothing, and the
unparsed tail becomes the `;; WARNING: Message has 3 extra bytes at end`
count.  Courts: CLI-DIG-0004 cases 117/118.

## DNS-LORE-0028 — the short form applies UNKNOWNFORMAT and EXPANDAAAA but never MULTILINE, even under `+yaml`

`short_answer` → `say_message` calls `dns_rdata_tofmttext` with the
style flags `UNKNOWNFORMAT | EXPANDAAAA | NOCRYPTO` (plus RRCOMMENT) and
a plain `" "` linebreak — the multiline flag is never set, so
`+short +multiline` SOA stays single-line.  Under `+yaml +short` the YAML
branch prints the header block (`- type: MESSAGE` … the counts), then the
bare short answers replace the OPT/question/answer section blocks
(`short_answer` writes into the same buffer).  Courts: CLI-DIG-0004 cases
19/20 (expandaaaa in short), 29/30 (multiline ignored), 27 (yaml+short).
