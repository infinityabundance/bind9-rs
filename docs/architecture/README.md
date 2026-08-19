# Architecture

- **Module layout** — the intended module taxonomy of the six crates and how
  it maps to BIND's source layout: `docs/architecture/module-layout.md`
- **Query pipeline** — the authoritative/recursive answer path (Phase 3+):
  *pending*
- **Zone lifecycle** — the primary/secondary/transfer state machines
  (Phase 4): *pending*
- **DNSSEC state machines** — validation and KASP transitions (Phase 6):
  *pending*
- **Historical version atlas** — `forensics/versions/` + the release index
  (Phase 0)

## Current module map

```text
bind9-rs-core/
  error.rs        shared result-code taxonomy with BIND text strings
  class.rs        classes (IN/CH/HS/NONE/ANY/CLASS<n>)
  rrtype.rs       full known-type table incl. historical types
  ttl.rs          TTL scalar and strtottl-style text parsing
  serial.rs       RFC 1982 serial arithmetic (dns_serial_gt semantics)
  rcode.rs        rcode table incl. RESERVED11-15 quirk
  name/           Name + Label: text (decimal escapes), wire (segment-marker
                  pointer rule), compare (right-to-left from root),
                  rdatacompare (case-insensitive bytewise), countlabels
  wire.rs         hex helpers
  rdata/          Rdata enum + A/AAAA/CH-A/NS/PTR/DNAME/SOA/MX/SRV/MINFO/RP/
                  TXT/SPF/RRSIG/SIG/NSEC3/TSIG/TKEY/OPT/unknown, canonical
                  forms, \# generic path, fromtext/towire/totext
  message/        Header, Question, Message parse/render with per-section
                  rrset merging (min-TTL, singletons, class rules), rcode
                  ext-merge, TSIG/SIG(0)/TKEY placement, RRSIG covers,
                  best-effort recovery, Compressor (BIND 9.20 dns_compress
                  semantics, CASE/LARGE/disabled flags)
  edns/           OPT with ext-rcode/version/DO/Z packing and option
                  validation (OPTERR)
  presentation/   isc_lex-faithful tokenizer: LexToken/LexOptions mirroring
                  isc_lex_gettoken (comments, paren/multiline, qstrings,
                  numbers, escapes, CRLF, specials), the master-token view
                  used by the rdata layer, and escape resolution

bind9-rs-tools/
  dig/            CLI parsing (FULLCHECK prefix semantics, per-lookup
                  transport snapshots, +opcode/+qid/+ednsopt machinery),
                  output rendering (masterdump indent() and the 24/24/24/32
                  .. 24/32/40/48 style matrix, multiline SOA/RRSIG,
                  +unknownformat/\# and expandaaaa, +ttlunits, +identify,
                  +yaml, the OPT pseudo-section and statistics blocks,
                  rcode/opcode display tables), UDP/TCP client with EDNS
                  cookie carry-forward, BADVERS negotiation, +padding
                  alignment, opcode-mismatch/truncation retries

bind9-rs-forensics/
  schemas.rs      release index / source manifest / behavior records /
                  version deltas / court manifests / residuals / receipts
  court.rs        court discovery + runner (oracle/rust sides, compare)
  residual.rs     §13 taxonomy + persistence
  receipt.rs      reproducible receipts with environment/capture hashes
  atlas.rs        Doxygen-derived API coverage ledger
  release_index.rs ISC release inventory
```

## Key archaeology findings encoded so far (each with its court)

1. `dns_name_compare` orders labels **right-to-left from the root**
   (via `dns_name_fullcompare`), not left-to-right.
2. `dns_name_rdatacompare` is **case-insensitive** bytewise (RFC 4034
   canonical ordering lowercases).
3. `\DDD` escapes are **decimal** in 9.20.26 (UNKNOWN-0001: when did this
   change?).
4. `dns_name_fromtext` returns **"ran out of space"** (ISC_R_NOSPACE) for
   names over 255 octets — never NAMETOOLONG (buffer clamped to
   DNS_NAME_MAXWIRE).
5. `dns_name_fromwire` rejects pointers that target the **current segment
   start** (`pointer >= marker`), not merely forward pointers.
6. Every rendered name — including the question name — is added to the
   compression table, and suffix matching is case-insensitive **by default**
   (see 11 for named's actual default).
7. The masterfile lexer returns **raw tokens**; consumers (name/char-string
   parsers) resolve escapes; unknown rdata is signalled by a `\#` token.
8. RCODEs 11-15 render as `RESERVED11`..`RESERVED15`; BADKEY/BADTIME/... are
   not message rcodes.
9. `countlabels` includes the root label for absolute names
   (`countlabels(".") == 1`).
10. BIND 9.20 renders escapes with **decimal** digits in `dns_name_totext`.
11. `named` compresses query responses **case-sensitively by default**
    (`DNS_COMPRESS_CASE`), unless the peer matches the view's
    `nocasecompress` ACL (lib/ns/client.c).  AXFR/IXFR responses use
    `DNS_COMPRESS_CASE | DNS_COMPRESS_LARGE` (lib/ns/xfrout.c); update
    requests add `DNS_COMPRESS_LARGE` (lib/dns/request.c).  The compressor
    therefore models all four BIND flags, each courted by its own
    RENDER-COMPRESS-* court.
12. The compression table is a **robin-hood hash set** of `(hash, coff)`
    pairs — 64 slots by default, 1024 with `DNS_COMPRESS_LARGE` — with a
    75% load cap (`count > mask*3/4` refuses inserts; 48 of 64 slots) and
    a 0x4000 offset cap.  Suffix matching is verified against the actual
    message bytes (`match_suffix`: literal, pointer-to-previous, or root
    continuation).  A byte-exact port is required: an earlier HashMap
    approximation chose different offsets than BIND (RENDER-COMPRESS-0001
    residual).
13. **`coff == 0` is the empty-slot sentinel** (`compress.h`): valid
    compression offsets can never be zero because the DNS header occupies
    message offset 0.  Consequence: in a bare-buffer probe, a name whose
    whole-name entry would sit at offset 0 is invisible to later renders —
    they match only its stored suffixes (e.g. `example.com.` rendered
    twice yields `example` + pointer to `com.@8`, never `\xc0\x00`).
    Real messages never hit this because the header pushes every name past
    offset 12.
14. `dns_rdata_fromtext` (rdata.c) has a **consume-to-end-of-line wrapper**:
    after the type-specific parse, any further token is `DNS_R_EXTRATOKEN`
    ("extra input text").  Number fields are lexed as NUMBER tokens
    (digit-only): a non-number is `ISC_R_BADNUMBER`, overflow is
    `ISC_R_RANGE`.  The SOA serial is such a number token, but
    refresh/retry/expire/minimum use `dns_counter_fromtext` → `bind_ttl`
    (lib/dns/ttl.c): digit groups with `w d h m s` units ("1h" = 3600),
    per-group overflow → `DNS_R_SYNTAX`, summed overflow → `ISC_R_RANGE`.
15. The RFC 3597 generic form is validated for KNOWN types
    (`rdata_validate` runs `dns_rdata_fromwire` over the hex):
    `TYPE1 \# 1 00` → "unexpected end of input", `TYPE16 \# 1 00` →
    the concrete TXT `""`.  For TXT, `\#` is generic only when followed
    by a number token, otherwise it is a literal `#` string
    (`DNS_RDATA_UNKNOWNESCAPE`).  Meta types (and type 0) are rejected
    with `DNS_R_METATYPE` in the generic form; without `\#` a meta type
    is "not implemented".
16. Unknown-rdata text form: `\# <len> <hex>` with **uppercase** hex
    (`isc_hex_totext`), no trailing space for length 0; hex errors:
    non-hex digit or odd digit count → `DNS_R_BADHEX`; a decoded byte past
    the declared length → `ISC_R_NOSPACE`; fewer bytes than declared →
    `ISC_R_UNEXPECTEDEND`; length > 65535 → `ISC_R_RANGE`.
17. `dns_rdata_totext` for character-strings (`commatxt_totext`) escapes
    only octets < 0x20 or >= 0x7f inside quotes (space is literal); `\DDD`
    uses **decimal** digits.  `dns_rdata_fromwire` reports unconsumed
    rdata bytes as `DNS_R_EXTRADATA` ("extra input data") and short
    rdata as `ISC_R_UNEXPECTEDEND`.
18. `dns_rdata_ismeta` rejects type 0 and {OPT, TKEY, TSIG, IXFR, AXFR,
    MAILB, MAILA, ANY} in the generic form (oracle-verified via
    `TYPE0`/`TYPE41`/... → "invalid use of a meta type").
