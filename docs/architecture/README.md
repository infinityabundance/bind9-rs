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
bind9-core/
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
  rdata/          Rdata enum + A/AAAA/NS/CNAME/PTR/SOA/MX/SRV/MINFO/RP/
                  TXT/unknown, canonical forms, \# generic path
  message/        Header, Question, Message parse/render, Compressor
                  (BIND 9.20 dns_compress semantics)
  edns/           OPT with ext-rcode/version/DO/Z packing
  presentation/   isc_lex-faithful lexer (raw tokens; consumers resolve
                  escapes)

bind9-tools/
  dig/            CLI parsing (FULLCHECK prefix semantics), output rendering
                  (masterdump indent(), 24/32/40/48 columns), UDP/TCP client

bind9-forensics/
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
   compression table, and suffix matching is case-insensitive.
7. The masterfile lexer returns **raw tokens**; consumers (name/char-string
   parsers) resolve escapes; unknown rdata is signalled by a `\#` token.
8. RCODEs 11-15 render as `RESERVED11`..`RESERVED15`; BADKEY/BADTIME/... are
   not message rcodes.
9. `countlabels` includes the root label for absolute names
   (`countlabels(".") == 1`).
10. BIND 9.20 renders escapes with **decimal** digits in `dns_name_totext`.
