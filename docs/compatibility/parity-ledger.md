# Parity Ledger

Authoritative status of every compatibility surface (spec §47).  Statuses:

```
UNKNOWN | ARCHAEOLOGY | SCAFFOLDED | PARTIAL | ORACLE-TESTED |
RESIDUALS-OPEN | PROVEN | HISTORICAL-ONLY | INTENTIONALLY-UNSUPPORTED
```

`PROVEN` requires court receipts under `forensics/receipts/` plus the
archaeology records.  This file is a snapshot; regenerate the machine
form via `bind9-api-coverage regen` (per-function detail lives in
`forensics/archaeology/api-atlas/api-coverage.json`).

| Surface | Status | Evidence |
|---|---|---|
| DNS name text parsing (`dns_name_fromtext`) | PARTIAL | CORE-NAME-TEXT-0001 (0 residuals) |
| DNS name text rendering (`dns_name_totext`) | PARTIAL | CORE-NAME-TEXT-0001 |
| DNS name wire parsing (`dns_name_fromwire`) | PARTIAL | CORE-NAME-WIRE-0001 |
| DNS name comparison (`dns_name_compare`) | PARTIAL | archaeology of `dns_name_fullcompare`; court pending |
| DNS name canonical comparison (`dns_name_rdatacompare`) | PARTIAL | archaeology; court pending |
| DNS name compression (`dns_compress_*`) | PARTIAL | archaeology of 9.20 `compress.c`; RENDER-COMPRESS court pending |
| DNS message parse (`dns_message_parse`) | PARTIAL | archaeology of `getsection`; WIRE-MESSAGE court pending |
| DNS message render (`dns_message_render`) | PARTIAL | archaeology of `dns_name_towire`; court pending |
| RDATA framework (A/AAAA/NS/CNAME/SOA/MX/TXT/SRV/unknown/...) | PARTIAL | unit tests; court pending |
| EDNS OPT | PARTIAL | unit tests; court pending |
| RCODE/class/type tables | PARTIAL | archaeology of `rcode.c`; court pending |
| Masterfile lexer (`isc_lex` semantics) | PARTIAL | archaeology of `lex.c`/`rdata.c`; court pending |
| dig CLI + output | PARTIAL | archaeology of `dig.c`/`dighost.c`/`masterdump.c`; CLI-DIG-0001..0003 (0 residuals) |
| libcap text grammar (`cap_from_text`/`cap_to_text`) | PROVEN | CAP-PROBE-0001 (0 residuals; byte-identical to C oracle) |
| libcap external format (`cap_copy_ext`/`cap_copy_int`) | PROVEN | CAP-PROBE-0001 |
| libcap flag/compare (`cap_set_flag`/`cap_get_flag`/`cap_compare`) | PROVEN | CAP-PROBE-0001 |
| libcap IAB (`cap_iab_*`) | PROVEN | CAP-PROBE-0001 |
| libcap process observables (`cap_get_proc`/bound/ambient/mode/secbits) | PROVEN | CAP-PROC-0001 (0 residuals; same-container kernel state) |
| libcap VFS file xattr (`cap_get_file`/`cap_set_file`/rootid, v2+v3) | PROVEN | CAP-FILE-0001 (0 residuals; four-corner C↔Rust xattr interop, byte-exact) |
| libmaxminddb metadata + decoder + search tree (`MMDB_*`) | PROVEN | MMDB-0001 (0 residuals; 41-address GAI corpus, decoder DB, corrupt-DB corpus, byte-exact) |
| json-c tokener + object model + serializer (`json_tokener_*`, `json_object_*`) | PROVEN | JSON-0001 (0 residuals; 90+ input parse corpus, strict mode, depth limit, %.17g/NOZERO double path, COLOR, int/uint boundaries, byte-exact) |
| zlib (`compress`/`uncompress`, `deflate*`/`inflate*`, `adler32`/`crc32`, `gz*` incl. gzprintf) | PROVEN | ZLIB-0001 (0 residuals; level x strategy matrix, wrapper matrix, flush modes, dictionaries, gzip-header round trip, error taxonomy, glibc-vsnprintf gzprintf battery, gz file layer, byte-exact) |
| fstrm (control codec, `fstrm_writer`/`fstrm_reader`/`fstrm_rdwr`, file/unix/tcp transports, `fstrm_iothr` + queues) | PROVEN | FSTRM-0001 (0 residuals; upstream test_control corpus, writer/reader state machines incl. bidirectional handshake + negotiation, max-frame-size quirk, writev chunking, inet_pton/strtoul init validation, iothr option/submit taxonomy, discard path, AF_UNIX + TCP four-corner interop, byte-exact) |
| libidn2 IDNA2008/UTS #46 (`idn2_lookup_ul`, `idn2_to_ascii_lz`/`_8z`, `idn2_to_unicode_8zlz`, the `_lz` locale layer, NO_TR46, label tests, bidi, context rules, punycode) | PROVEN | LZ-0001 (0 residuals; 3-locale corpus C.UTF-8/C/ISO-8859-1, ICONV_FAIL/ENCODING_ERROR taxonomy, NO_TR46 pure-IDNA2008 path, flag-conflict taxonomy, label-test corners, byte-exact) |
| `named` runtime | UNKNOWN | |
| Recursive resolver | UNKNOWN | |
| DNSSEC | UNKNOWN | |
| Zone transfers / journal | UNKNOWN | |
| Dynamic update | UNKNOWN | |
| `rndc` control channel | UNKNOWN | |
| Views / ACL / RPZ / catalog zones | UNKNOWN | |
| Logging / statistics / dnstap | UNKNOWN | |
| Plugins / DLZ / DynDB | UNKNOWN | |
