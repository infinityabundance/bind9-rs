# BIND 9 API Coverage Ledger

Machine-readable form: `api-coverage.json`.  Statuses follow the parity-ledger taxonomy (§47).  A surface is `PROVEN` only with court receipts; `UNKNOWN` entries are tracked in the unknowns ledger.  Regenerate with `bind9-api-coverage regen` after updating `coverage-rules.json`.

## Scope

- bin/check: 4 files, 26 functions
- bin/confgen: 8 files, 19 functions
- bin/delv: 1 files, 31 functions
- bin/dig: 6 files, 30 functions
- bin/dnssec: 12 files, 74 functions
- bin/named: 37 files, 139 functions
- bin/nsupdate: 1 files, 0 functions
- bin/plugins: 2 files, 24 functions
- bin/rndc: 3 files, 15 functions
- bin/tools: 7 files, 51 functions
- fuzz/dns_master_load.c: 1 files, 2 functions
- fuzz/dns_message_checksig.c: 1 files, 3 functions
- fuzz/dns_message_parse.c: 1 files, 5 functions
- fuzz/dns_name_fromtext_target.c: 1 files, 2 functions
- fuzz/dns_name_fromwire.c: 1 files, 2 functions
- fuzz/dns_qp.c: 1 files, 7 functions
- fuzz/dns_qpkey_name.c: 1 files, 2 functions
- fuzz/dns_rdata_fromtext.c: 1 files, 2 functions
- fuzz/dns_rdata_fromwire_text.c: 1 files, 3 functions
- fuzz/fuzz.h: 1 files, 2 functions
- fuzz/isc_lex_getmastertoken.c: 1 files, 2 functions
- fuzz/isc_lex_gettoken.c: 1 files, 2 functions
- fuzz/main.c: 1 files, 3 functions
- fuzz/old.c: 1 files, 1 functions
- fuzz/old.h: 1 files, 1 functions
- lib/dns: 396 files, 3749 functions
- lib/isc: 193 files, 1012 functions
- lib/isccfg: 16 files, 178 functions
- lib/ns: 26 files, 292 functions

**Total: 727 files, 5679 functions** (pinned oracle version, see `sources/manifest-*.json`).

## Status summary

| Status | Count |
|---|---|
| ARCHAEOLOGY | 82 |
| PARTIAL | 26 |
| SCAFFOLDED | 1 |
| UNKNOWN | 5570 |

## Surfaces with court or rust coverage

| Function | Library | Status | Court | Rust module |
|---|---|---|---|---|
| `dns_compress_init` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_compress_invalidate` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_compress_setpermitted` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_compress_getpermitted` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_compress_name` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_compress_rollback` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_master_questiontotext` | lib/dns | ARCHAEOLOGY | CLI-DIG-OUTPUT-0001 | `` |
| `dns_master_stylecreate` | lib/dns | ARCHAEOLOGY | CLI-DIG-OUTPUT-0001 | `bind9-tools::dig::output` |
| `dns_rcode_fromtext` | lib/dns | SCAFFOLDED |  | `bind9-core::rcode` |
| `dns_rcode_totext` | lib/dns | PARTIAL |  | `bind9-core::rcode` |
| `dns_rdataclass_fromtext` | lib/dns | PARTIAL |  | `bind9-core::class` |
| `dns_rdataclass_totext` | lib/dns | PARTIAL |  | `bind9-core::class` |
| `dns_rdatatype_fromtext` | lib/dns | PARTIAL |  | `bind9-core::rrtype` |
| `dns_rdatatype_totext` | lib/dns | PARTIAL |  | `bind9-core::rrtype` |
| `dns_ttl_totext` | lib/dns | ARCHAEOLOGY |  | `bind9-core::ttl` |
| `dns_ttl_fromtext` | lib/dns | ARCHAEOLOGY |  | `bind9-core::ttl` |
| `dns_name_isabsolute` | lib/dns | PARTIAL |  | `bind9-core::name` |
| `dns_name_fullcompare` | lib/dns | ARCHAEOLOGY | CORE-NAME-COMPARE-0001 | `bind9-core::name` |
| `dns_name_compare` | lib/dns | PARTIAL | CORE-NAME-COMPARE-0001 | `bind9-core::name` |
| `dns_name_rdatacompare` | lib/dns | PARTIAL | CORE-NAME-RDATACOMPARE | `bind9-core::name` |
| `dns_name_issubdomain` | lib/dns | PARTIAL | CORE-NAME-ISSUBDOMAIN | `bind9-core::name` |
| `dns_name_fromtext` | lib/dns | PARTIAL | CORE-NAME-TEXT-0001 | `bind9-core::name` |
| `dns_name_totext` | lib/dns | PARTIAL | CORE-NAME-TOTEXT-0001 | `bind9-core::name` |
| `dns_name_fromwire` | lib/dns | PARTIAL | CORE-NAME-WIRE-0001 | `bind9-core::name::wire` |
| `dns_name_towire` | lib/dns | PARTIAL | CORE-NAME-WIRE-TOWIRE | `bind9-core::name::wire` |
| `dns_compress_setpermitted` | lib/dns | PARTIAL | RENDER-COMPRESS-0001 | `bind9-core::message::compression` |
| `dns_rdata_txt_first` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_rdata_txt_next` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_rdata_txt_current` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_rdata_txt_first` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_rdata_txt_next` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_rdata_txt_current` | lib/dns | PARTIAL |  | `bind9-core::rdata` |
| `dns_ttl_totext` | lib/dns | ARCHAEOLOGY |  | `bind9-core::ttl` |
| `dns_ttl_fromtext` | lib/dns | ARCHAEOLOGY |  | `bind9-core::ttl` |
| `isc_sockaddr_equal` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_eqaddr` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_compare` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_eqaddrprefix` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_totext` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_format` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_hash_ex` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_hash` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_any` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_any6` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_fromin` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_anyofpf` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_fromin6` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_v6fromin` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_pf` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_fromnetaddr` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_setport` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_getport` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_ismulticast` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_isexperimental` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_issitelocal` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_islinklocal` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_isnetzero` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_fromsockaddr` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_sockaddr_disabled` | lib/isc | ARCHAEOLOGY |  | `bind9-platform` |
| `isc_time_set` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_settoepoch` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_isepoch` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_now_hires` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_now` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_monotonic` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_nowplusinterval` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_compare` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_add` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_subtract` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_microdiff` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_seconds` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_secondsastimet` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_nanoseconds` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_miliseconds` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formattimestamp` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formathttptimestamp` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_parsehttptimestamp` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601L` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601Lms` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601Lus` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601ms` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatISO8601us` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
| `isc_time_formatshorttimestamp` | lib/isc | ARCHAEOLOGY |  | `bind9-platform::clock` |
