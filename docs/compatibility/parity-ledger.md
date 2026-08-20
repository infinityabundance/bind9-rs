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
| DNS name text parsing (`dns_name_fromtext`) | PROVEN | CORE-NAME-TEXT-0001 (0 residuals; fromtext/totext/towire against the root origin, escape forms, byte-exact) |
| DNS name text rendering (`dns_name_totext`) | PROVEN | CORE-NAME-TEXT-0001 |
| DNS name wire parsing (`dns_name_fromwire`) | PROVEN | CORE-NAME-WIRE-0001 (0 residuals; labels, compression pointers, bounds, error codes) |
| DNS name comparison (`dns_name_compare`) | PROVEN | CORE-NAME-COMPARE-0001 (0 residuals; fullcompare order, namereln, common labels, subdomain, equality) |
| DNS name canonical comparison (`dns_name_rdatacompare`) | PROVEN | CORE-NAME-COMPARE-0001 |
| DNS name compression (`dns_compress_*`) | PROVEN | RENDER-COMPRESS-0001..0005 (0 residuals; default/disabled/case/large 1024-slot/RFC 3597-not-permitted, byte-exact) |
| DNS message parse (`dns_message_parse`) | PROVEN | WIRE-MESSAGE-0001 (0 residuals; header, question semantics, section merging and class rules, compression incl. pointers into the header, OPT placement and option validation, TSIG/SIG(0)/TKEY placement, RRSIG covers, NSEC3 owners, update meta classes, truncation, parse→render→reparse) |
| DNS message render (`dns_message_render`) | PROVEN | WIRE-MESSAGE-0001 |
| RDATA framework (A/AAAA/NS/CNAME/PTR/SOA/MX/TXT/SRV/MINFO/RP + RFC 3597 unknown) | PROVEN | WIRE-RDATA-0001 (0 residuals; fromtext/totext/towire/digest/fromwire, error taxonomy, byte-exact) |
| EDNS OPT | PROVEN | WIRE-MESSAGE-0001 (OPT placement, ext-rcode/version/DO/Z packing, option validation incl. OPTERR) |
| RCODE/class/type tables | PROVEN | TABLES-0001 (0 residuals; rcode/tsigrcode/rdatatype/rdataclass totext+fromtext, ismeta/issingleton/isknown, RESERVED11..15 TOTEXTONLY and KEYDATA asymmetries) |
| Masterfile lexer (`isc_lex` semantics) | PROVEN | ISC-LEX-0001 (0 residuals; gettoken + getmastertoken, DNSMASTERFILE comments, paren/multiline, quoted strings, numbers incl. overflow, escapes, CRLF, NUL specials, byte-exact) |
| dig CLI + output | PROVEN | archaeology of `dig.c`/`dighost.c`/`masterdump.c`; CLI-DIG-0001..0004 (0 residuals; 125-case option matrix over the scripted responder: masterfile styles incl. multiline SOA/RRSIG, +nottl/+noclass/+ttlunits/+onesoa/+unknownformat/+expandaaaa/+split/+header-only/+identify/+yaml, EDNS options incl. cookie states + carry-forward and BADCOOKIE, DO/CO flags, +opcode/+qid, per-lookup transports, truncation/EDNS-negotiation/opcode-mismatch retries, bad-packet/besteffort, -4/-6 resolution, byte-exact) |
| libuv 1.52.1 event loop (`uv_version`/`uv_library_shutdown`, `uv_loop_init`/`uv_run` DEFAULT/ONCE/NOWAIT/`uv_stop`/`uv_loop_alive`/`uv_loop_close`, the timer heap by (timeout, start_id) with repeat re-arm before the callback, idle/prepare/check iteration with idle-before-prepare, async coalescing + the cross-thread wakeup, signal dispatch one-callback-per-raise, `uv_udp_*` incl. the EAGAIN drain marker and scatter-one-datagram sends, `uv_tcp_*`/streams incl. the immediate-write path and SO_ERROR connect completion, handle utilities, `uv_dlopen`/`uv_dlsym`/`uv_dlerror`, `uv_random` via the threadpool, `uv_sleep`, `uv_barrier_*`, `uv_replace_allocator`, `uv_cancel`, the full UV_ERRNO_MAP) | PROVEN | LIBUV-0001 (0 residuals; 18 phases byte-exact in the oracle-libuv-1.52.1 container: version/library lifecycle; loop init/run/close incl. the DEFAULT pre-loop timer pass, the pending immediate-callback pass, close_cb LIFO, leftover-handle EBUSY; timer heap/repeat/rearm; watcher ordering; async 3-sends→1-callback + cross-thread send; signal taxonomy; the UDP taxonomy (EDESTADDRREQ/EISCONN/ENOTCONN, 4→604 send queue, drain marker, 64K alloc suggestion, connected recv); the TCP flow (second-listen no-op, accept EAGAIN, immediate-write queue-stays-0, try_write, shutdown→EOF, ECONNREFUSED, buffer-size roundtrip, EBADF after close); walk order + fileno EINVAL/EBADF; exact glibc dl messages; threadpool random; barrier serial-thread return; allocator counts (calloc 1 + realloc 1; free 2); cancel EINVAL/EBUSY; the 85-entry error battery incl. the Unknown system error forms) |
| liburcu 0.15.6 userspace RCU, membarrier flavor (`rcu_register_thread`/`rcu_unregister_thread`, the `rcu_read_lock`/`rcu_read_unlock` nesting counters + `rcu_read_ongoing`, the flavor's `rcu_quiescent_state`/`rcu_thread_online`/`rcu_thread_offline` no-ops, the two-pass `synchronize_rcu` grace period, `call_rcu` + `rcu_barrier` deferred reclamation, `rcu_dereference`/`rcu_assign_pointer`) | PROVEN | LIBURCU-0001 (0 residuals; 7 phases byte-exact in the oracle-liburcu-0.15.6 container: registration state; the exact 0/1/2/1/0 nesting values; the membarrier no-ops; the grace period with no readers; the nested reader blocking the writer until unlock; unregister removing the thread from the registry (an in-flight snapshot still waits, a later grace period returns); FIFO call_rcu ordering + rcu_barrier incl. the empty queue; the publication-pair round trips) |
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
| LMDB (`mdb_env_*`/`mdb_txn_*`/`mdb_dbi_open`/`mdb_put`/`mdb_get`/`mdb_del`/`mdb_cursor_*`/`mdb_stat`/`mdb_reader_*`/`mdb_env_copy2`, the B+tree + COW page model, sorted-dup sub-pages/sub-DBs, overflow pages, the freeDB txnid-keyed records, the compacting copy) | PROVEN | LMDB-0001 (0 residuals; 8 phases: basic/named/overflow/dups/fixed/many/readers/copy, byte-exact transcripts + structured page dumps parsing data.mdb directly — split points, node order, sub-page regions, sub-DB records, freeDB IDL page lists — hence the exact COW allocation order) |
| protobuf-c (`libprotobuf-c` 1.5.2 runtime: pack/unpack/pack_to_buffer/get_packed_size, the varint/fixed/ZigZag encoders incl. 10-byte negative int32s, the length-prefix stack with its INT_MAX and hdr+val>len rejections, wire-type validation, the required-field bitmap incl. the required-with-default exemption, the scanned-member slabs, unknown-field passthrough, `merge_messages`, `message_check`, the allocator hooks, buffer-simple, `message_init_generic`, descriptor/enum lookups, service dispatch) | PROVEN | PBC-0001 (0 residuals; 21 sections: packed/unpacked/optional/oneof/defaults batteries over the pinned protoc-gen-c 1.5.2 fixtures, field-number header boundaries, check/enum/lookup batteries, services, proto3 zeroish skipping, unknown-field round-trip, merge semantics, the unpack error taxonomy, the counting-allocator trace, buffer-simple growth, the dynamic descriptor, byte-exact) |
| NetBSD editline 20260512-3.1 (`el_init`/`el_gets`/`el_set`/`el_get`/`el_parse`/`el_source`/`el_insertstr`/`el_deletestr`/`el_deletestr1`/`el_replacestr`/`el_cursor`/`el_line`, the emacs and vi keymaps, the refresh engine with cursor addressing over TERM=xterm/dumb terminfo, prompts incl. EL_PROMPT_ESC literal spans and right prompts, `HistoryW` (setsize/enter/add/append/prev/next/curr/first/last/set/prev_str/next_str/prev_event/next_event/del/clear/setunique/getunique with the exact error taxonomy), incremental and vi history search, the readline layer (`readline`/`add_history`/`history_get`/`current_history`/`previous_history`/`next_history`/`history_search_prefix`/`history_search`/`history_expand`/`clear_history`), the `Tokenizer` (`tok_init`/`tok_str`/`tok_reset`), and NO_TTY pipe reads) | PROVEN | LE-0001 (0 residuals; 29 pty sessions with fixed byte scripts — plain/backspace/killline/killu-yank/mid-insert/transpose/killword/word-motion/case/ctrl-d/history/hist-search/arrows/kill-ring/vi/vi-search/rprompt/prompt-esc/dumb/utf8/noedit/longline/clearscreen/quoted-insert/empty-prompt/vi-yank-put/vi-undo/ed-command/readline — plus 7 direct API sessions, raw pty transcripts byte-exact, stdout+stderr+exit) |
| `named` runtime | UNKNOWN | |
| Recursive resolver | UNKNOWN | |
| DNSSEC | UNKNOWN | |
| Zone transfers / journal | UNKNOWN | |
| Dynamic update | UNKNOWN | |
| `rndc` control channel | UNKNOWN | |
| Views / ACL / RPZ / catalog zones | UNKNOWN | |
| Logging / statistics / dnstap | UNKNOWN | |
| Plugins / DLZ / DynDB | UNKNOWN | |
