# Unsafe Inventory

Every `unsafe` item in the workspace, with its safety invariant, caller
obligations, platform, test coverage, Miri status, sanitizer status, fuzz
coverage and audit status (spec §55).  Workspace policy: `unsafe_code =
"forbid"` everywhere except `bind9-rs-platform`, the designated boundary crate
(§4.6).

| Location | Reason | Invariant | Caller obligations | Platform | Tests | Miri | Sanitizers | Fuzz | Audit |
|---|---|---|---|---|---|---|---|---|---|
| `bind9-rs-tools` `platform::linux` (the audited OS/ABI boundary) | the crate root `#![deny(unsafe_code)]` admits unsafe only here; every libc call lives in this module with an inventory ID | the authoritative registry is `bind9-rs-tools/src/platform/unsafe_boundary.rs` (U-0001..U-0054): libcap/xattr/prctl/process primitives, the libuv event-loop syscalls (eventfd/poll/socket/bind/connect/sendmsg/recvmsg/sigaction/dl/getrandom/allocator fallback), each with its documented safety invariant | compat modules (`compat::libcap`, `compat::libuv`, …) call only these wrappers and stay safe Rust | linux (x86_64/gnu) | the per-entry court columns in `unsafe_boundary.rs` (libcap/zlib/LMDB/LIBUV-0001 courts) | not applicable to FFI kernel calls; pointer/buffer construction exercised by unit + court tests | release CI (§62, §63) | — | release audit reads `inventory::ENTRIES` |

Policy: any new `unsafe` must be isolated, justified, documented with its
safety invariant, tested, located at an intentional boundary, audited, and
kept out of protocol/business logic.
