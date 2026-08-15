//! `bind9-platform` — OS-specific behavior and audited unsafe boundaries
//! (§4.6).
//!
//! Socket, transport, interface, privileges, daemon, pidfile, chroot,
//! signals, timers, entropy, process and resource-limit behavior live here.
//! The rest of the codebase consumes safe abstractions with explicit
//! invariants; no convenience `unsafe` may leak upward.
//!
//! Every `unsafe` item in this crate is registered in
//! `docs/unsafe/unsafe-inventory.md` with its safety invariant, caller
//! obligations, platform, test coverage and audit status (§55).
//!
//! Dependency policy: `getrandom` is the sole dependency — the audited,
//! widely-reviewed interface to the OS CSPRNG, used for cookies, TSIG
//! nonces and test seeds.  Alternatives considered: `/dev/urandom` reads
//! (platform-fragile), bespoke entropy (forbidden by §25/§54).

#![allow(unsafe_code)]

/// Time: clocks with controllable behavior (needed for DNSSEC state
/// machines and TTL courts, §26).
pub mod clock;

/// Randomness and entropy (server IDs, DNS cookies, TSIG nonces, ...).
pub mod random;
