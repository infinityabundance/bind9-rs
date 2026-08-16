//! `bind9-rs-tools` — complete native-Rust custodian reimplementation of the
//! BIND 9 tool and dependency surface (Phase 0 addendum).
//!
//! One crate, non-negotiable (§1 of the addendum): every tool, every
//! conserved dependency module, every compatibility shim lives here as a
//! module — never in new first-party crates.
//!
//! The governing principles:
//!
//! > **Conserve the machine. Replace the hazards.**
//! > Same artifact. Same semantics. Same interfaces. Same formats. Same
//! > quirks where safe and compatibility-relevant. Safer substrate.
//! > Forensic receipts proving substitution.
//!
//! The compatibility target is *Layer C — custodian compatibility*: existing
//! infrastructure can substitute this implementation without knowing it
//! changed (§4).  A difference is evidence until proven otherwise (§5).
//!
//! Module layout (addendum §1):
//!
//! - [`common`] — shared CLI/output/diagnostics/environment/… machinery;
//! - [`tools`] — every BIND 9 utility, historical and current;
//! - [`compat`] — native Rust conservation of the infrastructure BIND's
//!   tools depend on (LMDB, fstrm, libcap, libidn2, libedit, liburcu,
//!   libuv, protobuf-c, libmaxminddb, zlib, json-c);
//! - [`platform`] — OS-specific behavior and the audited unsafe boundary;
//! - [`historical`] — the evidence-derived utility manifest and version
//!   history.
//!
//! A module whose scope is declared but whose surface is not yet
//! implemented is marked accordingly; the parity ledger
//! (`forensics/atlas/…`/`docs/compatibility/parity-ledger.md`) tracks every
//! surface — declared-but-empty is never claimed as implemented (§66).

#![forbid(unsafe_code)]

/// Shared machinery: CLI parsing, output rendering, diagnostics,
/// environment, resolver configuration, filesystem, TTY, time,
/// compatibility and versioning (§1 `common/`).
pub mod common;

/// Every BIND 9 utility, historical and current (§2).
pub mod tools;

/// Native Rust conservation modules for the infrastructure BIND's tools
/// depend upon (§3): LMDB, fstrm, libcap, libidn2, libedit, liburcu, libuv,
/// protobuf-c, libmaxminddb, zlib, json-c.
pub mod compat;

/// OS-specific behavior and the audited unsafe boundary (§1 `platform/`).
/// This module is the ONLY place in this crate where `unsafe` is
/// contemplated; every use must be registered in the unsafe inventory.
pub mod platform;

/// Evidence-derived utility manifest and version history (§2, §8).
pub mod historical;
