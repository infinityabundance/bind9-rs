//! `bind9-rs` — native Rust BIND 9 reimplementation.
//!
//! This is the public compatibility facade (spec §4.1).  It provides a
//! coherent interface over the internal architecture rather than exposing the
//! layout of the other five crates.  See `docs/architecture/` for the
//! architectural documentation, the compatibility ledger
//! (`docs/compatibility/parity-ledger.md`) for the authoritative status of
//! every compatibility surface, and `forensics/` for the executable evidence
//! that supports those statuses.
//!
//! The compatibility target is *observable BIND behavior* (§1), not merely
//! standards compliance.  Claims in this crate's documentation are backed by
//! court receipts under `forensics/receipts/`.

#![forbid(unsafe_code)]

/// Compatibility profiles (spec §58): explicit, evidence-backed historical
/// behavior modes.
pub mod profiles;
/// Version reporting: BIND version lines whose shape we reproduce.
pub mod version;

pub use bind9_core as core;
pub use bind9_platform as platform;
pub use bind9_server as server;
pub use bind9_tools as tools;
