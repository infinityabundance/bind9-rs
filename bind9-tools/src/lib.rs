//! `bind9-tools` — BIND 9 command-line utilities (§4.4).
//!
//! All binaries share protocol/semantic implementations with `bind9-core`.
//! The historical utility manifest is built from evidence
//! (`forensics/archaeology/utility-index.json`), not from assumptions.
//!
//! CLI parity (§32) is a courted surface: arguments, defaults, formatting,
//! exit status, stdin behavior, error wording.

#![forbid(unsafe_code)]

/// Historical utility manifest (archaeology-derived, §4.4).
pub mod manifest;

/// The `dig` implementation (Phase 2; §4.4, §32).
pub mod dig;

/// Tool version reporting.
pub mod version;
