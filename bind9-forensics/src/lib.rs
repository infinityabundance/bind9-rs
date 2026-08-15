//! `bind9-forensics` — the methodological heart of the project (§4.5).
//!
//! This crate turns vague compatibility claims into reproducible evidence:
//!
//! ```text
//! ARCHAEOLOGY → BEHAVIORAL HYPOTHESIS → ORACLE EXPERIMENT → RAW EVIDENCE
//!   → RUST IMPLEMENTATION → DIFFERENTIAL COURT → RESIDUAL
//!   → RESIDUAL CLASSIFICATION → MINIMIZED REPRODUCER
//!   → IMPLEMENTATION FIX / EXPLICIT EXPLANATION → REGRESSION INVARIANT
//!   → REPRODUCIBLE RECEIPT
//! ```
//!
//! Residual primacy (§13): a mismatch is not noise until proven to be noise.
//! Raw evidence is always stored; a normalizer may suppress a field only when
//! the suppression reason is documented and the original raw value retained.
//!
//! This crate is evidence tooling only.  It is never a dependency of the
//! production runtime, and nothing here may require BIND at runtime (§4.5).

#![forbid(unsafe_code)]

pub mod atlas;
pub mod court;
pub mod hashing;
pub mod receipt;
pub mod release_index;
pub mod residual;
pub mod schemas;
