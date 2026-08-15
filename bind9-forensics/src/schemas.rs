//! The machine-readable archive schemas (§10, §45, §70).
//!
//! These structs ARE the contracts: archaeology records, the release index,
//! version deltas, court manifests, residuals, receipts and evidence packs
//! serialize to TOML/JSON so that tests can query them and tools can verify
//! them.  Human-readable reports are generated from these, never the other
//! way around.
//!
//! Schema stability: fields here are versioned in `schema_version`.  Adding
//! a field is a minor change; removing/renaming one is a major change and
//! must update every parser and the verifier.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current archive schema version.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Release index (§10, §81)
// ---------------------------------------------------------------------------

/// One release directory on downloads.isc.org, as inventoried.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRecord {
    /// e.g. "9.20.26".
    pub version: String,
    /// Where the directory listing was observed (retrieval event).
    pub observed_at: String,
    /// The listing URL.
    pub source_url: String,
}

/// The full release index: the machine-readable version atlas seed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseIndex {
    pub schema_version: u32,
    /// ISO-8601 UTC retrieval timestamp.
    pub retrieved_at: String,
    /// The URL the index was derived from.
    pub source_url: String,
    pub releases: Vec<ReleaseRecord>,
}

// ---------------------------------------------------------------------------
// Source manifest (§45, §78)
// ---------------------------------------------------------------------------

/// A pinned upstream source artifact (tarball), with provenance and hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceManifest {
    pub schema_version: u32,
    /// BIND version, e.g. "9.20.26".
    pub version: String,
    /// The exact download URL.
    pub url: String,
    /// SHA-256 of the archive as retrieved.
    pub sha256: String,
    /// Archive size in bytes.
    pub size_bytes: u64,
    /// ISO-8601 UTC retrieval timestamp.
    pub retrieved_at: String,
    /// How provenance was checked (signature verification, checksum cross-check).
    pub provenance: String,
    /// Extracted source tree hash (whole-tree digest) if computed.
    pub tree_sha256: Option<String>,
}

// ---------------------------------------------------------------------------
// Behavior atlas record (§5)
// ---------------------------------------------------------------------------

/// A single archived behavior, e.g. `B9H-RESOLVER-00421`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorRecord {
    /// The behavior ID, e.g. "B9H-RESOLVER-00421".
    pub behavior_id: String,
    pub subsystem: String,
    /// First version where evidence places the behavior ("" = unknown).
    pub first_known_version: String,
    /// Last version where evidence places it ("" = current/unknown).
    pub last_known_version: String,
    /// "current", "historical", "changed", "removed", "unknown".
    pub status: String,
    /// Source references (URLs, commits, docs) — provenance required.
    pub sources: Vec<String>,
    /// Confidence: "proven", "likely", "hypothesis", "unknown".
    pub confidence: String,
    /// Observable surface (what a test would observe).
    pub observable_surface: String,
    /// Test status: "untested", "oracle-tested", "courted", "regression-invariant".
    pub test_status: String,
    /// Rust implementation status.
    pub rust_status: String,
    /// Security relevance: "" if none.
    pub security_relevance: String,
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Version delta (§6)
// ---------------------------------------------------------------------------

/// One observed change across a version transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionDelta {
    /// e.g. "9.16 -> 9.18".
    pub transition: String,
    /// Category from the §6 taxonomy.
    pub category: String,
    /// What changed, precisely.
    pub description: String,
    /// How old forms are treated: "accepted", "warning", "error", "ignored",
    /// "translated", "different-default", "different-output", "removed",
    /// "unknown".
    pub disposition: String,
    /// Evidence references.
    pub sources: Vec<String>,
}

// ---------------------------------------------------------------------------
// Court manifest (§12)
// ---------------------------------------------------------------------------

/// A court manifest: the contract for one compatibility question.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CourtManifest {
    pub schema_version: u32,
    /// Court ID, e.g. "CORE-NAME-TEXT-0001".
    pub court_id: String,
    /// The narrow compatibility question.
    pub question: String,
    /// Subsystem (e.g. "dns/name", "cli/dig").
    pub subsystem: String,
    /// Oracle versions this court is pinned against.
    pub oracle_versions: Vec<String>,
    /// Which harness runs the court ("probe", "dig", "named-checkzone",
    /// "message", "custom").
    pub harness: String,
    /// Normalization rules (documented reasons only, §13).
    pub normalization: Vec<String>,
    /// Expected invariants (semantic checks that must hold).
    pub invariants: Vec<String>,
    /// Timeout for oracle execution.
    pub timeout_secs: u64,
    /// Nondeterminism policy.
    pub nondeterminism_policy: String,
    /// Security classification.
    pub security_classification: String,
    /// References (RFCs, BIND sources, courts, issues).
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Residual (§13)
// ---------------------------------------------------------------------------

/// A differential mismatch, retained as evidence until explained.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Residual {
    pub schema_version: u32,
    /// Residual ID, e.g. "RESIDUAL-CORE-NAME-TEXT-0001-0003".
    pub residual_id: String,
    pub court_id: String,
    /// The §13 residual type.
    pub kind: String,
    /// Raw oracle observation (never normalized away).
    pub oracle_raw: String,
    /// Raw rust observation.
    pub rust_raw: String,
    /// Normalized comparison if any.
    pub normalized_oracle: Option<String>,
    pub normalized_rust: Option<String>,
    /// Classification: "explained", "minimized", "open", "unknown".
    pub classification: String,
    /// Explanation (empty while open).
    pub explanation: String,
    /// Link to minimized reproducer if any.
    pub minimized_reproducer: Option<String>,
    /// Link to regression invariant if one was added.
    pub regression_invariant: Option<String>,
}

// ---------------------------------------------------------------------------
// Receipt (§45)
// ---------------------------------------------------------------------------

/// A reproducible receipt: what was run, on what, with what result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub schema_version: u32,
    pub court_id: String,
    /// Git commit of the code under test.
    pub git_commit: String,
    /// Rust compiler version.
    pub rustc_version: String,
    /// Cargo.lock hash ("" if absent).
    pub cargo_lock_sha256: String,
    /// Oracle image digest / binary hash per oracle version.
    pub oracle_hashes: BTreeMap<String, String>,
    /// Environment digest (kernel, arch, locale, ...).
    pub environment_digest: String,
    /// ISO-8601 UTC completion time.
    pub completed_at: String,
    /// Input fixture hashes.
    pub input_hashes: BTreeMap<String, String>,
    /// Residuals produced by this run.
    pub residual_ids: Vec<String>,
    /// Invariant checks that passed.
    pub invariants_passed: Vec<String>,
    /// The raw capture directory hash (evidence integrity).
    pub captures_sha256: String,
    /// The command used to reproduce.
    pub repro_command: String,
}

// ---------------------------------------------------------------------------
// Evidence pack manifest (§46)
// ---------------------------------------------------------------------------

/// The manifest of a milestone evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePack {
    pub schema_version: u32,
    pub pack_id: String,
    pub created_at: String,
    /// Component → status.
    pub components: BTreeMap<String, String>,
    /// Component → receipt IDs.
    pub receipts: BTreeMap<String, Vec<String>>,
}
