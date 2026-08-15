//! Residual taxonomy and records (§13, §14, §69).
//!
//! A mismatch is not noise until proven to be noise.  Every differential
//! mismatch becomes a residual; classification happens only after
//! investigation; a normalizer may suppress a field only when the reason is
//! documented and the raw value retained.

use crate::schemas::Residual;

/// The §13 residual taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResidualKind {
    Wire,
    Semantic,
    State,
    Timing,
    Ordering,
    Text,
    Cli,
    Exit,
    Filesystem,
    Permission,
    Process,
    Log,
    Statistic,
    Control,
    Security,
    Platform,
    Performance,
    Nondeterministic,
    OracleVersion,
    Harness,
    Unknown,
}

impl ResidualKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ResidualKind::Wire => "WIRE",
            ResidualKind::Semantic => "SEMANTIC",
            ResidualKind::State => "STATE",
            ResidualKind::Timing => "TIMING",
            ResidualKind::Ordering => "ORDERING",
            ResidualKind::Text => "TEXT",
            ResidualKind::Cli => "CLI",
            ResidualKind::Exit => "EXIT",
            ResidualKind::Filesystem => "FILESYSTEM",
            ResidualKind::Permission => "PERMISSION",
            ResidualKind::Process => "PROCESS",
            ResidualKind::Log => "LOG",
            ResidualKind::Statistic => "STATISTIC",
            ResidualKind::Control => "CONTROL",
            ResidualKind::Security => "SECURITY",
            ResidualKind::Platform => "PLATFORM",
            ResidualKind::Performance => "PERFORMANCE",
            ResidualKind::Nondeterministic => "NONDETERMINISTIC",
            ResidualKind::OracleVersion => "ORACLE-VERSION",
            ResidualKind::Harness => "HARNESS",
            ResidualKind::Unknown => "UNKNOWN",
        }
    }
}

/// Classification of a residual after investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// Understood and either fixed or justified.
    Explained,
    /// Reduced to a minimal reproducer.
    Minimized,
    /// Under investigation.
    Open,
    /// Cannot yet be categorized.
    Unknown,
}

impl Classification {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Classification::Explained => "explained",
            Classification::Minimized => "minimized",
            Classification::Open => "open",
            Classification::Unknown => "unknown",
        }
    }
}

/// Build a residual record from a raw mismatch.
#[must_use]
pub fn make_residual(
    residual_id: &str,
    court_id: &str,
    kind: ResidualKind,
    oracle_raw: &str,
    rust_raw: &str,
) -> Residual {
    Residual {
        schema_version: crate::schemas::SCHEMA_VERSION,
        residual_id: residual_id.to_string(),
        court_id: court_id.to_string(),
        kind: kind.as_str().to_string(),
        oracle_raw: oracle_raw.to_string(),
        rust_raw: rust_raw.to_string(),
        normalized_oracle: None,
        normalized_rust: None,
        classification: Classification::Unknown.as_str().to_string(),
        explanation: String::new(),
        minimized_reproducer: None,
        regression_invariant: None,
    }
}

/// Persist residuals for a court run: `courts/<id>/residuals/<n>.json` plus
/// a `summary.json`.  Residuals are evidence: they are never deleted by tooling.
pub fn persist_all(court: &crate::court::Court, residuals: &[Residual]) -> Result<(), String> {
    let dir = court.dir.join("residuals");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut summary = Vec::new();
    for (i, r) in residuals.iter().enumerate() {
        let p = dir.join(format!("{:04}.json", i + 1));
        let json = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| e.to_string())?;
        summary.push(r.residual_id.clone());
    }
    let summary_json = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("summary.json"), summary_json).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_residual_defaults() {
        let r = make_residual("R-1", "C-1", ResidualKind::Text, "a", "b");
        assert_eq!(r.classification, "unknown");
        assert_eq!(r.kind, "TEXT");
        assert!(r.explanation.is_empty());
    }

    #[test]
    fn taxonomy_is_complete() {
        // Every kind has a distinct machine-readable tag.
        let mut tags: Vec<&str> = [
            ResidualKind::Wire,
            ResidualKind::Semantic,
            ResidualKind::State,
            ResidualKind::Timing,
            ResidualKind::Ordering,
            ResidualKind::Text,
            ResidualKind::Cli,
            ResidualKind::Exit,
            ResidualKind::Filesystem,
            ResidualKind::Permission,
            ResidualKind::Process,
            ResidualKind::Log,
            ResidualKind::Statistic,
            ResidualKind::Control,
            ResidualKind::Security,
            ResidualKind::Platform,
            ResidualKind::Performance,
            ResidualKind::Nondeterministic,
            ResidualKind::OracleVersion,
            ResidualKind::Harness,
            ResidualKind::Unknown,
        ]
        .iter()
        .map(|k| k.as_str())
        .collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), 21);
    }
}
