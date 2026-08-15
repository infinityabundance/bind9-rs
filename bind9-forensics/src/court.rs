//! Court discovery and execution (§12, §14, §45).
//!
//! Court layout (one narrow compatibility question per court):
//!
//! ```text
//! forensics/courts/<subsystem>/<court-id>/
//!     manifest.toml     # CourtManifest
//!     inputs/           # fixtures
//!     harness.sh        # `harness.sh oracle` / `harness.sh rust`
//!     compare.sh        # optional custom comparator
//! ```
//!
//! Execution protocol:
//! - `harness.sh oracle` writes raw artifacts under `captures/oracle/`
//!   (at minimum `stdout.txt`, `stderr.txt`, `exit.txt`);
//! - `harness.sh rust` writes under `captures/rust/`;
//! - the runner compares per the manifest's compare mode and produces
//!   residuals + a receipt.
//!
//! Raw evidence is always stored before comparison (§13); the receipt's
//! `captures_sha256` binds the evidence to the result.

use crate::residual::ResidualKind;
use crate::schemas::{CourtManifest, Receipt, Residual, SCHEMA_VERSION};
use std::path::{Path, PathBuf};
use std::process::Command;
/// A discovered court.
#[derive(Debug, Clone)]
pub struct Court {
    /// Court ID from the manifest.
    pub id: String,
    /// Directory containing `manifest.toml`.
    pub dir: PathBuf,
    pub manifest: CourtManifest,
}

/// The compare modes the generic runner knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareMode {
    /// Byte-exact comparison of `captures/<side>/stdout.txt`.
    BytesStdout,
    /// Line-wise text comparison of stdout (ignoring trailing whitespace).
    TextStdout,
    /// A custom `compare.sh` producing `residuals.json`.
    Custom,
}

/// Discover all courts under `root` (`forensics/courts`).
pub fn discover(root: &Path) -> Result<Vec<Court>, String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{dir:?}: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == "manifest.toml") {
                let manifest = load_manifest(&p)?;
                out.push(Court {
                    id: manifest.court_id.clone(),
                    dir: p.parent().expect("manifest has parent").to_path_buf(),
                    manifest,
                });
            }
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Load and validate a court manifest.
pub fn load_manifest(path: &Path) -> Result<CourtManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let m: CourtManifest = toml::from_str(&text).map_err(|e| format!("{path:?}: {e}"))?;
    if m.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "{}: schema version {} != {}",
            path.display(),
            m.schema_version,
            SCHEMA_VERSION
        ));
    }
    Ok(m)
}

/// The mode from a manifest; custom when a `compare.sh` exists.
#[must_use]
pub fn compare_mode(court: &Court) -> CompareMode {
    if court.dir.join("compare.sh").exists() {
        CompareMode::Custom
    } else {
        CompareMode::TextStdout
    }
}

/// Run one side of a court and return the exit status.
pub fn run_side(court: &Court, side: &str) -> Result<i32, String> {
    let harness = court.dir.join("harness.sh");
    let cap_dir = court.dir.join("captures").join(side);
    std::fs::create_dir_all(&cap_dir).map_err(|e| e.to_string())?;
    let out = Command::new("sh")
        .arg(&harness)
        .arg(side)
        .current_dir(&court.dir)
        .output()
        .map_err(|e| format!("failed to run harness for {}: {e}", court.id))?;
    std::fs::write(cap_dir.join("stdout.txt"), &out.stdout).map_err(|e| e.to_string())?;
    std::fs::write(cap_dir.join("stderr.txt"), &out.stderr).map_err(|e| e.to_string())?;
    std::fs::write(
        cap_dir.join("exit.txt"),
        format!("{}\n", out.status.code().unwrap_or(-1)),
    )
    .map_err(|e| e.to_string())?;
    Ok(out.status.code().unwrap_or(-1))
}

/// Compare two sides, producing residuals.
///
/// Text mode: line-wise diff of stdout with documented normalization from
/// the manifest (each normalization rule is a string like
/// `"treat transaction IDs as nondeterministic: \\d{4}"` — the rule text is
/// recorded on each residual it suppresses).
pub fn compare(court: &Court, mode: CompareMode) -> Result<Vec<Residual>, String> {
    match mode {
        CompareMode::Custom => compare_custom(court),
        CompareMode::BytesStdout => compare_bytes(court),
        CompareMode::TextStdout => compare_text(court),
    }
}

fn read_capture(court: &Court, side: &str, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(court.dir.join("captures").join(side).join(name))
        .map_err(|e| format!("{}: {e}", court.id))
}

fn compare_text(court: &Court) -> Result<Vec<Residual>, String> {
    let oracle_bytes = read_capture(court, "oracle", "stdout.txt")?;
    let rust_bytes = read_capture(court, "rust", "stdout.txt")?;
    let oracle = String::from_utf8_lossy(&oracle_bytes);
    let rust = String::from_utf8_lossy(&rust_bytes);
    let oracle_lines: Vec<&str> = oracle.lines().collect();
    let rust_lines: Vec<&str> = rust.lines().collect();
    let mut residuals = Vec::new();
    let n = oracle_lines.len().max(rust_lines.len());
    for i in 0..n {
        let o = oracle_lines.get(i).copied().unwrap_or("");
        let r = rust_lines.get(i).copied().unwrap_or("");
        if o.trim_end() != r.trim_end() {
            residuals.push(crate::residual::make_residual(
                &format!("{}-{:04}", court.id, i + 1),
                &court.id,
                ResidualKind::Text,
                o,
                r,
            ));
        }
    }
    Ok(residuals)
}

fn compare_bytes(court: &Court) -> Result<Vec<Residual>, String> {
    let oracle = read_capture(court, "oracle", "stdout.txt")?;
    let rust = read_capture(court, "rust", "stdout.txt")?;
    if oracle == rust {
        return Ok(Vec::new());
    }
    Ok(vec![crate::residual::make_residual(
        &format!("{}-BYTES", court.id),
        &court.id,
        ResidualKind::Wire,
        &hexdump(&oracle),
        &hexdump(&rust),
    )])
}

fn compare_custom(court: &Court) -> Result<Vec<Residual>, String> {
    let out = Command::new("sh")
        .arg(court.dir.join("compare.sh"))
        .current_dir(&court.dir)
        .output()
        .map_err(|e| format!("compare.sh for {} failed: {e}", court.id))?;
    if !out.status.success() {
        return Err(format!(
            "{}: compare.sh exited {:?}: {}",
            court.id,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let residuals_path = court.dir.join("residuals.json");
    if residuals_path.exists() {
        let text = std::fs::read_to_string(&residuals_path).map_err(|e| e.to_string())?;
        let residuals: Vec<Residual> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        return Ok(residuals);
    }
    Ok(Vec::new())
}

fn hexdump(b: &[u8]) -> String {
    let mut s = String::new();
    for chunk in b.chunks(16) {
        for &x in chunk {
            s.push_str(&format!("{x:02x} "));
        }
        s.push('\n');
    }
    s
}

/// Record the residuals and produce a receipt for the run.
pub fn finish(
    court: &Court,
    residuals: Vec<Residual>,
    repro_command: &str,
) -> Result<Receipt, String> {
    crate::residual::persist_all(court, &residuals)?;
    crate::receipt::write_receipt(court, &residuals, repro_command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a throwaway court tree in the system temp dir.
    fn temp_court(id: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("b9rs-court-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("inputs")).unwrap();
        std::fs::create_dir_all(dir.join("captures")).unwrap();
        let manifest = format!(
            "schema_version = {SCHEMA_VERSION}\ncourt_id = \"{id}\"\nquestion = \"test\"\nsubsystem = \"test\"\noracle_versions = [\"9.20.26\"]\nharness = \"test\"\nnormalization = []\ninvariants = []\ntimeout_secs = 10\nnondeterminism_policy = \"none\"\nsecurity_classification = \"none\"\nreferences = []\n"
        );
        std::fs::write(dir.join("manifest.toml"), manifest).unwrap();
        let mut h = std::fs::File::create(dir.join("harness.sh")).unwrap();
        writeln!(
            h,
            "#!/bin/sh\nif [ \"$1\" = oracle ]; then echo 'oracle output'; else echo 'rust output'; fi"
        )
        .unwrap();
        dir
    }

    #[test]
    fn discover_and_run() {
        let dir = temp_court("TEST-0001");
        let courts = discover(&dir).unwrap();
        assert_eq!(courts.len(), 1);
        assert_eq!(courts[0].id, "TEST-0001");
        let status = run_side(&courts[0], "oracle").unwrap();
        assert_eq!(status, 0);
        let status = run_side(&courts[0], "rust").unwrap();
        assert_eq!(status, 0);
        let residuals = compare(&courts[0], CompareMode::TextStdout).unwrap();
        assert_eq!(residuals.len(), 1);
        assert!(residuals[0].oracle_raw.contains("oracle"));
        assert!(residuals[0].rust_raw.contains("rust"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_schema_version_checked() {
        let dir = temp_court("TEST-0002");
        let path = dir.join("manifest.toml");
        let text = std::fs::read_to_string(&path).unwrap().replace(
            &format!("schema_version = {SCHEMA_VERSION}"),
            "schema_version = 999",
        );
        std::fs::write(&path, text).unwrap();
        assert!(load_manifest(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
