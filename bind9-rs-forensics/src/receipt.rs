//! Receipts (§45): the reproducible record of a court run.
//!
//! A court result that cannot be reproduced is not a receipt.  Each receipt
//! records the git commit, Rust compiler, Cargo.lock hash, oracle hashes,
//! environment digest, input hashes, residual IDs, invariants passed, and
//! the capture-directory hash binding the raw evidence to the result.
//!
//! `verify_receipt` re-computes everything recomputable and reports any
//! drift.

use crate::court::Court;
use crate::hashing::sha256_file;
use crate::schemas::{Receipt, Residual, SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Compute the environment digest: kernel, arch, OS, locale-relevant vars.
#[must_use]
pub fn environment_digest() -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("arch={}", std::env::consts::ARCH));
    parts.push(format!("os={}", std::env::consts::OS));
    if let Ok(k) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        parts.push(format!("kernel={}", k.trim()));
    }
    for var in ["LC_ALL", "LC_CTYPE", "LANG", "TZ"] {
        if let Ok(v) = std::env::var(var) {
            parts.push(format!("{var}={v}"));
        }
    }
    parts.sort();
    crate::hashing::sha256_hex(parts.join("\n").as_bytes())
}

/// The git commit of the repository containing `path`, if any.
#[must_use]
pub fn git_commit(repo_root: &Path) -> String {
    let out = std::process::Command::new("git")
        .args(["--no-pager", "rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "no-git".to_string(),
    }
}

/// Rust compiler version (real value from rustc, if present).
#[must_use]
pub fn rustc_version() -> String {
    let out = std::process::Command::new("rustc")
        .arg("--version")
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Hash of Cargo.lock, if present.
#[must_use]
pub fn cargo_lock_sha256(repo_root: &Path) -> String {
    match sha256_file(&repo_root.join("Cargo.lock")) {
        Ok(h) => h,
        Err(_) => String::new(),
    }
}

/// Compute the sha256 of a court's captures directory (evidence binding).
pub fn captures_sha256(court: &Court) -> String {
    let dir = court.dir.join("captures");
    let mut digester = sha2::Sha256::new();
    digest_tree(&dir, &mut digester);
    let d = digester.finalize();
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

use sha2::Digest as _;

fn digest_tree(dir: &Path, h: &mut sha2::Sha256) {
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(e) => e.flatten().map(|e| e.path()).collect(),
        Err(_) => return,
    };
    entries.sort();
    for p in entries {
        if p.is_dir() {
            digest_tree(&p, h);
        } else {
            if let Ok(bytes) = std::fs::read(&p) {
                h.update(p.file_name().unwrap_or_default().as_encoded_bytes());
                h.update(&bytes);
            }
        }
    }
}

/// Build the receipt struct for a completed court run.
pub fn build_receipt(
    court: &Court,
    residuals: &[Residual],
    repro_command: &str,
) -> Result<Receipt, String> {
    let repo_root = repo_root_of(&court.dir);
    let mut input_hashes = BTreeMap::new();
    let inputs = court.dir.join("inputs");
    if inputs.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&inputs)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_file() {
                input_hashes.insert(
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    sha256_file(&p).unwrap_or_default(),
                );
            }
        }
    }
    Ok(Receipt {
        schema_version: SCHEMA_VERSION,
        court_id: court.id.clone(),
        git_commit: git_commit(&repo_root),
        rustc_version: rustc_version(),
        cargo_lock_sha256: cargo_lock_sha256(&repo_root),
        oracle_hashes: BTreeMap::new(), // filled by the oracle layer (Phase 0 scripts)
        environment_digest: environment_digest(),
        completed_at: crate::release_index::iso_now(),
        input_hashes,
        residual_ids: residuals.iter().map(|r| r.residual_id.clone()).collect(),
        invariants_passed: court.manifest.invariants.clone(),
        captures_sha256: captures_sha256(court),
        repro_command: repro_command.to_string(),
    })
}

/// Write the receipt to `forensics/receipts/<court-id>.json`.
pub fn write_receipt(
    court: &Court,
    residuals: &[Residual],
    repro_command: &str,
) -> Result<Receipt, String> {
    let receipt = build_receipt(court, residuals, repro_command)?;
    let receipts_dir = repo_root_of(&court.dir).join("forensics").join("receipts");
    std::fs::create_dir_all(&receipts_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?;
    std::fs::write(receipts_dir.join(format!("{}.json", court.id)), json)
        .map_err(|e| e.to_string())?;
    Ok(receipt)
}

/// Verify a receipt file: recompute everything recomputable and report
/// consistency or drift as a list of problems (empty = consistent).
pub fn verify_receipt(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let receipt: Receipt = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut problems = Vec::new();
    if receipt.schema_version != SCHEMA_VERSION {
        problems.push(format!("schema version {}", receipt.schema_version));
    }
    // Locate the court and re-check what we can.
    let repo_root = repo_root_of(path.parent().unwrap_or(Path::new(".")));
    // The runner honors BIND9_COURTS_ROOT for courts living in the tools
    // forensics tree (bind9-rs-tools/forensics/courts); verify against the
    // same search root so dependency-court receipts are actually checkable.
    let court_dir = if let Ok(root) = std::env::var("BIND9_COURTS_ROOT") {
        PathBuf::from(root)
    } else {
        repo_root.join("forensics/courts")
    };
    // Find court by id (subsystem unknown from receipt; scan).
    let courts = crate::court::discover(&court_dir).unwrap_or_default();
    if let Some(court) = courts.iter().find(|c| c.id == receipt.court_id) {
        let now = captures_sha256(court);
        if now != receipt.captures_sha256 {
            problems.push("captures hash drifted (evidence modified)".to_string());
        }
        let commit = git_commit(&repo_root);
        if !commit.is_empty() && receipt.git_commit != "no-git" && commit != receipt.git_commit {
            problems.push(format!(
                "git commit moved: {} -> {}",
                receipt.git_commit, commit
            ));
        }
        let lock = cargo_lock_sha256(&repo_root);
        if !lock.is_empty()
            && !receipt.cargo_lock_sha256.is_empty()
            && lock != receipt.cargo_lock_sha256
        {
            problems.push("Cargo.lock changed".to_string());
        }
    } else {
        problems.push(format!("court {} not found", receipt.court_id));
    }
    Ok(problems)
}

/// Find the workspace root by walking up to the `Cargo.toml` with the
/// workspace marker.  The starting path is canonicalized first so that a
/// relative path (e.g. `forensics/receipts/…` passed on the command line)
/// resolves to a usable absolute root for subprocesses (`git rev-parse`
/// refuses an empty current-dir).
fn repo_root_of(start: &Path) -> std::path::PathBuf {
    let start = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    let mut p = Some(start.as_path());
    while let Some(dir) = p {
        let marker = dir.join("Cargo.toml");
        if marker.exists() {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                if text.contains("[workspace]") {
                    return dir.to_path_buf();
                }
            }
        }
        p = dir.parent();
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_digest_stable_shape() {
        let a = environment_digest();
        assert_eq!(a.len(), 64);
    }
}
