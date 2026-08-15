//! Release index: the machine-readable version atlas seed (§10, §81).
//!
//! Fetches the authoritative ISC directory listing
//! (`https://downloads.isc.org/isc/bind9/`), records the retrieval
//! timestamp, and persists a [`ReleaseIndex`].  Updating the oracle baseline
//! is a forensic event (spec §81): the old and new indexes are both kept.

use crate::schemas::{ReleaseIndex, ReleaseRecord, SCHEMA_VERSION};
use std::path::Path;
use std::process::Command;

/// The authoritative ISC release directory.
pub const ISC_BIND9_URL: &str = "https://downloads.isc.org/isc/bind9/";

/// Fetch and parse the current ISC release index.
///
/// Requires `curl` (documented external tool, oracle side only).  Returns an
/// error if the listing cannot be retrieved — callers must never synthesize
/// an index (that would manufacture evidence, §66).
pub fn fetch_remote_index() -> Result<ReleaseIndex, String> {
    let out = Command::new("curl")
        .args(["-sS", "-m", "60", ISC_BIND9_URL])
        .output()
        .map_err(|e| format!("failed to run curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("curl exited with {:?}", out.status.code()));
    }
    let body = String::from_utf8(out.stdout).map_err(|_| "listing is not UTF-8".to_string())?;
    let now = iso_now();
    let mut versions = parse_versions(&body);
    versions.sort();
    versions.dedup();
    Ok(ReleaseIndex {
        schema_version: SCHEMA_VERSION,
        retrieved_at: now.clone(),
        source_url: ISC_BIND9_URL.to_string(),
        releases: versions
            .into_iter()
            .map(|version| ReleaseRecord {
                version,
                observed_at: now.clone(),
                source_url: ISC_BIND9_URL.to_string(),
            })
            .collect(),
    })
}

/// Extract `9.x.y` version directories from an HTML directory listing.
fn parse_versions(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'9' && bytes[i + 1] == b'.' {
            let start = i;
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            if j > start {
                let v = &html[start..j];
                if v.split('.').count() >= 2 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                    out.push(v.to_string());
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// ISO-8601 UTC now.
pub fn iso_now() -> String {
    // No chrono dependency: format from the system clock.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Days since epoch.
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 } as u64;
    let yy = if mth <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yy, mth, d, h, m, s)
}

/// Persist an index as JSON.
pub fn save_index(index: &ReleaseIndex, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(index).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

/// Load a persisted index.
pub fn load_index(path: &Path) -> Result<ReleaseIndex, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listing() {
        let html = "<html><a href=\"9.0.0/\">9.0.0/</a><a href=\"9.20.26/\">9.20.26/</a><a href=\"9.21.24/\"></a>not-a-version 9.x junk 9.11.1/</html>";
        let v = parse_versions(html);
        assert!(v.contains(&"9.0.0".to_string()));
        assert!(v.contains(&"9.20.26".to_string()));
        assert!(v.contains(&"9.21.24".to_string()));
        assert!(v.contains(&"9.11.1".to_string()));
        assert!(!v.contains(&"9.x".to_string()));
    }

    #[test]
    fn iso_format() {
        let s = iso_now();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }
}
