//! The API atlas and coverage ledger (§0 custodian completeness, §47, §70).
//!
//! The atlas is generated from Doxygen XML over a pinned BIND tree
//! (scripts/archaeology/doxygen-atlas.sh) into
//! `forensics/archaeology/api-atlas/*.json`.  This module loads those
//! inventories and applies coverage rules
//! (`forensics/archaeology/api-atlas/coverage-rules.json`) to produce the
//! machine-readable `api-coverage.json` and the human-readable
//! `COVERAGE.md`.
//!
//! Coverage statuses follow the parity-ledger taxonomy (§47):
//! UNKNOWN / ARCHAEOLOGY / SCAFFOLDED / PARTIAL / ORACLE-TESTED /
//! RESIDUALS-OPEN / PROVEN / HISTORICAL-ONLY / INTENTIONALLY-UNSUPPORTED /
//! INTERNAL (no external surface).
//!
//! A function is `PROVEN` only with receipts (courts + archaeology); the
//! rules file is the assertion, the receipts are the evidence.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One inventoried function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasFunction {
    pub name: String,
    #[serde(default)]
    pub static_: bool,
    #[serde(default)]
    pub definition: String,
    #[serde(default)]
    pub args: String,
    #[serde(default)]
    pub brief: String,
    #[serde(default)]
    pub detailed: String,
    #[serde(default)]
    pub params: Vec<String>,
}

/// One inventoried file's members.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AtlasFile {
    #[serde(default)]
    pub functions: Vec<AtlasFunction>,
    #[serde(default)]
    pub typedefs: Vec<serde_json::Value>,
    #[serde(default)]
    pub enums: Vec<serde_json::Value>,
    #[serde(default)]
    pub structs: Vec<serde_json::Value>,
    #[serde(default)]
    pub macros: Vec<serde_json::Value>,
    #[serde(default)]
    pub variables: Vec<serde_json::Value>,
}

/// One library/tool inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasInventory {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub version: String,
    pub library: String,
    #[serde(default)]
    pub files: BTreeMap<String, AtlasFile>,
}

/// Load all atlas inventories from a directory.
pub fn load_all(dir: &str) -> Vec<AtlasInventory> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map(|e| e.flatten().map(|e| e.path()).collect::<Vec<_>>())
        .unwrap_or_default();
    entries.sort();
    for p in entries {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !name.starts_with("lib_") && !name.starts_with("bin_") && !name.starts_with("fuzz_") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(inv) = serde_json::from_str::<AtlasInventory>(&text) {
                out.push(inv);
            }
        }
    }
    out
}

/// Iterate (library, file, function) triples.
pub fn all_functions<'a>(
    inventories: &'a [AtlasInventory],
) -> impl Iterator<Item = (&'a str, &'a str, &'a AtlasFunction)> {
    inventories.iter().flat_map(|inv| {
        inv.files.iter().flat_map(move |(file, f)| {
            f.functions
                .iter()
                .map(move |func| (inv.library.as_str(), file.as_str(), func))
        })
    })
}

/// A coverage rule: the first matching rule for a function name wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRule {
    /// Glob pattern on the function name (`*` wildcard), or exact name.
    pub pattern: String,
    /// The §47 status.
    pub status: String,
    /// Court ID(s) that cover this surface.
    #[serde(default)]
    pub courts: Vec<String>,
    /// Rust module implementing it.
    #[serde(default)]
    pub rust_module: String,
    /// Archaeology behavior record IDs.
    #[serde(default)]
    pub archaeology: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

/// The coverage-rules file format: `{ "comment": ..., "rules": [...] }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesFile {
    #[serde(default)]
    comment: String,
    #[serde(default)]
    rules: Vec<CoverageRule>,
}

/// Load coverage rules; a missing rules file yields the empty rule set
/// (everything UNKNOWN — never assume coverage).
pub fn load_rules(path: &str) -> Vec<CoverageRule> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<RulesFile>(&t).ok())
        .map(|f| f.rules)
        .unwrap_or_default()
}

/// Glob match supporting a single trailing `*` (fnmatch-lite).
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        pattern == name
    }
}

/// The resolved coverage entry for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub library: String,
    pub file: String,
    pub function: String,
    pub static_: bool,
    pub definition: String,
    pub status: String,
    pub courts: Vec<String>,
    pub rust_module: String,
    pub archaeology: Vec<String>,
    pub notes: String,
}

/// Apply rules to all functions; first matching rule wins, then a synthetic
/// catch-all INTERNAL for static helpers with no doc, else UNKNOWN.
pub fn resolve(inventories: &[AtlasInventory], rules: &[CoverageRule]) -> Vec<CoverageEntry> {
    let mut out = Vec::new();
    for (lib, file, func) in all_functions(inventories) {
        let matched = rules.iter().find(|r| glob_match(&r.pattern, &func.name));
        let (status, courts, rust_module, archaeology, notes) = match matched {
            Some(r) => (
                r.status.clone(),
                r.courts.clone(),
                r.rust_module.clone(),
                r.archaeology.clone(),
                r.notes.clone(),
            ),
            None => {
                if func.static_ && func.brief.is_empty() {
                    // Internal helper with no documented surface; archived
                    // by source but not a compatibility surface.
                    (
                        "INTERNAL".to_string(),
                        Vec::new(),
                        String::new(),
                        Vec::new(),
                        "static helper, no external surface".to_string(),
                    )
                } else {
                    (
                        "UNKNOWN".to_string(),
                        Vec::new(),
                        String::new(),
                        Vec::new(),
                        "no coverage rule yet — see unknowns ledger".to_string(),
                    )
                }
            }
        };
        out.push(CoverageEntry {
            library: lib.to_string(),
            file: file.to_string(),
            function: func.name.clone(),
            static_: func.static_,
            definition: func.definition.clone(),
            status,
            courts,
            rust_module,
            archaeology,
            notes,
        });
    }
    out
}

/// Summarize the coverage matrix per status.
#[must_use]
pub fn summarize(entries: &[CoverageEntry]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for e in entries {
        *m.entry(e.status.clone()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching() {
        assert!(glob_match("dns_name_*", "dns_name_fromtext"));
        assert!(glob_match("dns_name_*", "dns_name_totext"));
        assert!(!glob_match("dns_name_*", "dns_message_parse"));
        assert!(glob_match("dns_message_parse", "dns_message_parse"));
        assert!(!glob_match("dns_message_parse", "dns_message_parsed"));
    }

    #[test]
    fn resolve_falls_back_to_unknown() {
        let inv = AtlasInventory {
            schema_version: 1,
            version: "9.20.26".to_string(),
            library: "lib/dns".to_string(),
            files: BTreeMap::from([(
                "name.c".to_string(),
                AtlasFile {
                    functions: vec![AtlasFunction {
                        name: "dns_name_fromtext".to_string(),
                        static_: false,
                        definition: "isc_result_t dns_name_fromtext".to_string(),
                        args: String::new(),
                        brief: "doc".to_string(),
                        detailed: String::new(),
                        params: Vec::new(),
                    }],
                    ..Default::default()
                },
            )]),
        };
        let entries = resolve(&[inv], &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, "UNKNOWN");
    }
}
