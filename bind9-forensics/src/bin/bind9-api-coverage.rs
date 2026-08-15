//! `bind9-api-coverage` — the custodian completeness ledger (§0, §47, §70).
//!
//! Loads the Doxygen-derived API atlas
//! (`forensics/archaeology/api-atlas/*.json`), applies the coverage rules
//! (`forensics/archaeology/api-atlas/coverage-rules.json`), and writes:
//!
//! - `api-coverage.json` — the full machine-readable matrix
//! - `COVERAGE.md` — the human-readable report
//!
//! Query mode:
//! ```text
//! bind9-api-coverage query <glob>     show status of matching surfaces
//! bind9-api-coverage summary          show status counts
//! bind9-api-coverage regen            regenerate matrix + report
//! ```
//!
//! The ledger is the answer to "do we cover EVERYTHING": every function in
//! the pinned BIND tree has a row, and nothing is PROVEN without receipts.

use std::path::PathBuf;
use std::process::ExitCode;

fn atlas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace")
        .join("forensics/archaeology/api-atlas")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprintln!("usage: bind9-api-coverage <regen|summary|query <glob>>");
        return ExitCode::from(2);
    };
    match run_cmd(cmd, &args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_cmd(cmd: &str, args: &[String]) -> Result<(), String> {
    let dir = atlas_dir();
    let invs = bind9_forensics::atlas::load_all(&dir.to_string_lossy());
    let rules =
        bind9_forensics::atlas::load_rules(&dir.join("coverage-rules.json").to_string_lossy());
    let entries = bind9_forensics::atlas::resolve(&invs, &rules);

    match cmd {
        "regen" => {
            let json = serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())?;
            std::fs::write(dir.join("api-coverage.json"), json).map_err(|e| e.to_string())?;
            std::fs::write(dir.join("COVERAGE.md"), render_markdown(&entries, &invs))
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        "summary" => {
            for (status, count) in bind9_forensics::atlas::summarize(&entries) {
                println!("{status:<28} {count:>5}");
            }
            let total = entries.len();
            println!("{:<28} {:>5}", "TOTAL", total);
            Ok(())
        }
        "query" => {
            let glob = args.get(1).ok_or("query requires a glob")?;
            let hits: Vec<_> = entries
                .iter()
                .filter(|e| bind9_forensics::atlas::glob_match(glob, &e.function))
                .collect();
            if hits.is_empty() {
                println!("no surfaces match '{glob}'");
            }
            for e in &hits {
                println!(
                    "{:<42} {:<10} {:<12} {:<18} court={} rust={}",
                    e.function,
                    e.kind,
                    e.library,
                    e.status,
                    e.courts.join(","),
                    e.rust_module
                );
            }
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            Err("unknown command".to_string())
        }
    }
}

fn render_markdown(
    entries: &[bind9_forensics::atlas::CoverageEntry],
    invs: &[bind9_forensics::atlas::AtlasInventory],
) -> String {
    let mut out = String::new();
    out.push_str("# BIND 9 API Coverage Ledger\n\n");
    out.push_str("Machine-readable form: `api-coverage.json`.  Statuses follow the parity-ledger taxonomy (§47).  A surface is `PROVEN` only with court receipts; `UNKNOWN` entries are tracked in the unknowns ledger.  Regenerate with `bind9-api-coverage regen` after updating `coverage-rules.json`.\n\n");
    out.push_str("## Scope\n\n");
    out.push_str("Every C/H surface of the pinned oracle tree is inventoried (custodian mandate: nothing C-shaped is left out).  Libraries/tools and their member-kind counts:\n\n");
    let mut total_files = 0;
    let mut total_members = 0;
    let mut kind_totals: std::collections::BTreeMap<String, usize> = Default::default();
    out.push_str("\n| Unit | Files | Functions | Macros | Enum values | Enums | Structs | Typedefs | Variables |\n|---|---|---|---|---|---|---|---|---|\n");
    for inv in invs {
        let nf = inv.files.len();
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for (_f, af) in &inv.files {
            for (kind, _m) in af.all_members() {
                *counts.entry(kind.to_string()).or_insert(0) += 1;
            }
        }
        let per_kind = |k: &str| counts.get(k).copied().unwrap_or(0);
        total_files += nf;
        for (k, c) in &counts {
            *kind_totals.entry(k.clone()).or_insert(0) += c;
            total_members += c;
        }
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            inv.library,
            nf,
            per_kind("function"),
            per_kind("macro"),
            per_kind("enum_value"),
            per_kind("enum"),
            per_kind("struct"),
            per_kind("typedef"),
            per_kind("variable")
        ));
    }
    out.push_str(&format!(
        "\n**Total: {total_files} files, {total_members} members** (pinned oracle version, see `sources/manifest-*.json`).  Kind totals: {}.\n\n",
        kind_totals
            .iter()
            .map(|(k, c)| format!("{k}={c}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str("## Status summary\n\n| Status | Count |\n|---|---|\n");
    for (status, count) in bind9_forensics::atlas::summarize(entries) {
        out.push_str(&format!("| {status} | {count} |\n"));
    }
    out.push_str("\n## Surfaces with court or rust coverage\n\n| Member | Kind | Library | Status | Court | Rust module |\n|---|---|---|---|---|---|\n");
    for e in entries {
        if e.courts.is_empty() && e.rust_module.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | `{}` |\n",
            e.function,
            e.kind,
            e.library,
            e.status,
            e.courts.join(", "),
            e.rust_module
        ));
    }
    out
}
