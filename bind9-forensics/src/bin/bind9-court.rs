//! `bind9-court` — the forensic court runner (§12, §45, §78).
//!
//! Commands:
//! ```text
//! bind9-court list                      enumerate all courts
//! bind9-court run <court-id>            execute a court (oracle + rust + compare)
//! bind9-court run --oracle-only <id>    execute only the oracle side
//! bind9-court run --rust-only <id>      execute only the rust side
//! bind9-court compare <court-id>        compare existing captures
//! bind9-court verify-receipt <path>     verify a receipt
//! bind9-court index <out.json>          fetch the ISC release index
//! bind9-court env-digest                print the environment digest
//! ```
//!
//! A court run writes raw evidence under `captures/`, residuals under
//! `residuals/`, and a receipt under `forensics/receipts/`.  The receipt is
//! only written when both sides executed; `--oracle-only`/`--rust-only` are
//! for incremental work and produce no receipt.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprintln!("usage: bind9-court <command> [args] (see --help)");
        return ExitCode::from(2);
    };
    let result = match cmd.as_str() {
        "--help" | "-h" => {
            println!(
                "bind9-court: forensic court runner\n\n\
                 list\n\
                 run <court-id>\n\
                 run --oracle-only <court-id>\n\
                 run --rust-only <court-id>\n\
                 compare <court-id>\n\
                 verify-receipt <path>\n\
                 index <out.json>\n\
                 env-digest"
            );
            Ok(())
        }
        "list" => cmd_list(),
        "run" => cmd_run(&args[1..]),
        "compare" => cmd_compare(&args[1..]),
        "verify-receipt" => cmd_verify(&args[1..]),
        "index" => cmd_index(&args[1..]),
        "env-digest" => {
            println!("{}", bind9_forensics::receipt::environment_digest());
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            Err("unknown command".to_string())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn courts_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace")
        .join("forensics")
        .join("courts")
}

fn cmd_list() -> Result<(), String> {
    let courts = bind9_forensics::court::discover(&courts_root())?;
    if courts.is_empty() {
        println!("(no courts found under {:?})", courts_root());
        return Ok(());
    }
    for c in &courts {
        println!(
            "{:<40} {:<16} {}",
            c.id, c.manifest.subsystem, c.manifest.question
        );
    }
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("run requires a court id".to_string());
    }
    if args[0] == "--oracle-only" {
        let id = args.get(1).ok_or("run --oracle-only requires a court id")?;
        return run_side_by_id(id, "oracle");
    }
    if args[0] == "--rust-only" {
        let id = args.get(1).ok_or("run --rust-only requires a court id")?;
        return run_side_by_id(id, "rust");
    }
    let id = &args[0];
    let courts = bind9_forensics::court::discover(&courts_root())?;
    let court = courts
        .iter()
        .find(|c| &c.id == id)
        .ok_or_else(|| format!("court {id} not found"))?;
    let oracle_status = bind9_forensics::court::run_side(court, "oracle")?;
    let rust_status = bind9_forensics::court::run_side(court, "rust")?;
    let mode = bind9_forensics::court::compare_mode(court);
    let residuals = bind9_forensics::court::compare(court, mode)?;
    let repro = format!("bind9-court run {id}");
    let receipt = bind9_forensics::court::finish(court, residuals.clone(), &repro)?;
    println!(
        "court {}: oracle exit {} rust exit {}; {} residual(s); receipt {}",
        court.id,
        oracle_status,
        rust_status,
        residuals.len(),
        receipt.captures_sha256
    );
    for r in &residuals {
        println!(
            "  {} [{}]: oracle={:?} rust={:?}",
            r.residual_id,
            r.kind,
            r.oracle_raw.chars().take(80).collect::<String>(),
            r.rust_raw.chars().take(80).collect::<String>()
        );
    }
    Ok(())
}

fn run_side_by_id(id: &str, side: &str) -> Result<(), String> {
    let courts = bind9_forensics::court::discover(&courts_root())?;
    let court = courts
        .iter()
        .find(|c| &c.id == id)
        .ok_or_else(|| format!("court {id} not found"))?;
    let status = bind9_forensics::court::run_side(court, side)?;
    println!("court {} {} side: exit {}", court.id, side, status);
    Ok(())
}

fn cmd_compare(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("compare requires a court id")?;
    let courts = bind9_forensics::court::discover(&courts_root())?;
    let court = courts
        .iter()
        .find(|c| &c.id == id)
        .ok_or_else(|| format!("court {id} not found"))?;
    let mode = bind9_forensics::court::compare_mode(court);
    let residuals = bind9_forensics::court::compare(court, mode)?;
    println!("{} residual(s) for {}", residuals.len(), court.id);
    for r in &residuals {
        println!(
            "  {} [{}]: oracle={:?} rust={:?}",
            r.residual_id,
            r.kind,
            r.oracle_raw.chars().take(80).collect::<String>(),
            r.rust_raw.chars().take(80).collect::<String>()
        );
    }
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("verify-receipt requires a path")?;
    let problems = bind9_forensics::receipt::verify_receipt(std::path::Path::new(path))?;
    if problems.is_empty() {
        println!("receipt {path}: consistent");
    } else {
        for p in &problems {
            println!("problem: {p}");
        }
    }
    Ok(())
}

fn cmd_index(args: &[String]) -> Result<(), String> {
    let out = args.first().ok_or("index requires an output path")?;
    let index = bind9_forensics::release_index::fetch_remote_index()?;
    bind9_forensics::release_index::save_index(&index, std::path::Path::new(out))?;
    println!(
        "wrote {} releases to {out} (retrieved {})",
        index.releases.len(),
        index.retrieved_at
    );
    Ok(())
}
