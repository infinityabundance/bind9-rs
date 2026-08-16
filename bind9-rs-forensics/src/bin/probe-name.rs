//! `probe-name` — the bind9-rs side of the `CORE-NAME-TEXT-*` courts.
//!
//! Mirrors `forensics/oracle/probes/probe_name.c` byte-for-byte: reads one
//! raw name per stdin line, emits
//!
//! ```text
//! OK <formatted> <wire-hex> <countlabels> <length>
//! ERR <result-text>
//! ```
//!
//! where the result-text is BIND's `isc_result_totext` string (see
//! `bind9-core::error`).  The oracle probe links real libdns; this probe
//! uses bind9-core.  Byte-identical output is the parity claim; anything
//! else becomes a residual.

use bind9_rs_core::error::Error;
use bind9_rs_core::name::Name;
use std::io::{BufRead, Write};

fn main() {
    let root = Name::root();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        if line.is_empty() {
            continue;
        }
        match Name::from_text(&line, Some(&root)) {
            Ok(name) => {
                let text = name.to_text();
                let mut wire = Vec::new();
                if bind9_rs_core::name::wire::to_wire_uncompressed(&name, &mut wire).is_err() {
                    let _ = writeln!(out, "WIRE-ERR internal");
                    continue;
                }
                let hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(
                    out,
                    "OK {} {} {} {}",
                    text,
                    hex,
                    name.label_count(),
                    name.wire_len_full()
                );
            }
            Err(e) => {
                let _ = writeln!(out, "ERR {}", err_text(&e));
            }
        }
    }
}

/// The BIND `isc_result_totext` string for an error.
fn err_text(e: &Error) -> String {
    e.to_string()
}
