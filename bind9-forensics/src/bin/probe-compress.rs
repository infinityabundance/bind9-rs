//! `probe-compress` — bind9-rs side of the `RENDER-COMPRESS-*` courts.
//! Mirrors `forensics/oracle/probes/probe_compress.c`: each stdin line is a
//! name rendered into a shared buffer with a persistent compressor; the
//! cumulative buffer hex is printed after each name.
//!
//! argv[1] selects the compression-context flags (comma-separated, as in
//! the C probe):
//! - `disabled`: DNS_COMPRESS_DISABLED (no table updates, no pointers)
//! - `case`: DNS_COMPRESS_CASE (case-sensitive matching; named's default)
//! - `large`: DNS_COMPRESS_LARGE (1024-slot table; AXFR/nsupdate)
//! - `nopermit`: pointers suppressed but names still populate the table

use bind9_core::message::compression::Compressor;
use bind9_core::name::Name;
use std::io::{BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags = args.first().map(String::as_str).unwrap_or("");
    let disabled = flags.split(',').any(|f| f == "disabled");
    let case = flags.split(',').any(|f| f == "case");
    let large = flags.split(',').any(|f| f == "large");
    let nopermit = flags.split(',').any(|f| f == "nopermit");

    let root = Name::root();
    let mut comp = Compressor::with_flags(disabled, large, case);
    if nopermit {
        comp.set_permitted(false);
    }
    let mut msg: Vec<u8> = Vec::new();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        if line.is_empty() {
            continue;
        }
        match Name::from_text(&line, Some(&root)) {
            Ok(name) => {
                comp.render(&name, &mut msg);
                let hex: String = msg.iter().map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(out, "{hex}");
            }
            Err(e) => {
                let _ = writeln!(out, "ERR {e}");
            }
        }
    }
}
