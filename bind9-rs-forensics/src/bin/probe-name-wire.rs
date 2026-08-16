//! `probe-name-wire` — the bind9-rs side of the `CORE-NAME-WIRE-*` courts.
//!
//! Mirrors `forensics/oracle/probes/probe_name_wire.c`: reads
//! "<hex-wire> <offset>" lines from stdin, parses a (possibly compressed)
//! name at the offset with compression permitted, and emits
//!
//! ```text
//! OK <formatted>
//! ERR <result-text>
//! ```
//!
//! Byte-identical output with the oracle is the parity claim.

use bind9_rs_core::error::Error;
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        if line.is_empty() {
            continue;
        }
        let (hexpart, offset) = match line.split_once(' ') {
            Some((h, o)) => (h, o.parse::<usize>().unwrap_or(0)),
            None => (line.as_str(), 0),
        };
        let wire = match decode_hex(hexpart) {
            Some(w) => w,
            None => {
                let _ = writeln!(out, "ERR bad input");
                continue;
            }
        };
        match bind9_rs_core::name::wire::from_wire(&wire, offset, true) {
            Ok(fw) => {
                let _ = writeln!(out, "OK {}", fw.name.to_text());
            }
            Err(e) => {
                let _ = writeln!(out, "ERR {}", e);
            }
        }
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[allow(dead_code)]
fn _assert_err_type(_e: &Error) {
    // The error Display strings are the court surface; the taxonomy is
    // checked by the court output comparison.
}
