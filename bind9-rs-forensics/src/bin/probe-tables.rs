//! `probe-tables` — bind9-rs side of the `TABLES-0001` court.
//! Mirrors `forensics/oracle/probes/probe_tables.c`: each stdin line is
//! `<cmd> <arg>`; one result line per command:
//!
//! ```text
//! OK <value>
//! ERR <result-text>
//! ```
//!
//! The commands cover `dns_rcode_totext/fromtext`,
//! `dns_tsigrcode_totext/fromtext`, `dns_rdatatype_totext/fromtext` and the
//! ismeta/issingleton/isknown predicates, and
//! `dns_rdataclass_totext/fromtext` — the RCODE/class/type tables.

use bind9_rs_core::class::Class;
use bind9_rs_core::error::Error;
use bind9_rs_core::rcode::{tsigrcode_from_text, tsigrcode_to_text, Rcode};
use bind9_rs_core::rrtype::RrType;
use std::io::{BufRead, Write};

fn err_text(e: &Error) -> String {
    e.bind_totext().to_string()
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let Some(cmd) = parts.next() else { continue };
        // The C probe reads the argument with %s, so only the first
        // whitespace-delimited word is the token.
        let arg = parts
            .next()
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("");
        let res = match cmd {
            "rcode-totext" => Ok(Rcode::from_u16(parse_n(arg)).to_text()),
            "tsigrcode-totext" => Ok(tsigrcode_to_text(parse_n(arg))),
            "type-totext" => Ok(RrType::from_u16(parse_n(arg)).to_text()),
            "class-totext" => Ok(Class::from_u16(parse_n(arg)).to_text()),
            "type-ismeta" => Ok(if RrType::from_u16(parse_n(arg)).is_meta() {
                "1".to_string()
            } else {
                "0".to_string()
            }),
            "type-issingleton" => Ok(if RrType::from_u16(parse_n(arg)).is_singleton() {
                "1".to_string()
            } else {
                "0".to_string()
            }),
            "type-isknown" => Ok(if RrType::from_u16(parse_n(arg)).is_known() {
                "1".to_string()
            } else {
                "0".to_string()
            }),
            "rcode-fromtext" => Rcode::from_text(arg).map(|r| r.to_u16().to_string()),
            "tsigrcode-fromtext" => tsigrcode_from_text(arg).map(|n| n.to_string()),
            "type-fromtext" => RrType::from_text(arg).map(|t| t.to_u16().to_string()),
            "class-fromtext" => Class::from_text(arg).map(|c| c.to_u16().to_string()),
            _ => Err(Error::Other("unknown-command".to_string())),
        };
        match res {
            Ok(v) => {
                let _ = writeln!(out, "OK {v}");
            }
            Err(e) => {
                let _ = writeln!(out, "ERR {}", err_text(&e));
            }
        }
    }
}

fn parse_n(s: &str) -> u16 {
    s.parse().unwrap_or(0)
}
