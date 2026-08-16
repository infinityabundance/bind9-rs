//! `probe-rdata` — bind9-rs side of the `WIRE-RDATA-*` courts.
//! Mirrors `forensics/oracle/probes/probe_rdata.c`: each stdin line is
//! `<type-mnemonic> <rdata text>`; one result line per case:
//!
//! ```text
//! OK <totext>|<wire-hex>|<canonical-hex>|<fromwire-totext>
//! ERR <error>
//! ```
//!
//! The type mnemonic is resolved with `RrType::from_text`; rdata text is
//! parsed against the root origin; the wire form is rendered with no
//! compressor (uncompressed names), the canonical form via
//! `Rdata::canonical_wire`, and the wire→text round-trip via
//! `Rdata::from_wire`.

use bind9_rs_core::message::compression::Compressor;
use bind9_rs_core::name::Name;
use bind9_rs_core::presentation::lexer::Lexer;
use bind9_rs_core::rdata::Rdata;
use bind9_rs_core::rrtype::RrType;
use std::io::{BufRead, Write};

fn main() {
    let root = Name::root();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.splitn(2, ' ');
        let Some(mtype) = fields.next() else { continue };
        let Some(rest) = fields.next() else {
            let _ = writeln!(out, "ERR missing-rdata-text");
            continue;
        };
        let Ok(type_) = RrType::from_text(mtype) else {
            let _ = writeln!(out, "TYPE-ERR unknown-type");
            continue;
        };
        let mut lex = Lexer::new(rest.as_bytes());
        let r = match Rdata::from_text(type_, &mut lex, Some(&root)) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(out, "ERR {e}");
                continue;
            }
        };
        // totext
        let text = r.to_text();
        // towire (no compressor: names uncompressed, order-independent)
        let mut wire = Vec::new();
        let mut comp = Compressor::with_flags(true, false, false); // DISABLED
        if let Err(e) = r.to_wire(&mut wire, Some(&mut comp)) {
            let _ = writeln!(out, "WIRE-ERR {e}");
            continue;
        }
        let wire_hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        // canonical (DNSSEC) form
        let mut canon = Vec::new();
        if let Err(e) = r.canonical_wire(&mut canon) {
            let _ = writeln!(out, "CANON-ERR {e}");
            continue;
        }
        let canon_hex: String = canon.iter().map(|b| format!("{b:02x}")).collect();
        // independent wire->text round-trip
        let mut pos = 0;
        let rt = match Rdata::from_wire(type_, &wire, &mut pos, wire.len()) {
            Ok(r2) => r2.to_text(),
            Err(e) => {
                let _ = writeln!(out, "FROMWIRE-ERR {e}");
                continue;
            }
        };
        let _ = writeln!(out, "OK {text}|{wire_hex}|{canon_hex}|{rt}");
    }
}
