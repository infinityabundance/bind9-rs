//! `probe-lex` — bind9-rs side of the `ISC-LEX-0001` court.
//! Mirrors `forensics/oracle/probes/probe_lex.c`: each stdin line is
//! `<cmd> <base64>`, where `cmd` is `lex` (`isc_lex_gettoken` with
//! EOL|EOF|DNSMULTILINE|ESCAPE|QSTRING|NUMBER) or `master`
//! (`isc_lex_getmastertoken(STRING, eol=true)`).
//!
//! Lines without a whitespace-separated second field are skipped, matching
//! the oracle's `sscanf("%s %s")` (a `master ` line with an empty payload is
//! silently dropped there).
//!
//! One result line per token:
//!
//! ```text
//! STRING <raw> / QSTRING <raw> / NUMBER <n> / SPECIAL <c> /
//! EOL / EOF / MASTER <token> / ERR <result-text>
//! ```
//!
//! Token bytes are written verbatim (the oracle uses `printf("%.*s")`), so
//! the capture comparison is byte-exact.

use bind9_rs_core::presentation::lexer::{LexOptions, LexToken, Lexer};
use std::io::{BufRead, Write};

/// The oracle's `b64decode` — the base64 alphabet plus silent skipping of
/// anything else (padding `=`, whitespace, junk).
fn b64_decode(s: &str, out: &mut Vec<u8>) {
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
}

/// The oracle prints tokens with `printf("%.*s")`, which stops at the
/// first NUL byte; quoted strings can legally contain NULs (the specials
/// table only applies outside quoted strings), so mirror the truncation.
fn c_printf_bytes(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(n) => &b[..n],
        None => b,
    }
}

/// One `run_lex` session: token loop with `isc_lex_gettoken` /
/// `isc_lex_getmastertoken` semantics, byte-identical output to the C probe.
fn run(data: &[u8], master: bool) -> Vec<u8> {
    let mut lx = Lexer::new(data);
    let options = if master {
        LexOptions::master()
    } else {
        LexOptions::all()
    };
    let mut out = Vec::new();
    let mut count = 0u32;
    loop {
        match lx.next_token(options) {
            Ok(LexToken::Eof) => {
                out.extend_from_slice(b"EOF\n");
                break;
            }
            // `isc_lex_getmastertoken(STRING)`: any non-string token is
            // ungot and reported as UNEXPECTEDTOKEN.
            Ok(LexToken::String(b)) if !master => {
                let b = c_printf_bytes(&b);
                out.extend_from_slice(b"STRING ");
                out.extend_from_slice(b);
                out.push(b'\n');
            }
            Ok(LexToken::Quoted(b)) if !master => {
                let b = c_printf_bytes(&b);
                out.extend_from_slice(b"QSTRING ");
                out.extend_from_slice(b);
                out.push(b'\n');
            }
            Ok(LexToken::Number(n)) if !master => {
                out.extend_from_slice(format!("NUMBER {n}\n").as_bytes());
            }
            Ok(LexToken::Special(c)) if !master => {
                out.extend_from_slice(b"SPECIAL ");
                out.push(c);
                out.push(b'\n');
            }
            Ok(LexToken::Eol) if !master => {
                out.extend_from_slice(b"EOL\n");
            }
            Ok(LexToken::String(b)) => {
                let b = c_printf_bytes(&b);
                out.extend_from_slice(b"MASTER STRING ");
                out.extend_from_slice(b);
                out.push(b'\n');
            }
            Ok(LexToken::Eol) => {
                out.extend_from_slice(b"MASTER EOL\n");
            }
            Ok(_) => {
                out.extend_from_slice(b"ERR unexpected token\n");
                break;
            }
            Err(e) => {
                // The C probe breaks the session on the first error.
                out.extend_from_slice(format!("ERR {}\n", e.bind_totext()).as_bytes());
                break;
            }
        }
        count += 1;
        if count > 10_000 {
            out.extend_from_slice(b"ERR too-many-tokens\n");
            break;
        }
    }
    out
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        let mut words = line.split_whitespace();
        let (Some(cmd), Some(b64)) = (words.next(), words.next()) else {
            continue;
        };
        let mut data = Vec::new();
        b64_decode(b64, &mut data);
        let res = match cmd {
            "lex" => run(&data, false),
            "master" => run(&data, true),
            _ => b"ERR unknown-command\n".to_vec(),
        };
        let _ = out.write_all(&res);
    }
}
