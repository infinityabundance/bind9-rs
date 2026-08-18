//! `probe-message` — bind9-rs side of the `WIRE-MESSAGE-*` courts.
//! Mirrors `forensics/oracle/probes/probe_message.c`: each stdin line is a
//! wire-format DNS message in lowercase hex; the transcript is
//!
//! ```text
//! PARSE <result-text>
//! HEADER id=0x.... opcode=.. rcode=.. flags=0x.... qd=.. an=.. ns=.. ar=..
//! QUESTION <name> <class> <type>           (per question rdataset)
//! ANSWER <name> ttl=<n> <class> <type> <rdata-totext>   (per rdata)
//! AUTHORITY ...                            (same layout)
//! ADDITIONAL ...
//! OPT udpsize=<n> extrcode=<n> version=<n> do=<n> z=0x....
//!      options=<code>:<len>:<hex>[, ...]
//! TSIG <name>
//! SIG0 <name>
//! RENDER <hex>
//! REPARSE <result-text>
//! <full structure again>
//! ```
//!
//! The parse runs with `DNS_MESSAGEPARSE_BESTEFFORT`; the render path
//! mirrors the fuzz harness (renderbegin + the four rendersections +
//! renderend), and the rendered bytes are parsed again with the same flow.

use bind9_rs_core::class::Class;
use bind9_rs_core::error::Error;
use bind9_rs_core::message::{
    Message, NameRrsets, ParseStatus, SECTION_ADDITIONAL, SECTION_ANSWER, SECTION_AUTHORITY,
    SECTION_QUESTION,
};
use bind9_rs_core::name::Name;
use bind9_rs_core::rrtype::RrType;
use std::io::{BufRead, Write};

fn parse_hex(line: &str) -> Result<Vec<u8>, &'static str> {
    if line.len() % 2 != 0 {
        return Err("odd-hex-length");
    }
    let mut out = Vec::with_capacity(line.len() / 2);
    let bytes = line.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_digit(bytes[i]);
        let lo = hex_digit(bytes[i + 1]);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            return Err("non-hex");
        };
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// BIND `dns_rdatatype_totext`: mnemonic when known, else `TYPE%u`.
fn type_text(t: RrType) -> String {
    t.to_text()
}

/// BIND `dns_rdataclass_totext` (the C probe falls back to `CLASS%u`).
fn class_text(c: Class) -> String {
    c.to_text()
}

fn result_text(status: ParseStatus) -> &'static str {
    match status {
        ParseStatus::Success => "success",
        ParseStatus::Recoverable => "recoverable error occurred",
    }
}

fn error_text(e: &Error) -> String {
    e.bind_totext().to_string()
}

fn print_section(out: &mut String, sections: &[Vec<NameRrsets>; 4], section: usize, label: &str) {
    for n in &sections[section] {
        let name = n.name.to_text();
        for rr in &n.rrsets {
            if rr.question {
                out.push_str(&format!(
                    "QUESTION {name} {} {}\n",
                    class_text(rr.class),
                    type_text(rr.type_)
                ));
                continue;
            }
            for r in &rr.rdata {
                out.push_str(&format!(
                    "{label} {name} ttl={} {} {} {}\n",
                    rr.ttl,
                    class_text(rr.class),
                    type_text(rr.type_),
                    r.to_text()
                ));
            }
        }
    }
}

fn print_message(out: &mut String, m: &Message) {
    out.push_str(&format!(
        "HEADER id=0x{:04x} opcode={} rcode={} flags=0x{:04x} qd={} an={} ns={} ar={}\n",
        m.id,
        m.flags.opcode,
        m.rcode,
        m.raw_flags,
        m.counts[SECTION_QUESTION],
        m.counts[SECTION_ANSWER],
        m.counts[SECTION_AUTHORITY],
        m.counts[SECTION_ADDITIONAL]
    ));
    print_section(out, &m.sections, SECTION_QUESTION, "QUESTION");
    print_section(out, &m.sections, SECTION_ANSWER, "ANSWER");
    print_section(out, &m.sections, SECTION_AUTHORITY, "AUTHORITY");
    print_section(out, &m.sections, SECTION_ADDITIONAL, "ADDITIONAL");
    if let Some(o) = &m.opt {
        out.push_str(&format!(
            "OPT udpsize={} extrcode={} version={} do={} z=0x{:04x}",
            o.udp_payload_size(),
            o.ext_rcode(),
            o.version(),
            u8::from(o.do_flag()),
            o.z()
        ));
        let opts = o.options();
        if !opts.is_empty() {
            out.push_str(" options=");
            for (i, o) in opts.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let hex: String = o.data.iter().map(|b| format!("{b:02x}")).collect();
                out.push_str(&format!("{}:{}:{}", o.code, o.data.len(), hex));
            }
        }
        out.push('\n');
    }
    if let Some(t) = &m.tsig {
        out.push_str(&format!("TSIG {}\n", t.to_text()));
    }
    if let Some(s) = &m.sig0 {
        out.push_str(&format!("SIG0 {}\n", s.to_text()));
    }
}

fn run_case(out: &mut String, wire: &[u8]) {
    let (msg, status) = match Message::parse_besteffort(wire) {
        Ok(v) => v,
        Err(e) => {
            out.push_str(&format!("PARSE {}\n", error_text(&e)));
            return;
        }
    };
    out.push_str(&format!("PARSE {}\n", result_text(status)));
    print_message(out, &msg);

    // Render the message back to wire (dns_message_renderbegin +
    // rendersections + renderend).
    let mut render_buf = Vec::new();
    let render_result = msg.render(&mut render_buf, true);
    match render_result {
        Ok(()) => {
            let hex: String = render_buf.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!("RENDER {hex}\n"));
        }
        Err(e) => {
            out.push_str(&format!("RENDER-ERR {}\n", error_text(&e)));
        }
    }

    // Re-parse the rendered bytes.
    match Message::parse_besteffort(&render_buf) {
        Ok((msg2, status2)) => {
            out.push_str(&format!("REPARSE {}\n", result_text(status2)));
            print_message(out, &msg2);
        }
        Err(e) => {
            out.push_str(&format!("REPARSE {}\n", error_text(&e)));
        }
    }
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut transcript = String::new();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        transcript.clear();
        match parse_hex(line) {
            Ok(wire) => run_case(&mut transcript, &wire),
            Err(e) => transcript.push_str(&format!("BAD-INPUT {e}\n")),
        }
        let _ = out.write_all(transcript.as_bytes());
        let _ = out.flush();
    }
}

#[allow(dead_code)]
fn _name_doc(n: &Name) -> String {
    n.to_text()
}
