//! libidn2-lz-probe — Rust mirror of `forensics/oracle/probes/
//! probe-libidn2-lz.c` for the LZ-0001 court (§28, §37).  Runs in the same
//! oracle-libidn2-2.3.8 container; stdout must be byte-identical.
//!
//! The harness runs the probe once per locale (LANG set per run) plus the
//! algorithm section; the locale codeset is resolved from the environment
//! exactly like the C's `nl_langinfo(CODESET)` for the pinned locales.
//!
//! Usage: libidn2-lz-probe locale | libidn2-lz-probe algo

use bind9_rs_tools::compat::libidn2::*;

fn print_string(data: &[u8]) {
    print!("\"");
    for &c in data {
        if (0x20..=0x7e).contains(&c) {
            if c == b'"' {
                print!("\\\"");
            } else {
                print!("{}", c as char);
            }
        } else {
            print!("\\x{c:02x}");
        }
    }
    print!("\"");
}

fn rcname(e: Error) -> &'static str {
    e.name().trim_start_matches("IDN2_")
}

/// Mirror of the C probe's `printf("  %-26s ", label)`: `%-26s` pads the
/// label to 26 *bytes* (multibyte UTF-8 labels are not aligned by char
/// count).
fn pad(label: &str) -> String {
    if label.len() >= 26 {
        label.to_string()
    } else {
        format!("{label}{}", " ".repeat(26 - label.len()))
    }
}

fn probe_lz(label: &str, s: &[u8], flags: i32) {
    match to_ascii_lz_u8(s, flags) {
        Ok(out) => {
            print!("  {} ", pad(label));
            print_string(s);
            print!(" -> ");
            print_string(&out);
            println!();
        }
        Err(e) => {
            print!("  {} ", pad(label));
            print_string(s);
            println!(" -> rc={} ({})", e.code(), rcname(e));
        }
    }
}

fn probe_8zlz(label: &str, s: &str, flags: i32) {
    match to_unicode_8zlz_u8(s, flags) {
        Ok(out) => {
            print!("  {} ", pad(label));
            print_string(s.as_bytes());
            print!(" -> ");
            print_string(&out);
            println!();
        }
        Err(e) => {
            print!("  {} ", pad(label));
            print_string(s.as_bytes());
            println!(" -> rc={} ({})", e.code(), rcname(e));
        }
    }
}

fn probe_8z(label: &str, s: &str, flags: i32) {
    probe_lz(label, s.as_bytes(), flags)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("locale") => {
            println!("== locale {} ==", locale_codeset());

            let mue_utf8: &[u8] = &[
                b'm', 0xc3, 0xbc, b'n', b'c', b'h', b'e', b'n', b'.', b'd', b'e',
            ];
            let mue_l1: &[u8] = &[b'm', 0xfc, b'n', b'c', b'h', b'e', b'n', b'.', b'd', b'e'];
            let fass_utf8: &[u8] = &[b'f', b'a', 0xc3, 0x9f, b'.', b'd', b'e'];
            let fass_l1: &[u8] = &[b'f', b'a', 0xdf, b'.', b'd', b'e'];
            let sigma_utf8: &[u8] = &[0xcf, 0x82, b'.', b'g', b'r'];
            let emoji: &[u8] = b"\xf0\x9f\x98\x80.com";

            probe_lz("lz münchen.de", mue_utf8, flags::NONTRANSITIONAL);
            probe_lz("lz faß.de", fass_utf8, flags::NONTRANSITIONAL);
            probe_lz("lz ς.gr", sigma_utf8, flags::NONTRANSITIONAL);
            probe_lz("lz example.com", b"example.com", flags::NONTRANSITIONAL);
            probe_lz(
                "lz _tcp.example.com",
                b"_tcp.example.com",
                flags::NONTRANSITIONAL,
            );
            probe_lz(
                "lz XN--MNCHEN-3YA.DE",
                b"XN--MNCHEN-3YA.DE",
                flags::NONTRANSITIONAL,
            );
            probe_lz("lz emoji.com", emoji, flags::NONTRANSITIONAL);
            probe_lz("lz münchen.de latin1", mue_l1, flags::NONTRANSITIONAL);
            probe_lz("lz faß.de latin1", fass_l1, flags::NONTRANSITIONAL);

            probe_8zlz(
                "8zlz xn--mnchen-3ya.de",
                "xn--mnchen-3ya.de",
                flags::NONTRANSITIONAL,
            );
            probe_8zlz(
                "8zlz XN--MNCHEN-3YA.DE",
                "XN--MNCHEN-3YA.DE",
                flags::NONTRANSITIONAL,
            );
            probe_8zlz("8zlz xn--e28h.com", "xn--e28h.com", flags::NONTRANSITIONAL);
            probe_8zlz("8zlz example.com", "example.com", flags::NONTRANSITIONAL);
            probe_8zlz("8zlz a..b", "a..b", flags::NONTRANSITIONAL);
        }
        Some("algo") => {
            println!("== NO_TR46 (pure IDNA2008) ==");
            probe_8z("no46 münchen.de", "münchen.de", flags::NO_TR46);
            probe_8z("no46 MÜNCHEN.de", "MÜNCHEN.de", flags::NO_TR46);
            probe_8z("no46 EXAMPLE.COM", "EXAMPLE.COM", flags::NO_TR46);
            probe_8z("no46 faß.de", "faß.de", flags::NO_TR46);
            probe_8z("no46 ς.gr", "ς.gr", flags::NO_TR46);
            probe_8z("no46 βόλος.gr", "βόλος.gr", flags::NO_TR46);
            probe_8z(
                "no46 xn--mnchen-3ya.de",
                "xn--mnchen-3ya.de",
                flags::NO_TR46,
            );
            probe_8z(
                "no46 XN--MNCHEN-3YA.DE",
                "XN--MNCHEN-3YA.DE",
                flags::NO_TR46,
            );
            probe_8z(
                "no46 xn--0zwm56d.example",
                "xn--0zwm56d.example",
                flags::NO_TR46,
            );
            probe_8z("no46 a\\u00ADb.com", "a\u{00AD}b.com", flags::NO_TR46);
            probe_8z("no46 a\\u200Cb.com", "a\u{200C}b.com", flags::NO_TR46);
            probe_8z("no46 a\\u200Db.com", "a\u{200D}b.com", flags::NO_TR46);
            probe_8z("no46 emoji.com", "😀.com", flags::NO_TR46);
            probe_8z("no46 ßß.com", "ßß.com", flags::NO_TR46);
            probe_8z("no46 _tcp.example.com", "_tcp.example.com", flags::NO_TR46);
            probe_8z("no46 1.2.3.4", "1.2.3.4", flags::NO_TR46);
            probe_8z("no46 a..b", "a..b", flags::NO_TR46);
            probe_8z("no46 .leading-dot", ".leading-dot", flags::NO_TR46);
            probe_8z("no46 trailing-dot.", "trailing-dot.", flags::NO_TR46);
            probe_8z("no46 www.xn--0.0.com", "www.xn--0.0.com", flags::NO_TR46);

            println!("== flag taxonomy ==");
            probe_8z(
                "TR|NT",
                "example.com",
                flags::TRANSITIONAL | flags::NONTRANSITIONAL,
            );
            probe_8z(
                "NT|NO_TR46",
                "example.com",
                flags::NONTRANSITIONAL | flags::NO_TR46,
            );
            probe_8z(
                "TR|NO_TR46",
                "example.com",
                flags::TRANSITIONAL | flags::NO_TR46,
            );
            probe_8z(
                "ALABEL|NO_ALABEL",
                "example.com",
                flags::ALABEL_ROUNDTRIP | flags::NO_ALABEL_ROUNDTRIP,
            );
            probe_8z("0 flags", "faß.de", 0);
            probe_8z(
                "NO_ALABEL_ROUNDTRIP",
                "xn--mnchen-3ya.de",
                flags::NO_ALABEL_ROUNDTRIP | flags::NONTRANSITIONAL,
            );

            println!("== label tests ==");
            probe_8z("nt leading mark", "\u{0301}a.com", flags::NONTRANSITIONAL);
            probe_8z("no46 leading mark", "\u{0301}a.com", flags::NO_TR46);
            probe_8z("nt 2hyphen", "aß--b.com", flags::NONTRANSITIONAL);
            probe_8z("no46 2hyphen", "aß--b.com", flags::NO_TR46);
            probe_8z("nt hyphen-start", "-aä.com", flags::NONTRANSITIONAL);
            probe_8z("no46 hyphen-start", "-aä.com", flags::NO_TR46);
            probe_8z("nt hyphen-end", "aä-.com", flags::NONTRANSITIONAL);
            probe_8z("no46 hyphen-end", "aä-.com", flags::NO_TR46);
            probe_8z("nt unassigned", "\u{0378}.com", flags::NONTRANSITIONAL);
            probe_8z("no46 unassigned", "\u{0378}.com", flags::NO_TR46);
            probe_8z("nt bidi ok", "אב.com", flags::NONTRANSITIONAL);
            probe_8z("nt bidi bad", "aאb.com", flags::NONTRANSITIONAL);
            probe_8z("no46 bidi bad", "aאb.com", flags::NO_TR46);
            probe_8z("nt zwnj valid", "ب\u{200C}ب.com", flags::NONTRANSITIONAL);
            probe_8z("nt zwj invalid", "ب\u{200D}ب.com", flags::NONTRANSITIONAL);
            probe_8z("nt zwnj a-b", "a\u{200C}b.com", flags::NONTRANSITIONAL);
            probe_8z("nt middot l·l", "l\u{00B7}l.com", flags::NONTRANSITIONAL);
            probe_8z("nt middot a·b", "a\u{00B7}b.com", flags::NONTRANSITIONAL);
            probe_8z("nt keraia greek", "α\u{0375}a.com", flags::NONTRANSITIONAL);
            probe_8z("nt keraia not", "a\u{0375}b.com", flags::NONTRANSITIONAL);
            probe_8z("nt katakana dot", "\u{30FB}a.com", flags::NONTRANSITIONAL);
            probe_8z(
                "nt katakana dot kata",
                "ア\u{30FB}a.com",
                flags::NONTRANSITIONAL,
            );
            probe_8z(
                "nt std3 _ä",
                "_aä.com",
                flags::NONTRANSITIONAL | flags::USE_STD3_ASCII_RULES,
            );
            probe_8z(
                "no46 std3 _ä",
                "_aä.com",
                flags::NO_TR46 | flags::USE_STD3_ASCII_RULES,
            );
            probe_8z(
                "nt _tcp +std3",
                "_tcp.example.com",
                flags::NONTRANSITIONAL | flags::USE_STD3_ASCII_RULES,
            );
            probe_8z(
                "nt longascii",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
                flags::NONTRANSITIONAL,
            );
            probe_8z(
                "nt longlabel",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaä.com",
                flags::NONTRANSITIONAL,
            );
            probe_8z(
                "no46 longlabel",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaä.com",
                flags::NO_TR46,
            );
        }
        _ => std::process::exit(1),
    }
}
