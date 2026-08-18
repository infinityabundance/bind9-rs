//! `dig` output rendering (BIND 9.20.26 `dig.c`/`dighost.c`/`masterdump.c`
//! formats, courted byte-for-byte by `CLI-DIG-OUTPUT-*`).
//!
//! Column layout (the `dns_master_style`): name → column 24, TTL → 32,
//! class → 40, type → 48, with tab-width 8 indentation exactly as
//! `masterdump.c indent()` computes it: tabs to the next tab stop, then
//! spaces; if the target column is behind the cursor, one column of space.

use bind9_rs_core::edns::{option_code, EdnsOption, Opt};
use bind9_rs_core::message::{Message, Record};
use bind9_rs_core::rcode::Rcode;
use bind9_rs_core::rrtype::RrType;
use std::io::Write;

use super::options::DigOptions;

/// Style columns (dig's default `dns_master_stylecreate(..., 24, 32, 40, 48,
/// 80, 8, ...)`).
const TTL_COLUMN: usize = 24;
const CLASS_COLUMN: usize = 32;
const TYPE_COLUMN: usize = 40;
const RDATA_COLUMN: usize = 48;
const TAB_WIDTH: usize = 8;

/// Statistics block info.
pub struct StatisticsInfo {
    pub rtt_usec: u64,
    pub server_text: String,
    pub server_arg: String,
    pub proto: &'static str,
    pub received: usize,
}

/// The cookie verification state for a received OPT (dighost.c
/// `process_cookie` → `msg->cc_ok`/`cc_bad`):
/// - `Good`: server echoed our cookie plus a valid server cookie (>= 16
///   bytes) → `; COOKIE: ... (good)`;
/// - `Echoed`: only our cookie echoed (< 16 bytes) → `; COOKIE: ...
///   (echoed)`;
/// - `Bad`: echoed but mismatched / too short → `; COOKIE: ... (bad)`;
/// - `None`: no COOKIE option in the response (no suffix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieState {
    None,
    Good,
    Echoed,
    Bad,
}

/// The indentation primitive from `masterdump.c indent()`: advance from
/// `from` to `to`, tabs first then spaces; never less than one column.
fn indent(out: &mut Vec<u8>, from: usize, to: usize) {
    let mut to = to;
    if to < from + 1 {
        to = from + 1;
    }
    let mut from = from;
    let mut ntabs = (to / TAB_WIDTH).saturating_sub(from / TAB_WIDTH);
    if ntabs > 0 {
        while ntabs > 0 {
            out.push(b'\t');
            ntabs -= 1;
        }
        // BIND updates `from` to the last tab stop only when tabs were
        // emitted; the remaining offset is spaces.
        from = (to / TAB_WIDTH) * TAB_WIDTH;
    }
    let nspaces = to - from;
    for _ in 0..nspaces {
        out.push(b' ');
    }
}

/// Render one answer-style record line with the style columns.
fn render_record_line(
    out: &mut Vec<u8>,
    name: &str,
    ttl: Option<u32>,
    class: &str,
    type_: &str,
    rdata: &str,
) {
    out.extend_from_slice(name.as_bytes());
    let mut col = name.len();
    if let Some(ttl) = ttl {
        indent(out, col, TTL_COLUMN);
        col = TTL_COLUMN;
        let t = ttl.to_string();
        out.extend_from_slice(t.as_bytes());
        col += t.len();
    }
    indent(out, col, CLASS_COLUMN);
    col = CLASS_COLUMN;
    out.extend_from_slice(class.as_bytes());
    col += class.len();
    indent(out, col, TYPE_COLUMN);
    col = TYPE_COLUMN;
    out.extend_from_slice(type_.as_bytes());
    col += type_.len();
    indent(out, col, RDATA_COLUMN);
    out.extend_from_slice(rdata.as_bytes());
    out.push(b'\n');
}

/// The IDN to-text filter (dighost.c idn_filter via
/// `dns_name_settotextfilter` when `+idnout`): response names are converted
/// to Unicode; the filter is skipped when conversion fails (name unchanged).
fn filtered_name(opts: &DigOptions, name: &bind9_rs_core::name::Name) -> String {
    if opts.idnout {
        if let Some(unicode) = crate::compat::libidn2::idn_filter(&name.to_text()) {
            return unicode;
        }
    }
    name.to_text()
}

/// Render one question line: `;name <class> <type>` with class at column 32
/// and type at column 40 (`dns_master_questiontotext`).
fn render_question_line(out: &mut Vec<u8>, name: &str, class: &str, type_: &str) {
    out.push(b';');
    out.extend_from_slice(name.as_bytes());
    let mut col = name.len();
    indent(out, col, CLASS_COLUMN);
    col = CLASS_COLUMN;
    out.extend_from_slice(class.as_bytes());
    col += class.len();
    indent(out, col, TYPE_COLUMN);
    out.extend_from_slice(type_.as_bytes());
    out.push(b'\n');
}

/// Render the full response message, exactly in dig's order (dig.c
/// `printmessage`): greeting (already printed by the caller), `;; Got
/// answer:`, header, flags, warnings, OPT pseudo-section, and the
/// question/answer/authority/additional sections.  The `;; Got answer:`
/// block, header and section-name comments are gated on `comments`; the
/// short form prints answer rdata only (dig.c `short_answer`/`say_message`).
pub fn render_message<W: Write>(
    msg: &Message,
    full_rcode: Rcode,
    opts: &DigOptions,
    cookie_state: CookieState,
    cmdline: &mut Option<String>,
    w: &mut W,
) -> std::io::Result<()> {
    let mut buf = Vec::new();

    // The greeting prints on the first printmessage call regardless of
    // +nocomments (dig.c:733-738: gated only on cmdline/printcmd/short);
    // it is cleared even when suppressed.
    if let Some(g) = cmdline.take() {
        if opts.print_cmd && !opts.short {
            buf.extend_from_slice(g.as_bytes());
        }
    }

    if opts.short {
        // dig.c short_answer: answer RDATA only, one record per line.
        for r in &msg.answer {
            if r.type_ == RrType::Opt {
                continue;
            }
            buf.extend_from_slice(r.rdata.to_text().as_bytes());
            buf.push(b'\n');
        }
        w.write_all(&buf)?;
        return Ok(());
    }

    // dig.c: `if (comments && !short_form && !dns64prefix)`.
    if opts.comments {
        buf.extend_from_slice(b";; Got answer:\n");

        // ->>HEADER<<- line.
        buf.extend_from_slice(
            format!(
                ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n",
                opcode_text(msg.flags.opcode),
                rcode_dig_text(full_rcode),
                msg.id
            )
            .as_bytes(),
        );

        // Flags line + counts (dig.c printmessage).
        render_flags_counts(&mut buf, msg);

        // Recursion requested but not available.
        if msg.flags.rd && !msg.flags.ra {
            buf.extend_from_slice(b";; WARNING: recursion requested but not available\n");
        }
        // EDNS query returned FORMERR/NOTIMP without an OPT in the response.
        // (dig.c: `edns != -1 && msg->opt == NULL && (FORMERR|NOTIMP)`).
        if opts.edns.is_some()
            && msg.opt.is_none()
            && matches!(full_rcode, Rcode::FormErr | Rcode::NotImp)
        {
            buf.extend_from_slice(
                format!(
                    "\n;; WARNING: EDNS query returned status {} - retry with '{}noedns'\n",
                    rcode_dig_text(full_rcode),
                    if opts.dnssec { "+nodnssec " } else { "" },
                )
                .as_bytes(),
            );
        }

        // Blank line separating the header block from the sections (dig.c
        // printf("\n") before dumping the rendered buffer).
        buf.push(b'\n');

        // OPT pseudo-section (dig.c: `comments && headers`).
        if let Some(opt) = &msg.opt {
            render_opt_section(&mut buf, opt, cookie_state);
        }
    }

    // Sections in dig's fixed order; the section-name comments are gated on
    // `comments` (the NOCOMMENTS totext flag).
    if opts.section_question {
        render_section(
            &mut buf,
            "QUESTION",
            &msg_question(msg),
            render_question,
            opts,
        );
    }
    if opts.section_answer {
        render_section(&mut buf, "ANSWER", &msg.answer, render_answer_record, opts);
    }
    if opts.section_authority {
        render_section(
            &mut buf,
            "AUTHORITY",
            &msg.authority,
            render_answer_record,
            opts,
        );
    }
    if opts.section_additional {
        render_section(
            &mut buf,
            "ADDITIONAL",
            &msg.additional,
            render_answer_record,
            opts,
        );
    }

    w.write_all(&buf)?;
    Ok(())
}

/// Render the statistics block (dig `received()`).
pub fn render_statistics<W: Write>(
    info: &StatisticsInfo,
    opts: &DigOptions,
    w: &mut W,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    if opts.use_usec {
        buf.extend_from_slice(format!(";; Query time: {} usec\n", info.rtt_usec).as_bytes());
    } else {
        buf.extend_from_slice(format!(";; Query time: {} msec\n", info.rtt_usec / 1000).as_bytes());
    }
    buf.extend_from_slice(
        format!(
            ";; SERVER: {}({}) ({})\n",
            info.server_text, info.server_arg, info.proto
        )
        .as_bytes(),
    );
    buf.extend_from_slice(format!(";; WHEN: {}\n", when_text()).as_bytes());
    buf.extend_from_slice(format!(";; MSG SIZE  rcvd: {}\n", info.received).as_bytes());
    buf.push(b'\n'); // BIND's received() ends the block with a blank line
    w.write_all(&buf)?;
    Ok(())
}

/// The `;; flags: ...; QUERY: ...` line (dig.c printmessage).
pub(super) fn render_flags_counts(buf: &mut Vec<u8>, msg: &Message) {
    buf.extend_from_slice(b";; flags:");
    if msg.flags.qr {
        buf.extend_from_slice(b" qr");
    }
    if msg.flags.aa {
        buf.extend_from_slice(b" aa");
    }
    if msg.flags.tc {
        buf.extend_from_slice(b" tc");
    }
    if msg.flags.rd {
        buf.extend_from_slice(b" rd");
    }
    if msg.flags.ra {
        buf.extend_from_slice(b" ra");
    }
    if msg.flags.ad {
        buf.extend_from_slice(b" ad");
    }
    if msg.flags.cd {
        buf.extend_from_slice(b" cd");
    }
    if msg.flags.z {
        buf.extend_from_slice(b"; MBZ: 0x4");
    }
    buf.extend_from_slice(
        format!(
            "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
            usize::from(msg.question.is_some()),
            msg.answer.len(),
            msg.authority.len(),
            msg.additional.len() + usize::from(msg.opt.is_some()),
        )
        .as_bytes(),
    );
}

/// Render the OPT pseudo-section (lib/dns/message.c
/// `dns_message_pseudosectiontotext`): `;; OPT PSEUDOSECTION:`, the EDNS
/// line, and one `; <NAME>: <render>` line per option.
pub(super) fn render_opt_section(buf: &mut Vec<u8>, opt: &Opt, cookie_state: CookieState) {
    buf.extend_from_slice(b";; OPT PSEUDOSECTION:\n");
    // `; EDNS: version: %u, flags:%s%s; udp: %u` — flags are " do", " co";
    // a nonzero MBZ (excluding DO|CO) prints `; MBZ: 0x%.4x, udp: `.
    let mbz = opt.z() & !(0x8000 | 0x4000);
    let mut line = format!("; EDNS: version: {}, flags:", opt.version());
    if opt.do_flag() {
        line.push_str(" do");
    }
    if opt.co_flag() {
        line.push_str(" co");
    }
    if mbz != 0 {
        line.push_str(&format!("; MBZ: 0x{mbz:04x}, udp: "));
    } else {
        line.push_str("; udp: ");
    }
    line.push_str(&opt.udp_payload_size().to_string());
    line.push('\n');
    buf.extend_from_slice(line.as_bytes());
    for o in opt.options() {
        buf.extend_from_slice(b"; ");
        buf.extend_from_slice(option_text(o.code).as_bytes());
        buf.push(b':');
        render_option_value(buf, o, cookie_state);
        buf.push(b'\n');
    }
}

/// Render one OPT option's value (message.c `pseudosectiontotext` switch):
/// COOKIE gets lowercase hex without separators plus the (good|echoed|bad)
/// suffix; PADDING prints ` (N bytes)`; ECS renders the prefix; the
/// generic form is hex-with-spaces plus `("printable")`.
fn render_option_value(buf: &mut Vec<u8>, o: &EdnsOption, cookie_state: CookieState) {
    match o.code {
        option_code::COOKIE => {
            // message.c: `ADD_STRING(target, " ")` before the hex bytes.
            buf.push(b' ');
            for b in &o.data {
                buf.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            match cookie_state {
                CookieState::Good => buf.extend_from_slice(b" (good)"),
                CookieState::Echoed => buf.extend_from_slice(b" (echoed)"),
                CookieState::Bad => buf.extend_from_slice(b" (bad)"),
                CookieState::None => {}
            }
        }
        option_code::PADDING => {
            if !o.data.is_empty() {
                buf.extend_from_slice(format!(" ({} bytes)", o.data.len()).as_bytes());
            }
        }
        option_code::ECS => {
            // message.c render_ecs: family/addrlen/scopelen/addr, e.g.
            // ` 192.0.2.0/24/0` (malformed → generic hex fallback).
            if o.data.len() >= 4 {
                let family = u16::from_be_bytes([o.data[0], o.data[1]]);
                let addrlen = o.data[2];
                let scopelen = o.data[3];
                let addrbytes = (usize::from(addrlen) + 7) / 8;
                let valid = match family {
                    0 => addrlen == 0 && scopelen == 0,
                    1 => addrlen <= 32 && scopelen <= 32,
                    2 => addrlen <= 128 && scopelen <= 128,
                    _ => false,
                };
                if valid && o.data.len() >= 4 + addrbytes {
                    let addr = &o.data[4..4 + addrbytes];
                    let text = match family {
                        1 => {
                            let mut o4 = [0u8; 4];
                            o4[..addrbytes.min(4)].copy_from_slice(&addr[..addrbytes.min(4)]);
                            std::net::Ipv4Addr::from(o4).to_string()
                        }
                        2 => {
                            let mut o6 = [0u8; 16];
                            o6[..addrbytes.min(16)].copy_from_slice(&addr[..addrbytes.min(16)]);
                            std::net::Ipv6Addr::from(o6).to_string()
                        }
                        _ => "0".to_string(),
                    };
                    buf.extend_from_slice(format!(" {text}/{addrlen}/{scopelen}").as_bytes());
                    return;
                }
            }
            render_option_hex(buf, o);
        }
        _ => render_option_hex(buf, o),
    }
}

/// The generic option fallback (message.c): hex bytes separated by spaces,
/// then `("printable")`.
fn render_option_hex(buf: &mut Vec<u8>, o: &EdnsOption) {
    if o.data.is_empty() {
        return;
    }
    buf.push(b' ');
    let mut printable = String::with_capacity(o.data.len());
    for (i, b) in o.data.iter().enumerate() {
        if i > 0 {
            buf.push(b' ');
        }
        buf.extend_from_slice(format!("{b:02x}").as_bytes());
        printable.push(if b.is_ascii_graphic() {
            *b as char
        } else {
            '.'
        });
    }
    buf.extend_from_slice(b"(\"");
    buf.extend_from_slice(printable.as_bytes());
    buf.push(b'"');
    buf.push(b')');
}

/// Render the query (send) message for the `+qr` path (dig.c printmessage
/// with `msg == lookup->sendmsg`): the greeting (deferred cmdline), `;;
/// Sending:`, header block, OPT pseudo-section, question section, and the
/// trailing blank line.  The `;; QUERY SIZE: N` line is printed by the
/// caller (gated on `stats`).
pub fn render_send_message<W: Write>(
    msg: &Message,
    opts: &DigOptions,
    cmdline: &mut Option<String>,
    w: &mut W,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    // The greeting prints on the first printmessage call regardless of
    // +nocomments (dig.c:733-738).
    if let Some(g) = cmdline.take() {
        if opts.print_cmd && !opts.short {
            buf.extend_from_slice(g.as_bytes());
        }
    }
    if opts.comments && !opts.short {
        buf.extend_from_slice(b";; Sending:\n");
        buf.extend_from_slice(
            format!(
                ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n",
                opcode_text(msg.flags.opcode),
                "NOERROR",
                msg.id
            )
            .as_bytes(),
        );
        render_flags_counts(&mut buf, msg);
        // Blank line separating the header block from the sections.
        buf.push(b'\n');
        if let Some(opt) = &msg.opt {
            render_opt_section(&mut buf, opt, CookieState::None);
        }
    }
    if opts.section_question && msg.question.is_some() {
        render_section(
            &mut buf,
            "QUESTION",
            &msg_question(msg),
            render_question,
            opts,
        );
    }
    w.write_all(&buf)?;
    Ok(())
}

/// BIND's `%a %b %d %H:%M:%S %Z %Y` localtime format.
fn when_text() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Local time with %Z — approximate with UTC offset 0 when TZ is unset.
    let tz_offset = tz_offset_secs();
    let local = now + tz_offset;
    civil(&local)
}

/// Parse TZ (POSIX form) for the local offset; defaults to 0.
fn tz_offset_secs() -> i64 {
    if let Ok(tz) = std::env::var("TZ") {
        if tz.is_empty() || tz == "UTC" || tz == "GMT" || tz == "Etc/UTC" {
            return 0;
        }
        // POSIX TZ like "EST5EDT" or "UTC0"; handle plain +/-HH:MM.
        if let Some(rest) = tz.strip_prefix("UTC") {
            if let Some(v) = parse_offset(rest) {
                return v;
            }
        }
        // Try the trailing numeric part of a POSIX spec (e.g. EST5 → +5h).
        let bytes = tz.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'+'
                || b == b'-'
                || (b.is_ascii_digit() && i > 0 && bytes[i - 1].is_ascii_alphabetic())
            {
                let start = if b == b'+' || b == b'-' { i } else { i };
                let num: String = bytes[start..]
                    .iter()
                    .take_while(|c| c.is_ascii_digit() || **c == b':' || **c == b'+' || **c == b'-')
                    .map(|&c| c as char)
                    .collect();
                if let Some(v) = parse_offset(&num) {
                    return v;
                }
                break;
            }
        }
    }
    0
}

fn parse_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let sign = if s.starts_with('-') { -1 } else { 1 };
    let s = s.trim_start_matches(['+', '-']);
    let (h, m) = match s.split_once(':') {
        Some((h, m)) => (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?),
        None => (s.parse::<i64>().ok()?, 0),
    };
    Some(sign * (h * 3600 + m * 60))
}

/// Convert epoch seconds (already local) to `%a %b %d %H:%M:%S %Z %Y`.
fn civil(secs: &i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let yy = if mth <= 2 { y + 1 } else { y };
    let weekday = ((days + 4).rem_euclid(7)) as usize;
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {} {}",
        WD[weekday],
        MO[(mth - 1) as usize],
        d,
        h,
        m,
        s,
        tz_abbrev(),
        yy
    )
}

fn tz_abbrev() -> String {
    std::env::var("TZ")
        .ok()
        .and_then(|t| {
            if t.is_empty() || t == "UTC" || t == "GMT" {
                Some(t)
            } else {
                None
            }
        })
        .unwrap_or_else(|| "UTC".to_string())
}

/// dig's opcode text table.
fn opcode_text(opcode: u8) -> &'static str {
    match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        3 => "RESERVED3",
        4 => "NOTIFY",
        5 => "UPDATE",
        6 => "RESERVED6",
        7 => "RESERVED7",
        8 => "RESERVED8",
        9 => "RESERVED9",
        10 => "RESERVED10",
        11 => "RESERVED11",
        12 => "RESERVED12",
        13 => "RESERVED13",
        14 => "RESERVED14",
        15 => "RESERVED15",
        _ => "RESERVED?",
    }
}

/// dig's `rcode_totext`: dns_rcode_totext, with a `?` prefix for the
/// numeric-only (unknown) case.
fn rcode_dig_text(rcode: Rcode) -> String {
    let t = rcode.to_text();
    if t.bytes().all(|b| b.is_ascii_digit()) {
        format!("?{t}")
    } else {
        t
    }
}

/// EDNS option name from BIND's `option_names` table (subset; unknown →
/// `OPT=<code>`).
fn option_text(code: u16) -> String {
    match code {
        1 => "LLQ".to_string(),
        2 => "UL".to_string(),
        3 => "NSID".to_string(),
        4 => "reserved".to_string(),
        5 => "DAU".to_string(),
        6 => "DHU".to_string(),
        7 => "N3U".to_string(),
        8 => "CLIENT-SUBNET".to_string(),
        9 => "EXPIRE".to_string(),
        10 => "COOKIE".to_string(),
        11 => "TCP-KEEPALIVE".to_string(),
        12 => "PADDING".to_string(),
        13 => "CHAIN".to_string(),
        14 => "KEY-TAG".to_string(),
        15 => "EDE".to_string(),
        _ => format!("OPT={code}"),
    }
}

/// The question section rendered as a slice of line-strings.
fn msg_question(msg: &Message) -> Vec<Record> {
    // The question is not a Record list; represent it as a pseudo-record
    // carrying the question's fields for uniform rendering.
    let mut v = Vec::new();
    if let Some(q) = &msg.question {
        v.push(Record {
            name: q.qname.clone(),
            type_: q.qtype,
            class: q.qclass,
            ttl: bind9_rs_core::ttl::Ttl::ZERO,
            rdata: bind9_rs_core::rdata::Rdata::A("0.0.0.0".parse().unwrap()),
        });
    }
    v
}

type RecordRenderer = fn(&mut Vec<u8>, &Record, &DigOptions);

fn render_section(
    buf: &mut Vec<u8>,
    name: &str,
    records: &[Record],
    renderer: RecordRenderer,
    opts: &DigOptions,
) {
    if records.is_empty() {
        return;
    }
    let mut section = Vec::new();
    if opts.comments {
        section.extend_from_slice(format!(";; {name} SECTION:\n").as_bytes());
    }
    for r in records {
        renderer(&mut section, r, opts);
    }
    // The blank line separating sections is part of the comments rendering
    // (BIND: +noall +answer emits the record without a trailing blank).
    if opts.comments {
        section.push(b'\n');
    }
    buf.extend_from_slice(&section);
}

fn render_question(buf: &mut Vec<u8>, r: &Record, opts: &DigOptions) {
    render_question_line(
        buf,
        &filtered_name(opts, &r.name),
        &r.class.to_text(),
        &r.type_.to_text(),
    );
}

fn render_answer_record(buf: &mut Vec<u8>, r: &Record, opts: &DigOptions) {
    let ttl = if r.type_ == RrType::Opt {
        None
    } else {
        Some(r.ttl.as_u32())
    };
    render_record_line(
        buf,
        &filtered_name(opts, &r.name),
        ttl,
        &r.class.to_text(),
        &r.type_.to_text(),
        &rdata_text(opts, r),
    );
}

/// The RDATA text with dig's totext filter applied (dig.c printmessage sets
/// the idn_filter via `dig_idnsetup(query->lookup, true)`; the filter covers
/// every name in the message, including names inside RDATA).
fn rdata_text(opts: &DigOptions, r: &Record) -> String {
    if opts.idnout {
        r.rdata.to_text_filtered(&mut |s| {
            crate::compat::libidn2::idn_filter(s).unwrap_or_else(|| s.to_string())
        })
    } else {
        r.rdata.to_text()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indent_math() {
        // From masterdump.c semantics: name "example.com." (12) to 24:
        // ntabs = 24/8 - 12/8 = 3-1 = 2 tabs.
        let mut out = Vec::new();
        indent(&mut out, 12, 24);
        assert_eq!(out, b"\t\t");
        // From 27 to 32: 32/8 - 27/8 = 4-3 = 1 tab.
        let mut out = Vec::new();
        indent(&mut out, 27, 32);
        assert_eq!(out, b"\t");
        // From 5 to 7: no tab stops crossed, 2 spaces.
        let mut out = Vec::new();
        indent(&mut out, 5, 7);
        assert_eq!(out, b"  ");
        // Target behind cursor: one column of space.
        let mut out = Vec::new();
        indent(&mut out, 40, 30);
        assert_eq!(out, b" ");
    }

    #[test]
    fn rcode_text_with_question_prefix() {
        assert_eq!(rcode_dig_text(Rcode::NoError), "NOERROR");
        assert_eq!(rcode_dig_text(Rcode::BadCookie), "BADCOOKIE");
        // RESERVED11..15 are real table entries (TOTEXTONLY), so dig prints
        // them without the numeric-rcode '?' prefix.
        assert_eq!(rcode_dig_text(Rcode::Unknown(12)), "RESERVED12");
        // Only genuinely numeric rcodes get the prefix.
        assert_eq!(rcode_dig_text(Rcode::Unknown(24)), "?24");
    }
}
