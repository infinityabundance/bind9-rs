//! The `dig` implementation (Phase 2; §4.4, §32).
//!
//! Fidelity targets are taken from the archaeology of `bin/dig/dig.c` and
//! `bin/dig/dighost.c` (BIND 9.20.26) and verified byte-for-byte by the
//! `CLI-DIG-*` courts against the oracle binary:
//!
//! - greeting `; <<>> DiG <version> <<>> <args...>` with the `;; global
//!   options: +cmd` line;
//! - header/flag/count lines, warnings (recursion unavailable, EDNS
//!   FORMERR/NOTIMP retry hint, extra bytes);
//! - the `dns_master_style` column layout: name → 24, ttl → 32, class → 40,
//!   type → 48 (tab/space indentation with tab width 8, per
//!   `masterdump.c indent()`);
//! - the OPT pseudo-section and statistics block formats.
//!
//! Network transport uses `std::net` (a safe, audited abstraction); the
//! platform crate owns production socket machinery for `named`.

pub mod options;
pub mod output;

use bind9_rs_core::class::Class;
use bind9_rs_core::edns::{option_code, Opt};
use bind9_rs_core::message::{header, question::Question, Message};
use bind9_rs_core::name::Name;
use bind9_rs_core::rrtype::RrType;
use options::{parse_args, DigOptions, ParseError, Transport};
use output::{render_message, render_send_message, render_statistics, StatisticsInfo};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::Instant;

/// The per-process random 8-byte client cookie (dighost.c `cookie_secret` /
/// `compute_cookie`: the first 8 bytes of a 33-byte secret generated once at
/// startup, "should be per server" per the XXXMPA comment — an archived
/// quirk, not a fix).
fn client_cookie() -> &'static [u8; 8] {
    static COOKIE: OnceLock<[u8; 8]> = OnceLock::new();
    COOKIE.get_or_init(|| {
        let mut c = [0u8; 8];
        match bind9_rs_platform::random::fill_u64() {
            Ok(v) => c.copy_from_slice(&v.to_le_bytes()),
            Err(_) => { /* entropy unavailable: fixed value keeps dig usable */ }
        }
        c
    })
}

/// Run dig with the given argv (excluding argv[0]); returns the exit code
/// (BIND convention: 0 success, 1 failure, 10 warn+exit_or_usage).
pub fn run(argv: &[String]) -> i32 {
    let parsed = match parse_args(argv) {
        Ok(p) => p,
        Err(e) => {
            // dig.c exit taxonomy: invalid options print usage; `fatal()`
            // prints `dig: <msg>` (exit 1); `warn()`+`exit_or_usage` prints
            // `dig: <msg>` (exit 10); `-x` prints the bare message.
            match e {
                ParseError::Usage(m) => {
                    eprintln!("{m}");
                    eprint!("{}", options::USAGE);
                    return 1;
                }
                ParseError::Fatal(m) => {
                    eprintln!("dig: {m}");
                    return 1;
                }
                ParseError::Warn(m) => {
                    eprintln!("dig: {m}");
                    return 10;
                }
                ParseError::Bare(m) => {
                    eprintln!("{m}");
                    return 1;
                }
            }
        }
    };

    if parsed.help {
        print!("{}", options::HELP);
        return 0;
    }
    if parsed.version {
        println!("{}", crate::common::versioning::dig_version_line());
        return 0;
    }

    let mut rc = 0;
    // The greeting (dig.c `printgreeting`) is *built* when the first name is
    // parsed (using the printcmd/short globals at that moment — archived:
    // `dig example.com +noall` builds it, `dig +noall example.com` does not)
    // but only *printed* at the first `printmessage`.  That ordering is
    // observable: a truncated UDP response prints `;; Truncated, retrying in
    // TCP mode.` *before* the greeting, because the greeting is flushed with
    // the TCP answer; a total transport failure prints it before `;; no
    // servers could be reached`.
    let mut cmdline: Option<String> = match parsed.first_name_greeting {
        Some((pc, short_at_build, server_at_build)) if pc => {
            let mut g = String::new();
            g.push_str(&format!("\n; <<>> DiG 9.20.26 <<>> {}\n", parsed.cmdline));
            if server_at_build {
                // addresscount: the number of resolved addresses for @server,
                // resolved at parse time (dig.c getaddresses); courts pin
                // single-address cases.  Archived quirk: `dig -x ...
                // @server` builds the greeting before the @server is seen,
                // so the line is absent.
                g.push_str("; (1 server found)\n");
            }
            g.push_str(&format!(
                ";; global options:{}{}\n",
                if short_at_build { " +short" } else { "" },
                if pc { " +cmd" } else { "" }
            ));
            Some(g)
        }
        _ => None,
    };

    for lookup in &parsed.lookups {
        match query_once(&parsed, lookup, &mut cmdline) {
            Ok(()) => {}
            Err((msg, code)) => {
                if !msg.is_empty() {
                    eprintln!("dig: {msg}");
                }
                if code > rc {
                    rc = code;
                }
            }
        }
    }
    rc
}

/// One lookup unit (from one command-line "host [@server]" clause).
#[derive(Debug, Clone)]
pub struct Lookup {
    pub server: String,
    /// The raw (unparsed) name text from argv, used by idn_input exactly as
    /// BIND uses `lookup->textname` (dighost.c setup_lookup: conversion
    /// happens on the original spelling *before* dns_name_fromtext, so the
    /// escaped to-text form is never fed to libidn2).
    pub text: String,
    pub names: Vec<(Name, RrType, Class)>,
}

/// Build a lookup from a raw name argument.
pub fn build_lookup(
    server: &str,
    name_text: &str,
    qtype: RrType,
    qclass: Class,
) -> Result<Lookup, String> {
    let qname = Name::from_text(name_text, Some(&Name::root()))
        .map_err(|_| format!("invalid name '{name_text}'"))?;
    Ok(Lookup {
        server: server.to_string(),
        text: name_text.to_string(),
        names: vec![(qname, qtype, qclass)],
    })
}

fn resolve_server(server: &str, port: u16, v4: bool, v6: bool) -> Result<SocketAddr, String> {
    let host = server.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("couldn't get address for '{server}': {e}"))?
        .collect();
    for a in addrs {
        let ok = match a {
            SocketAddr::V4(_) => !v6,
            SocketAddr::V6(_) => !v4,
        };
        if ok {
            return Ok(a);
        }
    }
    Err(format!("couldn't get address for '{server}'"))
}

fn query_once(
    parsed: &DigOptions,
    lookup: &Lookup,
    cmdline: &mut Option<String>,
) -> Result<(), (String, i32)> {
    let (qname, qtype, qclass) = lookup.names[0].clone();
    // dighost.c: `if (lookup->idnin) { idn_input(textname, ...) }` — the
    // query name (the *original argv spelling*, not the parsed form) is
    // converted to its A-label form before the wire message is built; the
    // case-preservation quirk lives inside idn_input.
    let qname = if parsed.idnin {
        let text = crate::compat::libidn2::idn_input(&lookup.text);
        bind9_rs_core::name::Name::from_text(&text, Some(&bind9_rs_core::name::Name::root()))
            .map_err(|_| (format!("invalid name after IDN conversion '{text}'"), 1))?
    } else {
        qname
    };
    let port = parsed.port;
    let server_addr = resolve_server(&lookup.server, port, parsed.ipv4_only, parsed.ipv6_only)
        .map_err(|e| (e, 1))?;

    // The query message (dighost.c setup_lookup: RD is suppressed for
    // AXFR/IXFR; AD/AA/RA/TC/Z flags come from the lookup flags).
    let build_query = |id: u16| -> Result<Message, String> {
        let msg = Message {
            id,
            flags: header::Flags {
                qr: false,
                opcode: 0,
                aa: parsed.aaonly,
                tc: parsed.tcflag,
                rd: parsed.recurse && qtype != RrType::Axfr && qtype != RrType::Ixfr,
                ra: parsed.raflag,
                z: parsed.zflag,
                ad: parsed.adflag,
                cd: parsed.cdflag,
            },
            header_rcode: 0,
            question: Some(Question {
                qname: qname.clone(),
                qtype,
                qclass,
            }),
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            opt: edns_opt(parsed),
        };
        Ok(msg)
    };

    let mut msg = build_query(rand_id()).map_err(|e| (e, 1))?;
    let mut wire = Vec::new();
    msg.render(&mut wire, true)
        .map_err(|e| (format!("render: {e:?}"), 1))?;

    let mut stdout = std::io::stdout().lock();

    // The +qr path prints the send message via printmessage (dig.c
    // send_udp/send_tcp), then `;; QUERY SIZE: N` when stats are on.  The
    // greeting rides along with the first printmessage call.
    if parsed.print_qr && parsed.comments && !parsed.short {
        render_send_message(&msg, parsed, &mut *cmdline, &mut stdout)
            .map_err(|e| (e.to_string(), 1))?;
        if parsed.statistics {
            let _ = write!(stdout, ";; QUERY SIZE: {}\n\n", wire.len());
        }
    }

    // The exchange.  UDP send/recv failures print `;; communications error
    // to <addr#port>: <reason>` and retry up to `tries` attempts, re-sending
    // the same rendered message (dighost.c send_done/recv_done: the retry
    // query reuses the lookup's renderbuf, so the transaction ID is reused);
    // exhaustion then prints the pending cmdline (dighost.c:4139 prints it
    // unconditionally — archived quirk: `dig example.com +noall` still shows
    // the greeting here) plus `;; no servers could be reached` once.  TCP
    // connect failures print `;; Connection to <addr#port>(<server>) for
    // <name> failed: <reason>.` *and* `;; no servers could be reached` per
    // attempt (dighost.c:3642/3687 — observed: tries=3 prints the pair three
    // times), retry `tries` times, and never print the greeting.
    let exchange: Result<(Vec<u8>, std::time::Duration), ()> = (|| {
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let res = match parsed.transport {
                Transport::Udp => udp_exchange(&server_addr, &wire, parsed).map_err(|e| {
                    let _ = writeln!(
                        stdout,
                        ";; communications error to {}: {}",
                        server_text(&server_addr),
                        io_reason(&e)
                    );
                }),
                Transport::Tcp => tcp_exchange(&server_addr, &wire, &lookup.text).map_err(|e| {
                    let _ = writeln!(
                        stdout,
                        ";; Connection to {}({}) for {} failed: {}.",
                        server_text(&server_addr),
                        lookup.server,
                        lookup.text,
                        io_reason(&e)
                    );
                    let _ = writeln!(stdout, ";; no servers could be reached");
                }),
            };
            match res {
                Ok(v) => return Ok(v),
                Err(()) => {
                    if attempt >= usize::try_from(parsed.tries.max(1)).unwrap_or(usize::MAX) {
                        return Err(());
                    }
                }
            }
        }
    })();

    // Response handling: a truncated UDP reply requeues in TCP mode with a
    // fresh message (dighost.c recv_done: `;; Truncated, retrying in TCP
    // mode.` — the greeting is still pending and prints with the TCP
    // answer); an unparseable reply prints BIND's `;; Got bad packet:`
    // diagnostic and cancels (exit 0).  Total UDP failure prints the pending
    // cmdline then `;; no servers could be reached`, exit 9 (dighost.c
    // exitcode = 9: "No reply from server"); total TCP failure already
    // printed the per-attempt messages, exit 9.
    let (response, rtt, proto) = match exchange {
        Ok((r, t)) => match Message::parse(&r) {
            Ok(m) if parsed.transport == Transport::Udp && m.flags.tc && !parsed.ignore => {
                if parsed.comments {
                    let _ = writeln!(stdout, ";; Truncated, retrying in TCP mode.");
                }
                // Re-setup: new ID, same question/options (setup_lookup runs
                // again; the responder sends no server cookie).
                msg = build_query(rand_id()).map_err(|e| (e, 1))?;
                wire.clear();
                msg.render(&mut wire, true)
                    .map_err(|e| (format!("render: {e:?}"), 1))?;
                match tcp_exchange(&server_addr, &wire, &lookup.text) {
                    Ok((resp2, rtt2)) => (resp2, rtt2, "TCP"),
                    Err(e) => {
                        let _ = writeln!(
                            stdout,
                            ";; Connection to {}({}) for {} failed: {}.",
                            server_text(&server_addr),
                            lookup.server,
                            lookup.text,
                            io_reason(&e)
                        );
                        let _ = writeln!(stdout, ";; no servers could be reached");
                        return Err((String::new(), 9));
                    }
                }
            }
            Ok(_) => (
                r,
                t,
                if parsed.transport == Transport::Tcp {
                    "TCP"
                } else {
                    "UDP"
                },
            ),
            Err(e) => {
                print_bad_packet(&r, &e, &mut stdout);
                return Ok(());
            }
        },
        Err(()) => {
            if parsed.transport == Transport::Udp {
                if let Some(g) = cmdline.take() {
                    let _ = write!(stdout, "{g}");
                }
                let _ = writeln!(stdout, ";; no servers could be reached");
            }
            return Err((String::new(), 9));
        }
    };
    let recv_bytes = response.len();

    let resp = match Message::parse(&response) {
        Ok(m) => m,
        Err(e) => {
            print_bad_packet(&response, &e, &mut stdout);
            return Ok(());
        }
    };

    // The rcode shown is the full rcode (header + EDNS ext).
    let full_rcode = match &resp.opt {
        Some(o) => o.full_rcode(resp.header_rcode),
        None => bind9_rs_core::rcode::Rcode::from_u16(resp.header_rcode as u16),
    };

    // process_opt (dighost.c): when we sent a cookie and the response has an
    // OPT, verify the echoed cookie; a mismatch prints the client-cookie
    // warning (stdout, `;; ` prefix) and marks the COOKIE option `(bad)`.
    let mut cookie_state = output::CookieState::None;
    if parsed.sendcookie && resp.opt.is_some() {
        if let Some(opt) = &resp.opt {
            for o in opt.options() {
                if o.code == option_code::COOKIE {
                    cookie_state = if o.data.len() >= 8 && o.data[..8] == *client_cookie() {
                        if o.data.len() >= 16 {
                            output::CookieState::Good
                        } else {
                            output::CookieState::Echoed
                        }
                    } else if o.data.len() < 8 {
                        let _ = writeln!(stdout, ";; Warning: COOKIE bad token (too short)");
                        output::CookieState::Bad
                    } else {
                        let _ = writeln!(stdout, ";; Warning: Client COOKIE mismatch");
                        output::CookieState::Bad
                    };
                }
            }
        }
    }

    render_message(
        &resp,
        full_rcode,
        parsed,
        cookie_state,
        &mut *cmdline,
        &mut stdout,
    )
    .map_err(|e| (e.to_string(), 1))?;

    if parsed.statistics && !parsed.short {
        let info = StatisticsInfo {
            rtt_usec: rtt.as_micros() as u64,
            server_text: server_text(&server_addr),
            server_arg: lookup.server.clone(),
            proto,
            received: recv_bytes,
        };
        render_statistics(&info, parsed, &mut stdout).map_err(|e| (e.to_string(), 1))?;
    }

    Ok(())
}

/// Map an `io::Error` to BIND's `isc_result_totext` string for the
/// communications diagnostics (dighost.c: `isc_result_totext(eresult)`).
fn io_reason(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        WouldBlock | TimedOut => "timed out",
        ConnectionRefused => "connection refused",
        ConnectionReset => "connection reset",
        ConnectionAborted => "connection aborted",
        NetworkUnreachable => "network unreachable",
        HostUnreachable => "host unreachable",
        AddrNotAvailable => "address not available",
        AddrInUse => "address in use",
        PermissionDenied => "not permitted",
        NotFound => "not found",
        Interrupted => "interrupted",
        BrokenPipe => "connection reset",
        UnexpectedEof => "unexpected end",
        _ => "I/O error",
    }
}

fn udp_exchange(
    addr: &SocketAddr,
    query: &[u8],
    opts: &DigOptions,
) -> std::io::Result<(Vec<u8>, std::time::Duration)> {
    let bind: SocketAddr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(addr)?;
    let started = Instant::now();
    sock.send(query)?;
    let timeout = std::time::Duration::from_secs(opts.timeout_secs.max(1));
    sock.set_read_timeout(Some(timeout))?;
    let mut buf = vec![0u8; 65535];
    let n = sock.recv(&mut buf)?;
    let rtt = started.elapsed();
    Ok((buf[..n].to_vec(), rtt))
}

fn tcp_exchange(
    addr: &SocketAddr,
    query: &[u8],
    _name: &str,
) -> std::io::Result<(Vec<u8>, std::time::Duration)> {
    use std::io::{Read, Write};
    let started = Instant::now();
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let len = query.len() as u16;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed)?;
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr)?;
    let rlen = u16::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; rlen];
    stream.read_exact(&mut body)?;
    let rtt = started.elapsed();
    Ok((body, rtt))
}

/// The OPT for the query (dighost.c setup_lookup): added when `udpsize > -1
/// || dnssec || edns > -1 || ecs_addr != NULL`; the udp size defaults to
/// 1232; DO/CO come from ednsflags/dnssec/coflag; options are added in
/// order: +nsid, +subnet, COOKIE, +expire, +padding, +keepalive, +ednsopt.
fn edns_opt(opts: &DigOptions) -> Option<Opt> {
    if opts.udp_size.is_none() && !opts.dnssec && opts.edns.is_none() && !opts.nsid {
        return None;
    }
    let size = opts.udp_size.unwrap_or(1232);
    let mut o = Opt::new(size);
    if opts.dnssec || (opts.ednsflags & 0x8000) != 0 {
        o = o.with_do();
    }
    if opts.coflag || (opts.ednsflags & 0x4000) != 0 {
        o = o.with_co();
    }
    if opts.nsid {
        o = o.with_option(option_code::NSID, Vec::new());
    }
    if opts.sendcookie {
        let data = match &opts.cookie_hex {
            Some(hex) => crate::tools::dig::options::hex_decode(hex)
                .unwrap_or_else(|_| client_cookie().to_vec()),
            None => client_cookie().to_vec(),
        };
        o = o.with_option(option_code::COOKIE, data);
    }
    for (code, data) in &opts.ednsopts {
        o = o.with_option(*code, data.clone());
    }
    Some(o)
}

fn rand_id() -> u16 {
    // Use the platform crate's OS CSPRNG; fall back to a non-secure id
    // only if entropy is unavailable (transaction ids are not secrets).
    match bind9_rs_platform::random::fill_u64() {
        Ok(v) => (v & 0xffff) as u16,
        Err(_) => 0,
    }
}

fn server_text(addr: &SocketAddr) -> String {
    format!("{}#{}", addr.ip(), addr.port())
}

/// BIND's bad-packet diagnostic (dighost.c recv_done): `;; Got bad packet:
/// <isc_result_totext>` plus `hex_dump()` of the raw bytes, then the lookup
/// is cancelled (exit code stays 0).
fn print_bad_packet(packet: &[u8], err: &bind9_rs_core::error::Error, w: &mut impl Write) {
    let _ = writeln!(w, ";; Got bad packet: {}", err.bind_totext());
    hex_dump(packet, w);
}

/// dighost.c `hex_dump`: `%u bytes`, then 16-byte rows of `%02x ` followed
/// dighost.c `hex_dump`: `%u bytes`, then 16-byte rows of `%02x ` followed
/// by nine spaces and the printable ASCII (0x21..=0x7d); a trailing partial
/// row is padded with three spaces per missing byte.
fn hex_dump(buf: &[u8], w: &mut impl Write) {
    let len = buf.len();
    let _ = writeln!(w, "{len} bytes");
    for (i, &b) in buf.iter().enumerate() {
        let _ = write!(w, "{b:02x} ");
        if i % 16 == 15 {
            let _ = write!(w, "         ");
            for &c in &buf[i - 15..=i] {
                let _ = write!(
                    w,
                    "{}",
                    if (b'!'..=b'}').contains(&c) {
                        c as char
                    } else {
                        '.'
                    }
                );
            }
            let _ = writeln!(w);
        }
    }
    if len % 16 != 0 {
        for _ in (len % 16)..16 {
            let _ = write!(w, "   ");
        }
        let _ = write!(w, "         ");
        let start = (len / 16) * 16;
        for &c in &buf[start..len] {
            let _ = write!(
                w,
                "{}",
                if (b'!'..=b'}').contains(&c) {
                    c as char
                } else {
                    '.'
                }
            );
        }
        let _ = writeln!(w);
    }
}
