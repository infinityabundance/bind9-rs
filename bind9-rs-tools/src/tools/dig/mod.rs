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
use bind9_rs_core::message::{header, question::Question, Message, ParseStatus};
use bind9_rs_core::name::Name;
use bind9_rs_core::rrtype::RrType;
use options::{parse_args, DigOptions, ParseError, Transport};
use output::{
    render_message, render_send_message, render_statistics, render_yaml_message, StatisticsInfo,
};
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
    /// The transport snapshot at name-parse time (dig.c `lookup->tcp_mode`):
    /// `+tcp` after a name applies to that lookup only; later names clone
    /// the default lookup and keep the original transport.
    pub transport: Transport,
    /// dig.c `lookup->tcp_mode_set`: whether +tcp/+vc (or +notcp) was given
    /// for this lookup; AXFR/IXFR/ANY force TCP only when it is unset.
    pub tcp_mode_set: bool,
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
        transport: Transport::Udp,
        tcp_mode_set: false,
    })
}

fn resolve_server(server: &str, port: u16, v4: bool, v6: bool) -> Result<SocketAddr, String> {
    let host = server.trim_start_matches('[').trim_end_matches(']');
    // dig.c getaddresses: under -6 an IPv4 literal resolves to its
    // v4-mapped form (getaddrinfo AF_INET6), which start_tcp/start_udp then
    // skip with the mapped-address warning.
    if v6 && !v4 {
        if let Ok(v4addr) = host.parse::<std::net::Ipv4Addr>() {
            let mapped: std::net::Ipv6Addr = format!("::ffff:{v4addr}").parse().unwrap();
            return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                mapped, port, 0, 0,
            )));
        }
    }
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

    // dighost.c start_tcp/start_udp: under -6 an IPv4 literal resolves to a
    // v4-mapped address, which is skipped with a warning; an all-skipped
    // address list prints `;; No acceptable nameservers` and the lookup is
    // cancelled with exit code 0 (no greeting, no message).
    if parsed.ipv6_only {
        if let SocketAddr::V6(a) = &server_addr {
            if a.ip().to_ipv4_mapped().is_some() {
                let mut stdout = std::io::stdout().lock();
                if parsed.comments {
                    let _ = writeln!(stdout, ";; Skipping mapped address '{}'", a.ip());
                    let _ = writeln!(stdout, ";; No acceptable nameservers");
                }
                return Ok(());
            }
        }
    }

    // The query message (dighost.c setup_lookup: RD is suppressed for
    // AXFR/IXFR; AD/AA/RA/TC/Z flags come from the lookup flags; the
    // carried cookie is the server cookie learned from the previous
    // exchange (process_cookie → l->cookie)).
    let build_query =
        |id: u16, carried: Option<&[u8]>, edns_ver: Option<u8>| -> Result<Message, String> {
            let msg = Message::build(
                id,
                header::Flags {
                    qr: false,
                    opcode: parsed.opcode,
                    aa: parsed.aaonly,
                    tc: parsed.tcflag,
                    rd: parsed.recurse && qtype != RrType::Axfr && qtype != RrType::Ixfr,
                    ra: parsed.raflag,
                    z: parsed.zflag,
                    ad: parsed.adflag,
                    cd: parsed.cdflag,
                },
                0,
                // +header-only builds the query without a question (dighost.c
                // setup_lookup skips the question section; the observed wire has
                // qd=0, which the fixture answers with FORMERR).
                if parsed.header_only {
                    None
                } else {
                    Some(Question {
                        qname: qname.clone(),
                        qtype,
                        qclass,
                    })
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                edns_opt(parsed, carried, edns_ver),
            );
            let msg = if parsed.padding.is_some() {
                pad_query(msg, parsed.padding.unwrap_or(0))
            } else {
                msg
            };
            Ok(msg)
        };

    // The server cookie learned from a verified response, carried into the
    // next query for the same lookup (dighost.c process_cookie: `copy` on a
    // good echo stores the received cookie in l->cookie).
    let mut carried_cookie: Option<Vec<u8>> = None;
    // The EDNS version negotiated by a BADVERS retry (dighost.c ednsneg).
    let mut negotiated_edns: Option<u8> = None;
    let mut msg = build_query(parsed.qid.unwrap_or_else(rand_id), None, negotiated_edns)
        .map_err(|e| (e, 1))?;
    let mut wire = Vec::new();
    msg.render(&mut wire, true)
        .map_err(|e| (format!("render: {e:?}"), 1))?;

    let mut stdout = std::io::stdout().lock();

    // The response loop (dighost.c launch/recv_done): each iteration prints
    // the +qr send block, exchanges, and applies the response checks —
    // opcode mismatch (warning + timed-out + retry with the same wire),
    // BADVERS version negotiation (comment + retry with the lower version),
    // truncation (requeue in TCP mode with a fresh message), and the
    // recoverable/bad-packet paths.  UDP send/recv failures print
    // `;; communications error to <addr#port>: <reason>` and retry up to
    // `tries` attempts re-sending the same rendered message (dighost.c
    // send_done/recv_done: the retry query reuses the lookup's renderbuf, so
    // the transaction ID is reused); exhaustion then prints the pending
    // cmdline (dighost.c:4139 prints it unconditionally — archived quirk:
    // `dig example.com +noall` still shows the greeting here) plus
    // `;; no servers could be reached` once.  TCP connect failures print
    // `;; Connection to <addr#port>(<server>) for <name> failed: <reason>.`
    // *and* `;; no servers could be reached` per attempt
    // (dighost.c:3642/3687 — observed: tries=3 prints the pair three times),
    // retry `tries` times, and never print the greeting.
    let mut attempts_left: u32 = parsed.tries.max(1);
    let (response, rtt, proto) = loop {
        if parsed.print_qr && parsed.comments && !parsed.short {
            render_send_message(
                &msg,
                parsed,
                &mut *cmdline,
                &server_addr,
                wire.len(),
                lookup.transport,
                &mut stdout,
            )
            .map_err(|e| (e.to_string(), 1))?;
            if parsed.statistics {
                let _ = write!(stdout, ";; QUERY SIZE: {}\n\n", wire.len());
            }
        }

        let exchanged: Result<(Vec<u8>, std::time::Duration), ()> = match lookup.transport {
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
        let (r, t) = match exchanged {
            Ok(v) => v,
            Err(()) => {
                attempts_left -= 1;
                if attempts_left == 0 {
                    if lookup.transport == Transport::Udp {
                        if let Some(g) = cmdline.take() {
                            let _ = write!(stdout, "{g}");
                        }
                        let _ = writeln!(stdout, ";; no servers could be reached");
                    }
                    return Err((String::new(), 9));
                }
                continue;
            }
        };

        let m = match Message::parse(&r) {
            Ok(m) => m,
            Err(e) => {
                // An unparseable reply prints BIND's `;; Got bad packet:`
                // diagnostic and cancels (exit 0).
                print_bad_packet(&r, &e, &mut stdout);
                return Ok(());
            }
        };

        // dighost.c recv_done: a response whose opcode differs from the
        // query's is discarded with a warning and the query waits (the
        // receive timeout then reports `timed out` and the retry re-sends
        // the same wire).
        if m.flags.opcode != parsed.opcode {
            let _ = writeln!(
                stdout,
                ";; Warning: Opcode mismatch: expected {}, got {}",
                opcode_name(parsed.opcode),
                opcode_name(m.flags.opcode)
            );
            let _ = writeln!(
                stdout,
                ";; communications error to {}: timed out",
                server_text(&server_addr)
            );
            attempts_left -= 1;
            if attempts_left == 0 {
                let _ = writeln!(stdout, ";; no servers could be reached");
                return Err((String::new(), 9));
            }
            continue;
        }

        // dighost.c ednsneg: BADVERS (full rcode 16) with an OPT whose
        // version is lower than ours → retry with that version.
        if m.rcode == 16 && parsed.ednsneg {
            if let Some(opt) = &m.opt {
                let ver = opt.version();
                if (u16::from(ver)) < u16::from(parsed.edns.unwrap_or(0)) {
                    if parsed.comments {
                        let _ = writeln!(stdout, ";; BADVERS, retrying with EDNS version {}.", ver);
                    }
                    negotiated_edns = Some(ver);
                    msg = build_query(
                        parsed.qid.unwrap_or_else(rand_id),
                        carried_cookie.as_deref(),
                        negotiated_edns,
                    )
                    .map_err(|e| (e, 1))?;
                    wire.clear();
                    msg.render(&mut wire, true)
                        .map_err(|e| (format!("render: {e:?}"), 1))?;
                    attempts_left -= 1;
                    if attempts_left == 0 {
                        let _ = writeln!(stdout, ";; no servers could be reached");
                        return Err((String::new(), 9));
                    }
                    continue;
                }
            }
        }

        // A truncated UDP reply requeues in TCP mode with a fresh message
        // (dighost.c recv_done: `;; Truncated, retrying in TCP mode.` — the
        // greeting is still pending and prints with the TCP answer).
        if lookup.transport == Transport::Udp && m.flags.tc && !parsed.ignore {
            // process_opt runs on this truncated response too, so the server
            // cookie is learned before the TCP retry is built.
            let (_, tc_cookie) = verify_response_cookie(parsed, &m, &mut stdout);
            carried_cookie = tc_cookie;
            if parsed.comments {
                let _ = writeln!(stdout, ";; Truncated, retrying in TCP mode.");
            }
            msg = build_query(
                parsed.qid.unwrap_or_else(rand_id),
                carried_cookie.as_deref(),
                negotiated_edns,
            )
            .map_err(|e| (e, 1))?;
            wire.clear();
            msg.render(&mut wire, true)
                .map_err(|e| (format!("render: {e:?}"), 1))?;
            match tcp_exchange(&server_addr, &wire, &lookup.text) {
                Ok((resp2, rtt2)) => break (resp2, rtt2, "TCP"),
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

        break (
            r,
            t,
            if lookup.transport == Transport::Tcp {
                "TCP"
            } else {
                "UDP"
            },
        );
    };
    let recv_bytes = response.len();

    // dig's parse flags (PRESERVEORDER|BESTEFFORT|IGNORETRUNCATION): a
    // DNS_R_RECOVERABLE parse prints BIND's malformed-packet warning and
    // proceeds with the message; the unparsed tail is the extrabytes.
    let (resp, status, consumed) = match Message::parse_dig(&response) {
        Ok(v) => v,
        Err(e) => {
            print_bad_packet(&response, &e, &mut stdout);
            return Ok(());
        }
    };
    let extrabytes = response.len() - consumed;
    if status == ParseStatus::Recoverable {
        let _ = writeln!(
            stdout,
            ";; Warning: Message parser reports malformed message packet."
        );
    }

    // The rcode shown is the full rcode (header + EDNS ext).
    let full_rcode = match &resp.opt {
        Some(o) => o.full_rcode(resp.header_rcode),
        None => bind9_rs_core::rcode::Rcode::from_u16(resp.header_rcode as u16),
    };

    // process_opt (dighost.c): verify the response's COOKIE option and carry
    // a verified echo into the next query for this lookup.
    let (cookie_state, final_cookie) = verify_response_cookie(parsed, &resp, &mut stdout);
    carried_cookie = final_cookie;

    let identify = output::IdentifyInfo {
        addr_text: server_text(&server_addr),
        server_arg: lookup.server.clone(),
        rtt_usec: rtt.as_micros() as u64,
        bytes: recv_bytes,
    };

    if parsed.yaml {
        let mut yaml_out = Vec::new();
        render_yaml_message(
            &mut yaml_out,
            &resp,
            full_rcode,
            parsed,
            cookie_state,
            &server_addr,
            recv_bytes,
            if lookup.transport == Transport::Tcp {
                "TCP"
            } else {
                "UDP"
            },
        );
        stdout
            .write_all(&yaml_out)
            .map_err(|e| (e.to_string(), 1))?;
    } else {
        render_message(
            &resp,
            full_rcode,
            parsed,
            cookie_state,
            &mut *cmdline,
            extrabytes,
            Some(&identify),
            &mut stdout,
        )
        .map_err(|e| (e.to_string(), 1))?;
    }

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

/// dighost.c process_opt/process_cookie: verify the response's COOKIE option
/// against the sent client cookie (the `+cookie=hex` override when given,
/// else the per-process random cookie — dighost.c `sent = l->cookie ?:
/// cookie`, where the `cookie` buffer holds the +cookie override).  A
/// mismatch prints the client-cookie warning (gated on comments) and marks
/// the COOKIE option `(bad)`; a good (or echoed) echo returns the received
/// bytes for carry-forward (process_cookie stores them in l->cookie).
fn verify_response_cookie(
    parsed: &DigOptions,
    resp: &Message,
    w: &mut impl Write,
) -> (output::CookieState, Option<Vec<u8>>) {
    let mut cookie_state = output::CookieState::None;
    let mut carried = None;
    if parsed.sendcookie {
        let sent: Vec<u8> = match &parsed.cookie_hex {
            Some(hex) => crate::tools::dig::options::hex_decode(hex)
                .unwrap_or_else(|_| client_cookie().to_vec()),
            None => client_cookie().to_vec(),
        };
        if let Some(opt) = &resp.opt {
            for o in opt.options() {
                if o.code == option_code::COOKIE {
                    cookie_state = if o.data.len() >= 8 && o.data[..8] == sent[..] {
                        if o.data.len() >= 16 {
                            output::CookieState::Good
                        } else {
                            output::CookieState::Echoed
                        }
                    } else if o.data.len() < 8 {
                        if parsed.comments {
                            let _ = writeln!(w, ";; Warning: COOKIE bad token (too short)");
                        }
                        output::CookieState::Bad
                    } else {
                        if parsed.comments {
                            let _ = writeln!(w, ";; Warning: Client COOKIE mismatch");
                        }
                        output::CookieState::Bad
                    };
                    if matches!(
                        cookie_state,
                        output::CookieState::Good | output::CookieState::Echoed
                    ) {
                        carried = Some(o.data.clone());
                    }
                }
            }
        }
    }
    (cookie_state, carried)
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
/// 1232; the EDNS version comes from `+edns=N` (or the negotiated BADVERS
/// version); the flags word is assembled exactly like dighost.c: the
/// `+ednsflags` DO/CO bits are stripped, then dnssec ORs DO back in and
/// coflag ORs CO (`flags &= ~(DO|CO); if dnssec flags |= DO; if coflag
/// flags |= CO`); options are added in order: +nsid, +subnet, COOKIE,
/// +expire, +padding (0-length placeholder, filled by `pad_query` at
/// render-time size), +keepalive, +ednsopt.  The COOKIE data is the carried
/// server cookie when one was learned (dighost.c: `l->cookie`), else the
/// per-process 8-byte client cookie, else the `+cookie=hex` override.
/// `negotiated` overrides the EDNS version after a BADVERS retry.
fn edns_opt(opts: &DigOptions, carried: Option<&[u8]>, negotiated: Option<u8>) -> Option<Opt> {
    if opts.udp_size.is_none()
        && !opts.dnssec
        && opts.edns.is_none()
        && !opts.nsid
        && opts.subnet.is_none()
    {
        return None;
    }
    let size = opts.udp_size.unwrap_or(1232);
    let version = negotiated.unwrap_or(opts.edns.unwrap_or(0));
    // dighost.c: `flags = ednsflags; flags &= ~(DO|CO); if (dnssec) flags
    // |= DO; if (coflag) flags |= CO;` — DO (0x8000) renders as the
    // do_flag field, the rest ride the 15-bit Z field.
    let mut z = opts.ednsflags & !(0x8000 | 0x4000);
    if opts.coflag {
        z |= 0x4000;
    }
    let mut o = Opt::new(size).with_version(version);
    if opts.dnssec {
        o = o.with_do();
    }
    o = o.with_z(z);
    if opts.nsid {
        o = o.with_option(option_code::NSID, Vec::new());
    }
    if let Some(subnet) = &opts.subnet {
        if let Some(data) = ecs_option_data(subnet) {
            o = o.with_option(option_code::ECS, data);
        }
    }
    if opts.sendcookie {
        let data = match &opts.cookie_hex {
            Some(hex) => crate::tools::dig::options::hex_decode(hex)
                .unwrap_or_else(|_| client_cookie().to_vec()),
            None => carried.unwrap_or(client_cookie()).to_vec(),
        };
        o = o.with_option(option_code::COOKIE, data);
    }
    if opts.expire {
        o = o.with_option(option_code::EXPIRE, Vec::new());
    }
    if opts.padding.is_some() {
        // A 0-length PAD placeholder: BIND adds `opts[i].length = 0` at
        // build (dighost.c) and dns_message_renderend fills it so the total
        // message is a multiple of the padding size.  `pad_query` patches
        // the payload from the rendered size.
        o = o.with_option(option_code::PADDING, Vec::new());
    }
    if opts.tcp_keepalive {
        o = o.with_option(option_code::TCP_KEEPALIVE, Vec::new());
    }
    for (code, data) in &opts.ednsopts {
        o = o.with_option(*code, data.clone());
    }
    Some(o)
}

/// BIND `dns_message_opt_setpadding` / `dns_message_renderend`: the PAD
/// option was reserved with a 0-length payload at build; renderend computes
/// `padsize = padding - ((used + reserved) % padding)` where `used`
/// INCLUDES the 4-byte PAD option header, and fills the payload (an
/// already-aligned message gets padsize 0 and keeps the empty PAD).  The
/// query message has no other sections, so the size is deterministic: 12
/// (header) + question + OPT (with the empty PAD).
fn pad_query(mut msg: Message, pad: u16) -> Message {
    let opt = match msg.opt.take() {
        Some(o) => o,
        None => return msg,
    };
    let question_len = msg
        .question
        .as_ref()
        .map(|q| q.qname.wire_len_full() + 4)
        .unwrap_or(0);
    let opt_len = 11
        + opt
            .options()
            .iter()
            .map(|o| 4 + o.data.len())
            .sum::<usize>();
    let used = 12 + question_len + opt_len;
    let padsize = if used % usize::from(pad) == 0 {
        0
    } else {
        usize::from(pad) - used % usize::from(pad)
    };
    let opt = opt.with_padding_payload(vec![0u8; padsize]);
    msg.opt = Some(opt);
    msg
}

/// Encode an ECS option for `+subnet=addr/len` (RFC 7871: family, source
/// prefix length, scope 0, the address bits).  An unparseable prefix is
/// dropped, mirroring BIND's parse_netprefix failure to set ecs_addr.
fn ecs_option_data(text: &str) -> Option<Vec<u8>> {
    let (addr, plen) = match text.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (text, 24),
    };
    let (family, bytes, max): (u16, Vec<u8>, u8) =
        if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
            (1, v4.octets().to_vec(), 32)
        } else if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
            (2, v6.octets().to_vec(), 128)
        } else {
            return None;
        };
    if plen > max {
        return None;
    }
    let nbytes = usize::from(plen + 7) / 8;
    let mut data = Vec::with_capacity(4 + nbytes);
    data.extend_from_slice(&family.to_be_bytes());
    data.push(plen);
    data.push(0); // scope
    data.extend_from_slice(&bytes[..nbytes]);
    Some(data)
}

/// The opcode text table (dighost.c opcodetext).
fn opcode_name(opcode: u8) -> &'static str {
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
