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
use bind9_rs_core::edns::Opt;
use bind9_rs_core::message::{header, question::Question, Message};
use bind9_rs_core::name::Name;
use bind9_rs_core::rrtype::RrType;
use options::{parse_args, DigOptions, Transport};
use output::{render_message, render_statistics, StatisticsInfo};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Instant;

/// Run dig with the given argv (excluding argv[0]); returns the exit code
/// (BIND convention: 0 success, 1 failure).
pub fn run(argv: &[String]) -> i32 {
    let parsed = match parse_args(argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("{}", options::USAGE);
            return 1;
        }
    };

    if parsed.help {
        print!("{}", options::USAGE);
        return 0;
    }
    if parsed.version {
        println!("{}", crate::common::versioning::dig_version_line());
        return 0;
    }

    let mut rc = 0;
    for lookup in &parsed.lookups {
        match query_once(&parsed, lookup) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("dig: {e}");
                rc = 1;
            }
        }
    }
    rc
}

/// One lookup unit (from one command-line "host [@server]" clause).
#[derive(Debug, Clone)]
pub struct Lookup {
    pub server: String,
    pub names: Vec<(Name, RrType, Class)>,
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

fn query_once(parsed: &DigOptions, lookup: &Lookup) -> Result<(), String> {
    let (qname, qtype, qclass) = lookup.names[0].clone();
    let port = parsed.port;
    let server_addr = resolve_server(&lookup.server, port, parsed.ipv4_only, parsed.ipv6_only)?;

    let msg = Message {
        id: rand_id(),
        flags: header::Flags {
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: parsed.recurse,
            ra: false,
            z: false,
            ad: parsed.adflag,
            cd: parsed.cdflag,
        },
        header_rcode: 0,
        question: Some(Question {
            qname,
            qtype,
            qclass,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        opt: Some(edns_opt(parsed)),
    };

    let mut wire = Vec::new();
    msg.render(&mut wire, true)
        .map_err(|e| format!("render: {e:?}"))?;

    if parsed.print_qr {
        // BIND prints the query with +qr before the response.
        println!(";; Sending:");
        println!(
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {}",
            msg.id
        );
        println!(";; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1");
        println!();
    }

    let (response, rtt) = match parsed.transport {
        Transport::Udp => udp_exchange(&server_addr, &wire, parsed)?,
        Transport::Tcp => tcp_exchange(&server_addr, &wire)?,
    };
    let recv_bytes = response.len();

    let resp = Message::parse(&response).map_err(|e| format!("parse response: {e:?}"))?;

    // The rcode shown is the full rcode (header + EDNS ext).
    let full_rcode = match &resp.opt {
        Some(o) => o.full_rcode(resp.header_rcode),
        None => bind9_rs_core::rcode::Rcode::from_u16(resp.header_rcode as u16),
    };

    render_message(&resp, full_rcode, parsed, &mut std::io::stdout().lock())
        .map_err(|e| e.to_string())?;

    if parsed.statistics {
        let info = StatisticsInfo {
            rtt_usec: rtt.as_micros() as u64,
            server_text: server_text(&server_addr),
            server_arg: lookup.server.clone(),
            proto: match parsed.transport {
                Transport::Udp => "UDP",
                Transport::Tcp => "TCP",
            },
            received: recv_bytes,
        };
        render_statistics(&info, &mut std::io::stdout().lock()).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn udp_exchange(
    addr: &SocketAddr,
    query: &[u8],
    opts: &DigOptions,
) -> Result<(Vec<u8>, std::time::Duration), String> {
    let bind: SocketAddr = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
    sock.connect(addr).map_err(|e| format!("connect: {e}"))?;
    let started = Instant::now();
    sock.send(query).map_err(|e| format!("send: {e}"))?;
    let timeout = std::time::Duration::from_secs(opts.timeout_secs.max(1));
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let mut buf = vec![0u8; 65535];
    let n = match sock.recv(&mut buf) {
        Ok(n) => n,
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Err("communications error: timed out".to_string());
        }
        Err(e) => return Err(format!("recv: {e}")),
    };
    let rtt = started.elapsed();
    Ok((buf[..n].to_vec(), rtt))
}

fn tcp_exchange(addr: &SocketAddr, query: &[u8]) -> Result<(Vec<u8>, std::time::Duration), String> {
    use std::io::{Read, Write};
    let started = Instant::now();
    let mut stream = std::net::TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let len = query.len() as u16;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream
        .write_all(&framed)
        .map_err(|e| format!("send: {e}"))?;
    let mut hdr = [0u8; 2];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| format!("recv: {e}"))?;
    let rlen = u16::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; rlen];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("recv: {e}"))?;
    let rtt = started.elapsed();
    Ok((body, rtt))
}

fn edns_opt(opts: &DigOptions) -> Opt {
    let mut o = Opt::new(opts.udp_size.unwrap_or(1232));
    if opts.dnssec {
        o = o.with_do();
    }
    o
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
        names: vec![(qname, qtype, qclass)],
    })
}
