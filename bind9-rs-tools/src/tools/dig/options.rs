//! `dig` command-line parsing (BIND `dig.c` semantics, courted by
//! `CLI-DIG-OPTIONS-*`).
//!
//! BIND's `+option` handling accepts unambiguous case-insensitive prefixes
//! (`FULLCHECK`: the argument must be a prefix of exactly the checked name,
//! first matching chain wins) and errors with
//! `Invalid option: +<option>` + usage, exit 1.

use bind9_rs_core::class::Class;
use bind9_rs_core::rrtype::RrType;
use std::net::IpAddr;

use super::Lookup;

/// The dig usage text (BIND 9.20 shape).
pub const USAGE: &str = "Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}\n\
            {global-d-opt} host [@local-server] {local-d-opt}\n\
            [ host [@local-server] {local-d-opt} [...]]\n";

/// The dig help text (BIND 9.20 shape).
pub const HELP: &str = "\
Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}\n\
            {global-d-opt} host [@local-server] {local-d-opt}\n\
            [ host [@local-server] {local-d-opt} [...]]\n\
Where:  domain	  is in the Domain Name System\n\
        q-class  is one of (in,hs,ch,...) [default: in]\n\
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]\n\
                 (Use ixfr=version for type ixfr)\n\
        q-opt    is one of:\n\
                 -4                  (use IPv4 query transport only)\n\
                 -6                  (use IPv6 query transport only)\n\
                 -b address[#port]   (bind to source address/port)\n\
                 -c class            (set query class)\n\
                 -f filename         (batch mode)\n\
                 -k keyfile          (specify tsig key file)\n\
                 -m                  (enable memory usage debugging)\n\
                 -p port             (specify port number)\n\
                 -q name             (specify query name)\n\
                 -t type             (set query type)\n\
                 -u                  (display times in usec instead of msec)\n\
                 -x dot-notation     (shortcut for reverse lookups)\n\
                 -y [hmac:]name:secret  (specify named base64 tsig key)\n\
                 -h                  (print help and exit)\n\
                 -v                  (print version and exit)\n\
        global-d-opt    is one of:\n\
                 +[no]aaflag         (+[no]aaflag is same as +[no]aaonly)\n\
                 +[no]additional     (Control display of additional section)\n\
                 +[no]adflag         (Set or clear the AD bit)\n\
                 +[no]all            (Set or clear all display flags)\n\
                 +[no]answer         (Control display of answer section)\n\
                 +[no]authority      (Control display of authority section)\n\
                 +[no]badcookie      (Retry with a new cookie if BADCOOKIE)\n\
                 +[no]besteffort     (Try to parse DNS errors)\n\
                 +bufsize=###        (Set EDNS0 Max UDP packet size)\n\
                 +[no]cdflag         (Set or clear the CD bit)\n\
                 +[no]class          (Control display of class in records)\n\
                 +[no]cmd            (Control display of command line)\n\
                 +[no]comments       (Control display of comment lines)\n\
                 +[no]cookie         (Send a COOKIE option)\n\
                 +[no]crypto         (Control display of cryptographic fields)\n\
                 +[no]defname        (Use search list)\n\
                 +[no]dnssec         (Request DNSSEC records)\n\
                 +domain=###         (Set default domainname)\n\
                 +[no]edns[=###]     (Set EDNS version)\n\
                 +[no]ednsflags=###  (Set EDNS flags bits)\n\
                 +[no]ednsnegotiation (Set EDNS version negotiation)\n\
                 +ednsopt=###[:value] (Send specified EDNS option)\n\
                 +[no]expandaaaa     (Expand AAAA records)\n\
                 +[no]expire         (Request time to expire)\n\
                 +[no]fail           (Do not try next server)\n\
                 +[no]header-only    (Send query without a question section)\n\
                 +[no]identify       (ID responders in short answers)\n\
                 +[no]idnin          (Parse IDN names using IDNA2008)\n\
                 +[no]idnout         (Convert IDN response names using IDNA2008)\n\
                 +[no]ignore         (Don't revert to TCP for TC responses.)\n\
                 +[no]keepopen       (Keep the TCP socket open between queries)\n\
                 +[no]mapped         (Map IPv4 to IPv6 when displaying)\n\
                 +[no]multiline      (Print records in an expanded format)\n\
                 +ndots=###          (Set search NDOTS value)\n\
                 +[no]nsid           (Request Name Server ID)\n\
                 +[no]onesoa         (AXFR prints only one SOA record)\n\
                 +opcode=###         (Set the opcode of the request)\n\
                 +[no]qr             (Print question before sending)\n\
                 +[no]question       (Control display of question section)\n\
                 +[no]raflag         (Set or clear the RA bit)\n\
                 +[no]rdflag         (Set or clear the RD bit)\n\
                 +[no]recurse        (Recursive queries)\n\
                 +retry=###          (Set number of UDP retries) [default=2]\n\
                 +[no]rrcomments     (Control display of per-record comments)\n\
                 +[no]search         (Set whether to use the searchlist)\n\
                 +[no]short          (Short form answer)\n\
                 +[no]showsearch     (Search with intermediate results)\n\
                 +split=###          (Split long hex fields)\n\
                 +[no]stats          (Control display of statistics)\n\
                 +subnet=addr        (Set edns-client-subnet option)\n\
                 +[no]tcp            (TCP mode)\n\
                 +time=###           (Set query timeout) [default=5]\n\
                 +tries=###          (Set number of UDP attempts) [default=3]\n\
                 +[no]truncate       (Set the TC flag)\n\
                 +trusted-key=###    (Trusted key for DNSSEC)\n\
                 +[no]ttlid          (Control display of ttls in records)\n\
                 +[no]ttlunits       (Display TTLs in human-readable units)\n\
                 +[no]useedns        (Use EDNS)\n\
                 +[no]yaml           (Present the results as YAML)\n\
                 +[no]zflag          (Set or clear the Z flag)\n";

/// Transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Parsed dig invocation.
#[derive(Debug, Clone)]
pub struct DigOptions {
    pub lookups: Vec<Lookup>,
    pub help: bool,
    pub version: bool,
    pub port: u16,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub transport: Transport,
    pub recurse: bool,
    pub dnssec: bool,
    pub edns: bool,
    pub udp_size: Option<u16>,
    pub timeout_secs: u64,
    pub tries: u32,
    pub print_qr: bool,
    pub print_cmd: bool,
    pub comments: bool,
    pub statistics: bool,
    pub short: bool,
    pub section_question: bool,
    pub section_answer: bool,
    pub section_authority: bool,
    pub section_additional: bool,
    pub aaflag: bool,
    pub adflag: bool,
    pub cdflag: bool,
    pub tcflag: bool,
    pub zflag: bool,
    pub multiline: bool,
    pub ttlunits: bool,
    pub nottl: bool,
    pub noclass: bool,
    pub server: String,
    /// IDN conversion of query names (dighost.c make_empty_lookup: default
    /// on unless IDN_DISABLE is set; `+idnin`/`+noidnin` override).
    pub idnin: bool,
    /// IDN conversion of response names (default: stdout is a TTY;
    /// `+idnout`/`+noidnout` override).
    pub idnout: bool,
    /// Whether +tcp/+notcp was given (AXFR/ANY/ixfr force TCP only when
    /// this is unset; dig.c `tcp_mode_set`).
    pub tcp_mode_set: bool,
    /// Serial for `-t ixfr=N` / positional `ixfr=N`.
    pub ixfr_serial: Option<u32>,
}

impl Default for DigOptions {
    fn default() -> Self {
        DigOptions {
            lookups: Vec::new(),
            help: false,
            version: false,
            port: 53,
            ipv4_only: false,
            ipv6_only: false,
            transport: Transport::Udp,
            recurse: true,
            dnssec: false,
            edns: true,
            udp_size: None,
            timeout_secs: 5,
            tries: 3,
            print_qr: false,
            print_cmd: true,
            comments: true,
            statistics: true,
            short: false,
            section_question: true,
            section_answer: true,
            section_authority: true,
            section_additional: true,
            aaflag: false,
            adflag: false,
            cdflag: false,
            tcflag: false,
            zflag: false,
            multiline: false,
            ttlunits: false,
            nottl: false,
            noclass: false,
            server: "127.0.0.1".to_string(),
            // dighost.c make_empty_lookup(): IDN defaults depend on the
            // IDN_DISABLE environment variable and on stdout being a TTY
            // (idnout).  The oracle binary was built without libidn2, where
            // both default to false; our binary always has IDN support, so
            // the defaults match a libidn2-enabled build.
            idnin: std::env::var_os("IDN_DISABLE").is_none(),
            idnout: std::io::IsTerminal::is_terminal(&std::io::stdout()),
            tcp_mode_set: false,
            ixfr_serial: None,
        }
    }
}

/// Parse the dig argv with BIND 9.20 semantics (dig.c parse_args).
///
/// Positional handling mirrors the C state machine exactly:
/// - `open_type_class` starts true; `-t`/`-c` set it false.
/// - while true, each positional is tried as `ixfr=N`, then as a type
///   (`dns_rdatatype_fromtext`), then as a class, and only then as a name;
///   a type/class applies to the current (last) lookup.
/// - each name starts a new lookup carrying the accumulated type/class state.
pub fn parse_args(argv: &[String]) -> Result<DigOptions, String> {
    let mut opts = DigOptions::default();
    let mut server = String::new();
    let mut names: Vec<(String, RrType, Class)> = Vec::new();

    // The lookup state that positionals mutate (dig.c `lookup`):
    let mut open_type_class = true;
    let mut rdtype = RrType::A;
    let mut rdclass = Class::In;
    let mut rdtypeset = false;
    let mut rdclassset = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some(rest) = arg.strip_prefix('@') {
            if !server.is_empty() {
                return Err("Multiple servers specified".to_string());
            }
            server = rest.to_string();
        } else if arg.starts_with('+') {
            parse_plus(&mut opts, &arg[1..])?;
        } else if let Some(rest) = arg.strip_prefix('-') {
            // Short options: -t, -c, -p, -q, -x, -4, -6, -v, -h, -b.
            if rest.is_empty() {
                return Err("Invalid option: -".to_string());
            }
            let opt = &rest[..1];
            let has_value = rest.len() > 1;
            let mut value = if has_value {
                Some(rest[1..].to_string())
            } else {
                None
            };
            match opt {
                "4" => opts.ipv4_only = true,
                "6" => opts.ipv6_only = true,
                "v" => opts.version = true,
                "h" | "?" => opts.help = true,
                "t" => {
                    // dig.c case 't': sets open_type_class = false; the
                    // type applies to the current lookup.
                    open_type_class = false;
                    let value = next_value(argv, &mut i, value)?;
                    if value.len() >= 5 && value[..5].eq_ignore_ascii_case("ixfr=") {
                        rdtype = RrType::Ixfr;
                        if rdtypeset {
                            eprintln!(";; Warning, extra type option");
                        }
                        let serial = parse_serial(&value[5..])?;
                        rdtypeset = true;
                        opts.ixfr_serial = Some(serial);
                        opts.section_question = true;
                        opts.comments = true;
                        if !opts.tcp_mode_set {
                            opts.transport = Transport::Tcp;
                        }
                    } else {
                        match RrType::from_text(&value) {
                            Ok(t) if t != RrType::Ixfr => {
                                if rdtypeset {
                                    eprintln!(";; Warning, extra type option");
                                }
                                rdtype = t;
                                rdtypeset = true;
                                opts.ixfr_serial = None;
                                if t == RrType::Axfr {
                                    opts.section_question = true;
                                    opts.comments = true;
                                    // dighost.c setup_lookup: AXFR forces TCP.
                                    if !opts.tcp_mode_set {
                                        opts.transport = Transport::Tcp;
                                    }
                                } else if t == RrType::Any && !opts.tcp_mode_set {
                                    opts.transport = Transport::Tcp;
                                }
                            }
                            // `-t ixfr` without a serial is treated as an
                            // unknown type (dig.c: `result = DNS_R_UNKNOWN`).
                            _ => eprintln!(";; Warning, ignoring invalid type {value}"),
                        }
                    }
                }
                "c" => {
                    // dig.c case 'c': sets open_type_class = false.
                    open_type_class = false;
                    let value = next_value(argv, &mut i, value)?;
                    match Class::from_text(&value) {
                        Ok(c) => {
                            if rdclassset {
                                eprintln!(";; Warning, extra class option");
                            }
                            rdclass = c;
                            rdclassset = true;
                        }
                        Err(_) => eprintln!(";; Warning, ignoring invalid class {value}"),
                    }
                }
                "p" => {
                    let value = next_value(argv, &mut i, value)?;
                    opts.port = value.parse().map_err(|_| "invalid port".to_string())?;
                }
                "b" => {
                    let value = next_value(argv, &mut i, value)?;
                    let _ = value; // source-address binding: accepted, not yet wired
                }
                "q" => {
                    // dig.c case 'q': sets the name directly.
                    let value = next_value(argv, &mut i, value)?;
                    names.push((value, rdtype, rdclass));
                }
                "x" => {
                    // dig.c case 'x': reverse lookup; PTR/IN unless already set.
                    let value = next_value(argv, &mut i, value)?;
                    let ip: std::net::IpAddr = value.parse().map_err(|_| {
                        // dig.c: fprintf(stderr, "Invalid IP address %s\n"); exit(1)
                        format!("Invalid IP address {value}")
                    })?;
                    let rev = reverse_name(ip);
                    let t = if rdtypeset { rdtype } else { RrType::Ptr };
                    let c = if rdclassset { rdclass } else { Class::In };
                    names.push((rev, t, c));
                }
                other => {
                    return Err(format!("Invalid option: -{other}"));
                }
            }
        } else {
            // Positional argument (dig.c main parsing loop).
            if open_type_class {
                // `ixfr=N` is special (serial follows).
                if arg.len() >= 5 && arg[..5].eq_ignore_ascii_case("ixfr=") {
                    if rdtypeset {
                        eprintln!(";; Warning, extra type option");
                    }
                    rdtype = RrType::Ixfr;
                    rdtypeset = true;
                    let serial = parse_serial(&arg[5..])?;
                    opts.ixfr_serial = Some(serial);
                    opts.section_question = true;
                    opts.comments = true;
                    if !opts.tcp_mode_set {
                        opts.transport = Transport::Tcp;
                    }
                } else if let Ok(t) = RrType::from_text(arg) {
                    if rdtypeset {
                        eprintln!(";; Warning, extra type option");
                    }
                    // A bare `ixfr` positional needs a serial number.
                    if t == RrType::Ixfr {
                        eprintln!(";; Warning, ixfr requires a serial number");
                        continue;
                    }
                    rdtype = t;
                    rdtypeset = true;
                    opts.ixfr_serial = None;
                    if t == RrType::Axfr {
                        opts.section_question = true;
                        opts.comments = true;
                        // dighost.c setup_lookup: AXFR forces TCP.
                        if !opts.tcp_mode_set {
                            opts.transport = Transport::Tcp;
                        }
                    } else if t == RrType::Any && !opts.tcp_mode_set {
                        opts.transport = Transport::Tcp;
                    }
                    // A type parsed after a name was created applies to that
                    // lookup (dig.c mutates `lookup` directly).
                    if let Some(last) = names.last_mut() {
                        last.1 = t;
                    }
                } else if let Ok(c) = Class::from_text(arg) {
                    if rdclassset {
                        eprintln!(";; Warning, extra class option");
                    }
                    rdclass = c;
                    rdclassset = true;
                    if let Some(last) = names.last_mut() {
                        last.2 = c;
                    }
                } else {
                    names.push((arg.clone(), rdtype, rdclass));
                }
            } else {
                names.push((arg.clone(), rdtype, rdclass));
            }
        }
        i += 1;
    }
    if names.is_empty() {
        return Err("no query name given".to_string());
    }
    if server.is_empty() {
        server = "127.0.0.1".to_string();
    }

    let lookups: Vec<Lookup> = names
        .iter()
        .map(|(n, t, c)| {
            let qname =
                bind9_rs_core::name::Name::from_text(n, Some(&bind9_rs_core::name::Name::root()))
                    .map_err(|_| format!("invalid name '{n}'"))?;
            Ok(Lookup {
                server: server.clone(),
                names: vec![(qname, *t, *c)],
            })
        })
        .collect::<Result<_, String>>()?;

    opts.lookups = lookups;
    opts.server = server;
    Ok(opts)
}

/// Parse an IXFR serial (`parse_uint(..., MAXSERIAL, "serial number")`;
/// dig.c `fatal("Couldn't parse serial number")` on failure).
fn parse_serial(s: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| "Couldn't parse serial number".to_string())
}

fn next_value(argv: &[String], i: &mut usize, inline: Option<String>) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    argv.get(*i)
        .cloned()
        .ok_or_else(|| "option requires an argument".to_string())
}

/// Compute the in-addr.arpa / ip6.arpa name for -x.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for &b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0f, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// FULLCHECK semantics: `cmd` must be a case-insensitive prefix of `name`.
/// BIND requires the prefix to be strictly shorter than the full name
/// (`_l >= sizeof(A)` → invalid), so an exact full-length match is invalid.
fn matches(cmd: &str, name: &str) -> bool {
    if cmd.len() >= name.len() {
        return false;
    }
    name[..cmd.len()].eq_ignore_ascii_case(cmd)
}

/// Parse one `+option` (without the leading `+`).
fn parse_plus(opts: &mut DigOptions, option: &str) -> Result<(), String> {
    // Split off any =value.
    let (base, value) = match option.split_once('=') {
        Some((b, v)) => (b, Some(v.to_string())),
        None => (option, None),
    };
    let neg = base.strip_prefix("no");
    let cmd = neg.unwrap_or(base);
    let state = neg.is_none();

    // First matching chain wins (BIND's FULLCHECK ordering).
    let handled = match cmd.chars().next() {
        Some('a') => {
            if matches(cmd, "aaflag") || matches(cmd, "aaonly") {
                opts.aaflag = state;
                true
            } else if matches(cmd, "additional") {
                opts.section_additional = state;
                true
            } else if matches(cmd, "adflag") {
                opts.adflag = state;
                true
            } else if matches(cmd, "answer") {
                opts.section_answer = state;
                true
            } else if matches(cmd, "authority") {
                opts.section_authority = state;
                true
            } else if matches(cmd, "all") {
                opts.section_question = state;
                opts.section_authority = state;
                opts.section_answer = state;
                opts.section_additional = state;
                opts.comments = state;
                opts.statistics = state;
                opts.print_cmd = state;
                true
            } else {
                false
            }
        }
        Some('b') => {
            if matches(cmd, "bufsize") {
                let n: u16 = value
                    .as_deref()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("Invalid option: +{option}"))?;
                opts.udp_size = Some(n);
                true
            } else {
                false
            }
        }
        Some('c') => {
            if matches(cmd, "cmd") {
                opts.print_cmd = state;
                true
            } else if matches(cmd, "comments") {
                opts.comments = state;
                true
            } else if matches(cmd, "cdflag") {
                opts.cdflag = state;
                true
            } else if matches(cmd, "class") {
                opts.noclass = !state;
                true
            } else {
                false
            }
        }
        Some('d') => {
            if matches(cmd, "dnssec") {
                opts.dnssec = state;
                if state {
                    opts.edns = true;
                }
                true
            } else {
                false
            }
        }
        Some('e') => {
            if matches(cmd, "edns") {
                opts.edns = state;
                if let Some(v) = value {
                    // +edns=N: version — accepted, version 0 supported.
                    if v != "0" {
                        return Err(format!("EDNS version {v} not supported"));
                    }
                }
                true
            } else {
                false
            }
        }
        Some('i') => {
            if matches(cmd, "ignore") {
                // +ignore: do not retry over TCP on TC.  Stored but the
                // retry path is not yet wired (TC handling courted later).
                true
            } else if matches(cmd, "idnin") {
                opts.idnin = state;
                true
            } else if matches(cmd, "idnout") {
                opts.idnout = state;
                true
            } else {
                false
            }
        }
        Some('k') => {
            if matches(cmd, "keepopen") {
                true
            } else {
                false
            }
        }
        Some('m') => {
            if matches(cmd, "multiline") {
                opts.multiline = state;
                true
            } else {
                false
            }
        }
        Some('n') => {
            if matches(cmd, "nsid") {
                true
            } else {
                false
            }
        }
        Some('q') => {
            if matches(cmd, "qr") {
                opts.print_qr = state;
                true
            } else if matches(cmd, "question") {
                opts.section_question = state;
                true
            } else {
                false
            }
        }
        Some('r') => {
            if matches(cmd, "recurse") {
                opts.recurse = state;
                true
            } else if matches(cmd, "retry") || matches(cmd, "retries") {
                let _: u32 = value
                    .as_deref()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("Invalid option: +{option}"))?;
                true
            } else if matches(cmd, "rrcomments") {
                true
            } else {
                false
            }
        }
        Some('s') => {
            if matches(cmd, "short") {
                opts.short = state;
                true
            } else if matches(cmd, "stats") {
                opts.statistics = state;
                true
            } else if matches(cmd, "search") {
                true
            } else if matches(cmd, "split") {
                true
            } else {
                false
            }
        }
        Some('t') => {
            if matches(cmd, "tcp") {
                opts.transport = if state {
                    Transport::Tcp
                } else {
                    Transport::Udp
                };
                opts.tcp_mode_set = true;
                true
            } else if matches(cmd, "time") {
                let n: u64 = value
                    .as_deref()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("Invalid option: +{option}"))?;
                opts.timeout_secs = n;
                true
            } else if matches(cmd, "tries") {
                let n: u32 = value
                    .as_deref()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("Invalid option: +{option}"))?;
                opts.tries = n;
                true
            } else if matches(cmd, "ttlunits") {
                opts.ttlunits = state;
                true
            } else if matches(cmd, "ttlid") {
                opts.nottl = !state;
                true
            } else if matches(cmd, "tcflag") {
                opts.tcflag = state;
                true
            } else {
                false
            }
        }
        Some('u') => {
            if matches(cmd, "useedns") {
                opts.edns = state;
                true
            } else {
                false
            }
        }
        Some('z') => {
            if matches(cmd, "zflag") {
                opts.zflag = state;
                true
            } else {
                false
            }
        }
        _ => false,
    };

    if !handled {
        return Err(format!("Invalid option: +{option}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_parse() {
        // `example.com A`: one lookup, type A (dig.c open_type_class).
        let o = parse_args(&["example.com".to_string(), "A".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
        assert_eq!(o.lookups[0].names[0].1, RrType::A);

        // `A example.com`: type can precede the name.
        let o = parse_args(&["A".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
        assert_eq!(o.lookups[0].names[0].1, RrType::A);

        // `example.com TXT`: the last type applies to the current lookup.
        let o = parse_args(&["example.com".to_string(), "TXT".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
        assert_eq!(o.lookups[0].names[0].1, RrType::Tx);

        // Two names: two lookups; a trailing type applies to the current
        // (last) lookup only (dig.c mutates `lookup` directly).
        let o = parse_args(&[
            "a.example.com".to_string(),
            "b.example.com".to_string(),
            "MX".to_string(),
        ])
        .unwrap();
        assert_eq!(o.lookups.len(), 2);
        assert_eq!(o.lookups[0].names[0].1, RrType::A);
        assert_eq!(o.lookups[1].names[0].1, RrType::Mx);

        // After -t, positionals are names only.
        let o = parse_args(&[
            "-t".to_string(),
            "NS".to_string(),
            "example.com".to_string(),
        ])
        .unwrap();
        assert_eq!(o.lookups.len(), 1);
        assert_eq!(o.lookups[0].names[0].1, RrType::Ns);

        // Class positional: `example.com MX IN`.
        let o = parse_args(&[
            "example.com".to_string(),
            "MX".to_string(),
            "IN".to_string(),
        ])
        .unwrap();
        assert_eq!(o.lookups.len(), 1);
        assert_eq!(o.lookups[0].names[0].1, RrType::Mx);
        assert_eq!(o.lookups[0].names[0].2, Class::In);

        // AXFR forces TCP (dig.c).
        let o = parse_args(&["example.com".to_string(), "AXFR".to_string()]).unwrap();
        assert_eq!(o.transport, Transport::Tcp);

        // -q sets the name directly.
        let o = parse_args(&["-q".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
    }
}
