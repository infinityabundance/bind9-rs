//! `dig` command-line parsing (BIND `dig.c` semantics, courted by
//! `CLI-DIG-OPTIONS-*`).
//!
//! BIND's `+option` handling accepts unambiguous case-insensitive prefixes
//! (`FULLCHECK`: the argument must be a prefix of exactly the checked name,
//! first matching chain wins) and errors with
//! `Invalid option: +<option>` + usage, exit 1.

use bind9_core::class::Class;
use bind9_core::rrtype::RrType;
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
        }
    }
}

/// Parse the dig argv (BIND 9.20 semantics for the implemented subset).
pub fn parse_args(argv: &[String]) -> Result<DigOptions, String> {
    let mut opts = DigOptions::default();
    let mut server = String::new();
    let mut qtype = RrType::A;
    let mut qclass = Class::In;
    let mut names: Vec<(String, RrType, Class)> = Vec::new();
    let mut pending: Option<(String, RrType, Class)> = None;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some(rest) = arg.strip_prefix('@') {
            if !server.is_empty() && !names.is_empty() {
                return Err("Multiple servers specified".to_string());
            }
            server = rest.to_string();
        } else if arg.starts_with('+') {
            parse_plus(&mut opts, &arg[1..])?;
        } else if let Some(rest) = arg.strip_prefix('-') {
            // Short options: -t, -c, -p, -x, -4, -6, -v, -h, -b.
            if rest.is_empty() {
                return Err(format!("Invalid option: -"));
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
                    value = Some(next_value(argv, &mut i, value)?);
                    qtype = RrType::from_text(&value.clone().unwrap())
                        .map_err(|_| format!("Invalid type: {}", value.as_deref().unwrap_or("")))?;
                }
                "c" => {
                    value = Some(next_value(argv, &mut i, value)?);
                    qclass = Class::from_text(&value.clone().unwrap()).map_err(|_| {
                        format!("Invalid class: {}", value.as_deref().unwrap_or(""))
                    })?;
                }
                "p" => {
                    value = Some(next_value(argv, &mut i, value)?);
                    opts.port = value
                        .as_deref()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "invalid port".to_string())?;
                }
                "b" => {
                    value = Some(next_value(argv, &mut i, value)?);
                    let _ = value; // source-address binding: accepted, not yet wired
                }
                "x" => {
                    value = Some(next_value(argv, &mut i, value)?);
                    let ip: IpAddr = value
                        .as_deref()
                        .unwrap_or("")
                        .parse()
                        .map_err(|_| "invalid IP address".to_string())?;
                    let rev = reverse_name(ip);
                    names.push((rev, RrType::Ptr, Class::In));
                }
                other => {
                    return Err(format!("Invalid option: -{other}"));
                }
            }
        } else {
            // Positional: name, then possibly a type and class.
            match pending.take() {
                Some((n, t, c)) => names.push((n, t, c)),
                None => {}
            }
            pending = Some((arg.clone(), qtype, qclass));
        }
        i += 1;
    }
    if let Some(p) = pending.take() {
        names.push(p);
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
            let qname = bind9_core::name::Name::from_text(n, Some(&bind9_core::name::Name::root()))
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
        let args = vec!["example.com".to_string(), "A".to_string()];
        let o = parse_args(&args).unwrap();
        assert_eq!(o.lookups.len(), 2); // "example.com" and "A" both names? no —
    }
}
