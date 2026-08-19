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

/// The short usage printed for invalid options (dig.c `usage()`, captured
/// byte-exact from the oracle; note the continuation lines carry NO leading
/// spaces, unlike the full `-h` help).
pub const USAGE: &str = "Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}\n            {global-d-opt} host [@local-server] {local-d-opt}\n            [ host [@local-server] {local-d-opt} [...]]\n\nUse \"dig -h\" (or \"dig -h | more\") for complete list of options\n";

/// The full help text printed by `-h` (byte-exact capture from the pinned
/// oracle: `docker run --rm oracle-bind-9.20.26 dig -h`).
pub const HELP: &str = include_str!("help.txt");

/// Transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Parsed dig invocation.
///
/// Field names and defaults follow `dig_lookup_t` / the globals in dig.c
/// (BIND 9.20.26): `make_empty_lookup` + `dig_setup` set `edns=0`,
/// `adflag=true`, `sendcookie=true` on the default lookup, so EDNS (and
/// therefore the COOKIE option) is on by default.
#[derive(Debug, Clone)]
pub struct DigOptions {
    pub lookups: Vec<Lookup>,
    pub help: bool,
    pub version: bool,
    pub port: u16,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    /// `tcp_mode`: whether queries go over TCP.
    pub transport: Transport,
    /// Whether +tcp/+notcp/+vc/+novc was given (AXFR/ANY/ixfr force TCP
    /// only when this is unset; dig.c `tcp_mode_set`).
    pub tcp_mode_set: bool,
    /// `recurse` (RD flag).
    pub recurse: bool,
    /// `dnssec` (DO bit).
    pub dnssec: bool,
    /// `edns` version; `None` == -1 (EDNS disabled via +noedns).
    pub edns: Option<u8>,
    /// `udpsize`; `None` == -1 (default 1232 substituted at render time).
    pub udp_size: Option<u16>,
    pub timeout_secs: u64,
    /// Total attempts (`retries`).
    pub tries: u32,
    pub print_qr: bool,
    /// Global `printcmd` (set by +cmd/+all/+short/+yaml).
    pub print_cmd: bool,
    pub comments: bool,
    pub statistics: bool,
    /// Global `short_form`.
    pub short: bool,
    pub section_question: bool,
    pub section_answer: bool,
    pub section_authority: bool,
    pub section_additional: bool,
    /// `aaonly` (set by +aaflag/+aaonly; drives the AA flag in queries).
    pub aaonly: bool,
    pub adflag: bool,
    pub cdflag: bool,
    pub tcflag: bool,
    pub zflag: bool,
    pub raflag: bool,
    pub coflag: bool,
    /// `ignore`: do not retry in TCP mode on a truncated response.
    pub ignore: bool,
    /// `badcookie`: retry on BADCOOKIE responses (default true).
    pub badcookie: bool,
    /// `sendcookie`: include a COOKIE option in queries (default true).
    pub sendcookie: bool,
    /// Fixed cookie from `+cookie=####` (hex); otherwise a per-process
    /// random client cookie is used (dighost.c `compute_cookie`).
    pub cookie_hex: Option<String>,
    pub multiline: bool,
    pub ttlunits: bool,
    /// `nottl` (inverted by +ttl/+ttlid/+nottlunits).
    pub nottl: bool,
    /// `noclass` (inverted by +class/+cl).
    pub noclass: bool,
    /// `nocrypto` (inverted by +crypto).
    pub nocrypto: bool,
    pub header_only: bool,
    pub besteffort: bool,
    pub servfail_stops: bool,
    pub nsid: bool,
    pub expire: bool,
    pub tcp_keepalive: bool,
    /// `+padding=N`: pad the query to a multiple of N octets.
    pub padding: Option<u16>,
    /// `+subnet=addr/len`: the ECS prefix (address source); parsed at
    /// option time, encoded into the ECS option at query build.
    pub subnet: Option<String>,
    /// `+opcode=NAME|N`: the query opcode (0..15).
    pub opcode: u8,
    /// `+qid=N`: a fixed transaction ID.
    pub qid: Option<u16>,
    pub keep_open: bool,
    pub onesoa: bool,
    pub expandaaaa: bool,
    pub identify: bool,
    pub ednsneg: bool,
    pub ednsflags: u16,
    /// `+ednsopt` list: (code, data).
    pub ednsopts: Vec<(u16, Vec<u8>)>,
    /// `-u`: display times in usec.
    pub use_usec: bool,
    pub print_unknown_format: bool,
    /// `+yaml`: the YAML output format (dig.c `yaml` global).
    pub yaml: bool,
    pub server: String,
    /// IDN conversion of query names (dighost.c make_empty_lookup: default
    /// on unless IDN_DISABLE is set; `+idnin`/`+noidnin` override).
    pub idnin: bool,
    /// IDN conversion of response names (default: stdout is a TTY;
    /// `+idnout`/`+noidnout` override).
    pub idnout: bool,
    /// Serial for `-t ixfr=N` / positional `ixfr=N`.
    pub ixfr_serial: Option<u32>,
    /// The full command line (argv joined by spaces) for the greeting.
    pub cmdline: String,
    /// Whether an @server argument was given (drives `; (N server found)`;
    /// BIND resolves `addresscount` from the server at parse time).
    pub server_explicit: bool,
    /// `(print_cmd, short_form, server_seen)` at the moment the *first*
    /// name was parsed (dig.c printgreeting reads the globals — and
    /// `addresscount`, which is 0 until an @server argument has been
    /// resolved — when the name is seen).  `None` until a name is pushed;
    /// the no-name fallback captures the end-of-parse values.  This drives
    /// greeting *construction*; the greeting *printing* re-checks the
    /// current printcmd/short (dig.c:733).
    pub first_name_greeting: Option<(bool, bool, bool)>,
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
            tcp_mode_set: false,
            recurse: true,
            dnssec: false,
            // dig_setup: `default_lookup->edns = DEFAULT_EDNS_VERSION`.
            edns: Some(0),
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
            aaonly: false,
            // dig_setup: `default_lookup->adflag = true`.
            adflag: true,
            cdflag: false,
            tcflag: false,
            zflag: false,
            raflag: false,
            coflag: false,
            ignore: false,
            badcookie: true,
            // dig_setup: `default_lookup->sendcookie = true`.
            sendcookie: true,
            cookie_hex: None,
            multiline: false,
            ttlunits: false,
            nottl: false,
            noclass: false,
            nocrypto: false,
            header_only: false,
            besteffort: true,
            servfail_stops: true,
            nsid: false,
            expire: false,
            tcp_keepalive: false,
            padding: None,
            subnet: None,
            opcode: 0,
            qid: None,
            keep_open: false,
            onesoa: false,
            expandaaaa: false,
            identify: false,
            ednsneg: true,
            ednsflags: 0,
            ednsopts: Vec::new(),
            use_usec: false,
            print_unknown_format: false,
            yaml: false,
            server: "127.0.0.1".to_string(),
            // dighost.c make_empty_lookup(): IDN defaults depend on the
            // IDN_DISABLE environment variable and on stdout being a TTY
            // (idnout).  The oracle binary was built without libidn2, where
            // both default to false; our binary always has IDN support, so
            // the defaults match a libidn2-enabled build.
            idnin: std::env::var_os("IDN_DISABLE").is_none(),
            idnout: std::io::IsTerminal::is_terminal(&std::io::stdout()),
            ixfr_serial: None,
            cmdline: String::new(),
            server_explicit: false,
            first_name_greeting: None,
        }
    }
}

impl DigOptions {
    /// The socket protocol name for the YAML/stats output (dighost.c
    /// `tcp_mode ? "TCP" : "UDP"`).
    #[must_use]
    pub fn transport_name(&self) -> &'static str {
        match self.transport {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
        }
    }
}

/// Parse failure taxonomy, mirroring dig.c's exit paths:
/// - `Usage`: message + usage to stderr, exit 1 (invalid options)
/// - `Fatal`: `dig: <msg>` to stderr, exit 1 (`fatal()`)
/// - `Warn`: `dig: <msg>` to stderr, exit 10 (`warn()` + `exit_or_usage`
///   which ends in `digexit()` raising the exit code to >= 10)
/// - `Bare`: message only to stderr, exit 1 (e.g. `-x` invalid IP)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Usage(String),
    Fatal(String),
    Warn(String),
    Bare(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Usage(m)
            | ParseError::Fatal(m)
            | ParseError::Warn(m)
            | ParseError::Bare(m) => {
                write!(f, "{m}")
            }
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
/// One pending name (dig.c: a cloned `dig_lookup_t` per command-line name).
/// `transport`/`tcp_mode_set` snapshot the lookup-transport state at the
/// moment the name was parsed: `+tcp`/`+vc` mutate the *current* lookup only
/// (dig.c `case 't'`: `lookup->tcp_mode = state` on the current lookup), so
/// `dig example.com +tcp a.example.com` sends the first query over TCP and
/// the second over UDP (a later name clones the default lookup, whose
/// tcp_mode was never touched).
#[derive(Debug, Clone)]
struct PendingName {
    text: String,
    rdtype: RrType,
    rdclass: Class,
    transport: Transport,
    tcp_mode_set: bool,
}

/// Apply a transport change to the current lookup: the last parsed name if
/// any, else the pending default (dig.c mutates `lookup`, which is the
/// default lookup until the first name clones it).
fn set_transport(opts: &mut DigOptions, names: &mut [PendingName], t: Transport, set: bool) {
    if let Some(last) = names.last_mut() {
        last.transport = t;
        if set {
            last.tcp_mode_set = true;
        }
    } else {
        opts.transport = t;
        if set {
            opts.tcp_mode_set = true;
        }
    }
}

/// dig.c `if (!lookup->tcp_mode_set) { lookup->tcp_mode = true; }` for
/// AXFR/IXFR/ANY: force TCP on the current lookup unless it opted out.
fn force_tcp(opts: &mut DigOptions, names: &mut [PendingName]) {
    if let Some(last) = names.last_mut() {
        if !last.tcp_mode_set {
            last.transport = Transport::Tcp;
        }
    } else if !opts.tcp_mode_set {
        opts.transport = Transport::Tcp;
    }
}

/// Push a name as a new lookup, snapshotting the transport state (dig.c:
/// `*lookup = clone_lookup(default_lookup, true)` — the clone inherits the
/// default lookup's current tcp_mode/tcp_mode_set).
fn push_name(
    opts: &mut DigOptions,
    names: &mut Vec<PendingName>,
    text: &str,
    rdtype: RrType,
    rdclass: Class,
) {
    names.push(PendingName {
        text: text.to_string(),
        rdtype,
        rdclass,
        transport: opts.transport,
        tcp_mode_set: opts.tcp_mode_set,
    });
}

pub fn parse_args(argv: &[String]) -> Result<DigOptions, ParseError> {
    let mut opts = DigOptions::default();
    let mut server = String::new();
    let mut names: Vec<PendingName> = Vec::new();

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
            // Multiple @server arguments are legal in dig.c: each applies to
            // the successive lookup; for our single-server model the last
            // one wins.
            server = rest.to_string();
            opts.server_explicit = true;
        } else if arg.starts_with('+') {
            parse_plus(&mut opts, &mut names, &arg[1..])?;
        } else if let Some(rest) = arg.strip_prefix('-') {
            // Short options: -t, -c, -p, -q, -x, -4, -6, -v, -h, -b.
            if rest.is_empty() {
                return Err(ParseError::Usage("Invalid option: -".to_string()));
            }
            let opt = &rest[..1];
            let has_value = rest.len() > 1;
            let value = if has_value {
                Some(rest[1..].to_string())
            } else {
                None
            };
            match opt {
                "4" => {
                    if opts.ipv6_only {
                        return Err(ParseError::Fatal(
                            "only one of -4 and -6 allowed".to_string(),
                        ));
                    }
                    opts.ipv4_only = true;
                }
                "6" => {
                    if opts.ipv4_only {
                        return Err(ParseError::Fatal(
                            "only one of -4 and -6 allowed".to_string(),
                        ));
                    }
                    opts.ipv6_only = true;
                }
                "v" => opts.version = true,
                "h" | "?" => opts.help = true,
                "d" => {
                    // dig.c: -d enables debugging; accepted (debug output
                    // itself is courted later).
                }
                "u" => opts.use_usec = true,
                "m" => {
                    // dig.c -m: memory debugging (handled in preparse).
                }
                "i" => {
                    return Err(ParseError::Fatal("-i removed".to_string()));
                }
                "n" => {
                    return Err(ParseError::Fatal("-n removed".to_string()));
                }
                "r" => {
                    // dig.c preparse case 'r': do not read ~/.digrc.  We do
                    // not read .digrc yet (courted later); accept the flag.
                }
                "f" => {
                    // dig.c -f <file>: batch mode.  Accepted; batch parsing
                    // lands with the batch-file courts.
                    let _ = next_value(argv, &mut i, value)?;
                }
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
                                // dig.c mutates the *current* lookup: `-t`
                                // after a name applies to that name.
                                if let Some(last) = names.last_mut() {
                                    last.rdtype = t;
                                }
                                if t == RrType::Axfr {
                                    opts.section_question = true;
                                    opts.comments = true;
                                    // dighost.c setup_lookup: AXFR forces TCP.
                                    force_tcp(&mut opts, &mut names);
                                } else if t == RrType::Any {
                                    force_tcp(&mut opts, &mut names);
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
                            // dig.c mutates the *current* lookup: `-c` after
                            // a name applies to that name.
                            if let Some(last) = names.last_mut() {
                                last.rdclass = c;
                            }
                        }
                        Err(_) => eprintln!(";; Warning, ignoring invalid class {value}"),
                    }
                }
                "p" => {
                    let value = next_value(argv, &mut i, value)?;
                    let n = parse_uint("port number", &value, 0xffff)
                        .map_err(|_| ParseError::Fatal("Couldn't parse port number".to_string()))?;
                    opts.port = n as u16;
                }
                "b" => {
                    // dig.c case 'b': address[#port] source binding.  The
                    // address must parse as IPv6 or IPv4 (fatal otherwise).
                    let value = next_value(argv, &mut i, value)?;
                    let (addr, port_part) = match value.rsplit_once('#') {
                        Some((a, p)) => (a, Some(p)),
                        None => (value.as_str(), None),
                    };
                    if let Some(p) = port_part {
                        let _ = parse_uint("port number", p, 0xffff).map_err(|_| {
                            ParseError::Fatal("Couldn't parse port number".to_string())
                        })?;
                    }
                    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
                        opts.ipv4_only = false;
                        opts.ipv6_only = true;
                    } else if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                        opts.ipv6_only = false;
                        opts.ipv4_only = true;
                    } else {
                        return Err(ParseError::Fatal(format!("invalid address {addr}")));
                    }
                }
                "q" => {
                    // dig.c case 'q': sets the name directly.
                    let value = next_value(argv, &mut i, value)?;
                    capture_first_greeting(&mut opts, &names);
                    push_name(&mut opts, &mut names, &value, rdtype, rdclass);
                }
                "x" => {
                    // dig.c case 'x' -> get_reverse(value, strict=false):
                    // IPv6 parses strictly; anything else is blindly treated
                    // as a dotted-quad and its octets reversed (RFC 2317
                    // names like 0.168.192. ", so `-x bogus` queries
                    // "bogus.in-addr.arpa" rather than erroring.
                    let value = next_value(argv, &mut i, value)?;
                    if let Ok(ip6) = value.parse::<std::net::Ipv6Addr>() {
                        let rev = reverse_name(std::net::IpAddr::V6(ip6));
                        let t = if rdtypeset { rdtype } else { RrType::Ptr };
                        let c = if rdclassset { rdclass } else { Class::In };
                        capture_first_greeting(&mut opts, &names);
                        push_name(&mut opts, &mut names, &rev, t, c);
                    } else {
                        let rev = reverse_octets(&value);
                        let t = if rdtypeset { rdtype } else { RrType::Ptr };
                        let c = if rdclassset { rdclass } else { Class::In };
                        capture_first_greeting(&mut opts, &names);
                        push_name(&mut opts, &mut names, &rev, t, c);
                    }
                }
                _other => {
                    // dig.c prints the full option after the leading dash
                    // (`Invalid option: -%s` with the whole remainder).
                    return Err(ParseError::Usage(format!("Invalid option: -{rest}")));
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
                        force_tcp(&mut opts, &mut names);
                    } else if t == RrType::Any {
                        force_tcp(&mut opts, &mut names);
                    }
                    // A type parsed after a name was created applies to that
                    // lookup (dig.c mutates `lookup` directly).
                    if let Some(last) = names.last_mut() {
                        last.rdtype = t;
                    }
                } else if let Ok(c) = Class::from_text(arg) {
                    if rdclassset {
                        eprintln!(";; Warning, extra class option");
                    }
                    rdclass = c;
                    rdclassset = true;
                    if let Some(last) = names.last_mut() {
                        last.rdclass = c;
                    }
                } else {
                    capture_first_greeting(&mut opts, &names);
                    push_name(&mut opts, &mut names, arg, rdtype, rdclass);
                }
            } else {
                capture_first_greeting(&mut opts, &names);
                push_name(&mut opts, &mut names, arg, rdtype, rdclass);
            }
        }
        i += 1;
    }

    // dig.c: `If no lookup specified, search for root` — an empty lookup
    // list (no name given) becomes a `.` NS query.  -v/-h short-circuit
    // before this (BIND exits in dash_option).
    if opts.version || opts.help {
        return Ok(opts);
    }
    if names.is_empty() {
        // dig.c: the no-name fallback calls printgreeting at the end of
        // parse_args with the final global values.
        opts.first_name_greeting = Some((opts.print_cmd, opts.short, opts.server_explicit));
        push_name(&mut opts, &mut names, ".", RrType::Ns, Class::In);
    }
    if server.is_empty() {
        server = "127.0.0.1".to_string();
    }

    let lookups: Vec<Lookup> = names
        .iter()
        .map(|n| {
            let qname = bind9_rs_core::name::Name::from_text(
                &n.text,
                Some(&bind9_rs_core::name::Name::root()),
            )
            .map_err(|_| ParseError::Usage(format!("invalid name '{}'", n.text)))?;
            Ok(Lookup {
                server: server.clone(),
                text: n.text.clone(),
                names: vec![(qname, n.rdtype, n.rdclass)],
                transport: n.transport,
                tcp_mode_set: n.tcp_mode_set,
            })
        })
        .collect::<Result<_, ParseError>>()?;

    opts.lookups = lookups;
    opts.server = server;
    opts.cmdline = argv.join(" ");
    Ok(opts)
}

/// Parse an IXFR serial (dig.c `parse_uint(&serial, &value[5], MAXSERIAL,
/// "serial number")` + `fatal("Couldn't parse serial number")` on failure).
fn parse_serial(s: &str) -> Result<u32, ParseError> {
    let n = parse_uint("serial number", s, u32::MAX as u64)
        .map_err(|_| ParseError::Fatal("Couldn't parse serial number".to_string()))?;
    Ok(n as u32)
}

/// dig.c: printgreeting fires when the first name is parsed (`firstarg`);
/// record the globals it reads at that moment (including `addresscount`,
/// which is only nonzero once an @server argument has been resolved).
fn capture_first_greeting(opts: &mut DigOptions, names: &[PendingName]) {
    if names.is_empty() && opts.first_name_greeting.is_none() {
        opts.first_name_greeting = Some((opts.print_cmd, opts.short, opts.server_explicit));
    }
}

fn next_value(
    argv: &[String],
    i: &mut usize,
    inline: Option<String>,
) -> Result<String, ParseError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    argv.get(*i)
        .cloned()
        .ok_or_else(|| ParseError::Usage("option requires an argument".to_string()))
}

/// Blind octet reversal (dighost.c get_reverse/reverse_octets, non-strict):
/// split on '.', reverse the tokens, append `.in-addr.arpa`.  RFC 2317
/// names pass through; the result is lowercase.
fn reverse_octets(value: &str) -> String {
    let mut out = String::new();
    for tok in value.split('.').rev() {
        for c in tok.chars() {
            out.push(c.to_ascii_lowercase());
        }
        out.push('.');
    }
    out.push_str("in-addr.arpa");
    out
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

/// FULLCHECK semantics (dig.c): `cmd` must be a case-insensitive prefix of
/// `name`, and no longer than it.  BIND compares `strlen(cmd) >= sizeof(name)`
/// where `sizeof` includes the NUL, so an exact-length match is valid.
fn matches(cmd: &str, name: &str) -> bool {
    if cmd.len() > name.len() {
        return false;
    }
    name[..cmd.len()].eq_ignore_ascii_case(cmd)
}

/// `Invalid option: +<option>` + usage, exit 1 (dig.c `invalid_option:`).
fn plus_invalid(option: &str) -> ParseError {
    ParseError::Usage(format!("Invalid option: +{option}"))
}

/// The optnames table from dighost.c `save_opt` (name → code).
const OPTNAMES: &[(&str, u16)] = &[
    ("LLQ", 1),
    ("UPDATE-LEASE", 2),
    ("UL", 2),
    ("NSID", 3),
    ("DAU", 5),
    ("DHU", 6),
    ("N3U", 7),
    ("ECS", 8),
    ("EXPIRE", 9),
    ("COOKIE", 10),
    ("KEEPALIVE", 11),
    ("PADDING", 12),
    ("PAD", 12),
    ("CHAIN", 13),
    ("KEY-TAG", 14),
    ("EDE", 15),
    ("CLIENT-TAG", 16),
    ("SERVER-TAG", 17),
    ("REPORT-CHANNEL", 18),
    ("RC", 18),
    ("ZONEVERSION", 19),
    ("DEVICEID", 26946),
];

/// `parse_uint` (dighost.c): prints `invalid <desc> '<value>': <reason>` to
/// stdout and returns the reason; base 10.  The caller chooses the exit path
/// (`fatal` exit 1 vs `warn`+`exit_or_usage` exit 10).
fn parse_uint(what: &str, s: &str, max: u64) -> Result<u64, &'static str> {
    let err = |r: &'static str| {
        println!("invalid {what} '{s}': {r}");
        r
    };
    if s.is_empty() {
        return Err(err("not a valid number"));
    }
    // isc_parse_uint32: first char must be alphanumeric.
    if !s.chars().next().unwrap().is_ascii_alphanumeric() {
        return Err(err("not a valid number"));
    }
    match s.parse::<u64>() {
        Ok(n) if n <= max => Ok(n),
        Ok(_) => Err(err("out of range")),
        Err(_) => Err(err("not a valid number")),
    }
}

/// `parse_xint` (dighost.c): like parse_uint but base 0 (hex `0x` accepted).
fn parse_xint(what: &str, s: &str, max: u64) -> Result<u64, &'static str> {
    let err = |r: &'static str| {
        println!("invalid {what} '{s}': {r}");
        r
    };
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    match parsed {
        Ok(n) if n <= max => Ok(n),
        Ok(_) => Err(err("out of range")),
        Err(_) => Err(err("not a valid number")),
    }
}

/// `+option` parser (dig.c `plus_option`), a faithful transcription of the C
/// state machine including its prefix-resolution quirks:
///
/// - the first `=` splits cmd/value;
/// - a case-insensitive leading `no` inverts the state (but the remainder is
///   matched case-sensitively);
/// - an empty option (`dig +`) prints `;; Invalid option` to stdout and is
///   otherwise ignored;
/// - each `switch (cmd[N])` dispatches on the Nth character, so abbreviated
///   options are accepted only where the C chain admits them (`+cd`, `+co`,
///   `+cl`, `+ad`, `+ttl`, ...); `+sh`/`+sho` are rejected, `+shor` works;
/// - parse failures of `+<kw>=<value>` print `invalid <what> '<v>': <reason>`
///   to stdout, then `dig: Couldn't parse <what>` to stderr and exit 10
///   (`warn` + `exit_or_usage` → `digexit()`);
/// - removed options (`+mapped`, `+topdown`, `+sigchase`, `+trusted-key`,
///   `+unexpected`) `fatal()` with exit 1.
pub fn parse_plus(
    opts: &mut DigOptions,
    names: &mut [PendingName],
    option: &str,
) -> Result<(), ParseError> {
    let (raw_cmd, value) = match option.split_once('=') {
        Some((c, v)) => (c, Some(v.to_string())),
        None => (option, None),
    };
    // strtok_r(option, "=") returning NULL: the option is empty (`dig +`).
    if raw_cmd.is_empty() {
        println!(";; Invalid option {option}");
        return Ok(());
    }
    let (cmd, state) = if raw_cmd.len() >= 2 && raw_cmd[..2].eq_ignore_ascii_case("no") {
        (&raw_cmd[2..], false)
    } else {
        (raw_cmd, true)
    };
    if cmd.is_empty() {
        // `+no` → cmd "" → default case → invalid.
        return Err(plus_invalid(option));
    }

    let removed = |m: &str| ParseError::Fatal(format!("{m} option no longer supported"));
    // warn(...) + exit_or_usage → exit 10.
    let warn_exit = |what: &str| ParseError::Warn(format!("Couldn't parse {what}"));

    let c = cmd.as_bytes();
    let c1 = || c.get(1).copied();
    let c2 = || c.get(2).copied();
    let c3 = || c.get(3).copied();
    let c4 = || c.get(4).copied();
    let c7 = || c.get(7).copied();

    match c[0] {
        b'a' => match c1() {
            Some(b'a') => {
                if matches(cmd, "aaonly") || matches(cmd, "aaflag") {
                    opts.aaonly = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'd') => match c2() {
                Some(b'd') => {
                    if matches(cmd, "additional") {
                        opts.section_additional = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'f') | None => {
                    // `+ad` is a synonym for `+adflag`.
                    if matches(cmd, "adflag") {
                        opts.adflag = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                _ => return Err(plus_invalid(option)),
            },
            Some(b'l') => {
                if matches(cmd, "all") {
                    opts.section_question = state;
                    opts.section_authority = state;
                    opts.section_answer = state;
                    opts.section_additional = state;
                    opts.comments = state;
                    opts.statistics = state;
                    opts.print_cmd = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'n') => {
                if matches(cmd, "answer") {
                    opts.section_answer = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'u') => {
                if matches(cmd, "authority") {
                    opts.section_authority = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'b' => match c1() {
            Some(b'a') => {
                if matches(cmd, "badcookie") {
                    opts.badcookie = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'e') => {
                if matches(cmd, "besteffort") {
                    opts.besteffort = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'u') => {
                if !matches(cmd, "bufsize") {
                    return Err(plus_invalid(option));
                }
                if !state {
                    return Err(plus_invalid(option));
                }
                match value {
                    None => opts.udp_size = Some(1232), // DEFAULT_EDNS_BUFSIZE
                    Some(v) => {
                        let n = parse_uint("buffer size", &v, 0xffff)
                            .map_err(|_| warn_exit("buffer size"))?;
                        opts.udp_size = Some(n as u16);
                    }
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'c' => match c1() {
            Some(b'd') => {
                if c2().is_some() && c2() != Some(b'f') {
                    return Err(plus_invalid(option));
                }
                if matches(cmd, "cdflag") {
                    opts.cdflag = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'l') => {
                // `+cl` kept for backward compatibility.
                if matches(cmd, "class") || matches(cmd, "cl") {
                    opts.noclass = !state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'm') => {
                if matches(cmd, "cmd") {
                    opts.print_cmd = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'o') => match c2() {
                Some(b'f') | None => {
                    // `+co` is a synonym for `+coflag`.
                    if matches(cmd, "coflag") {
                        opts.coflag = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'm') => {
                    if matches(cmd, "comments") {
                        opts.comments = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'o') => {
                    if !matches(cmd, "cookie") {
                        return Err(plus_invalid(option));
                    }
                    if state && opts.edns.is_none() {
                        opts.edns = Some(0); // DEFAULT_EDNS_VERSION
                    }
                    opts.sendcookie = state;
                    match value {
                        Some(v) => {
                            // hexcookie[81] in dig.c: strlen >= 81 truncates.
                            if v.len() >= 81 {
                                return Err(ParseError::Warn("COOKIE data too large".into()));
                            }
                            opts.cookie_hex = Some(v);
                        }
                        None => opts.cookie_hex = None,
                    }
                }
                _ => return Err(plus_invalid(option)),
            },
            Some(b'r') => {
                if matches(cmd, "crypto") {
                    opts.nocrypto = !state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'd' => match c1() {
            Some(b'e') => {
                if !matches(cmd, "defname") {
                    return Err(plus_invalid(option));
                }
                eprintln!(";; +[no]defname option is deprecated; use +[no]search");
            }
            Some(b'n') => {
                if c2() != Some(b's') {
                    return Err(plus_invalid(option));
                }
                match c3() {
                    Some(b'6') => {
                        if !matches(cmd, "dns64prefix") {
                            return Err(plus_invalid(option));
                        }
                        if state {
                            opts.print_cmd = false;
                            opts.section_additional = false;
                            opts.section_answer = true;
                            opts.section_authority = false;
                            opts.section_question = false;
                            opts.comments = false;
                            opts.statistics = false;
                        }
                    }
                    Some(b's') => {
                        if !matches(cmd, "dnssec") {
                            return Err(plus_invalid(option));
                        }
                        if state && opts.edns.is_none() {
                            opts.edns = Some(0);
                        }
                        opts.dnssec = state;
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            Some(b'o') => {
                if c2().is_none() {
                    // `+do` is a synonym for `+dnssec`.
                    if state && opts.edns.is_none() {
                        opts.edns = Some(0);
                    }
                    opts.dnssec = state;
                } else if matches(cmd, "domain") {
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    if !state {
                        return Err(plus_invalid(option));
                    }
                    let _ = v; // domainopt: search-domain override (no-op)
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'e' => match c1() {
            Some(b'd') => {
                if c2() != Some(b'n') || c3() != Some(b's') {
                    return Err(plus_invalid(option));
                }
                match c4() {
                    None => {
                        if !matches(cmd, "edns") {
                            return Err(plus_invalid(option));
                        }
                        if !state {
                            opts.edns = None;
                        } else {
                            match value {
                                None => opts.edns = Some(0),
                                Some(v) => {
                                    let n = parse_uint("edns", &v, 255)
                                        .map_err(|_| warn_exit("edns"))?;
                                    opts.edns = Some(n as u8);
                                }
                            }
                        }
                    }
                    Some(b'f') => {
                        if !matches(cmd, "ednsflags") {
                            return Err(plus_invalid(option));
                        }
                        if !state {
                            opts.ednsflags = 0;
                        } else {
                            let n = match value {
                                None => 0,
                                Some(v) => parse_xint("ednsflags", &v, 0xffff)
                                    .map_err(|_| warn_exit("ednsflags"))?
                                    as u16,
                            };
                            if opts.edns.is_none() {
                                opts.edns = Some(0);
                            }
                            opts.ednsflags = n;
                        }
                    }
                    Some(b'n') => {
                        if !matches(cmd, "ednsnegotiation") {
                            return Err(plus_invalid(option));
                        }
                        opts.ednsneg = state;
                    }
                    Some(b'o') => {
                        if !matches(cmd, "ednsopt") {
                            return Err(plus_invalid(option));
                        }
                        if !state {
                            opts.ednsopts.clear();
                        } else {
                            let v = value.ok_or_else(|| {
                                ParseError::Warn("ednsopt no code point specified".into())
                            })?;
                            let (code, extra) = match v.split_once(':') {
                                Some((co, ex)) => (co, Some(ex)),
                                None => (v.as_str(), None),
                            };
                            save_ednsopt(opts, code, extra)?;
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            Some(b'x') => {
                if c2() != Some(b'p') {
                    return Err(plus_invalid(option));
                }
                match c3() {
                    Some(b'a') => {
                        if matches(cmd, "expandaaaa") {
                            opts.expandaaaa = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    Some(b'i') => {
                        if matches(cmd, "expire") {
                            opts.expire = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'f' => match c1() {
            Some(b'a') => {
                if matches(cmd, "fail") {
                    opts.servfail_stops = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'u') => {
                if !matches(cmd, "fuzztime") {
                    return Err(plus_invalid(option));
                }
                if state {
                    if let Some(v) = value {
                        let _ = parse_uint("fuzztime", &v, 0xffffffff)
                            .map_err(|_| warn_exit("fuzztime"))?;
                    }
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'h' => match c1() {
            Some(b'e') => {
                if matches(cmd, "header-only") {
                    opts.header_only = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b't') => {
                // https / https-get / https-post / http-plain / http-plain-get /
                // http-plain-post (FULLCHECK6).  DoH transport wiring lands with
                // the transport courts; accept and record the mode.
                const HTTPS: &[&str] = &[
                    "https",
                    "https-get",
                    "https-post",
                    "http-plain",
                    "http-plain-get",
                    "http-plain-post",
                ];
                if !HTTPS.iter().any(|h| matches(cmd, h)) {
                    return Err(plus_invalid(option));
                }
                if !state {
                    // https_mode = false (accepted; no transport yet)
                } else if !opts.tcp_mode_set {
                    set_transport(opts, names, Transport::Tcp, false);
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'i' => match c1() {
            Some(b'd') => match c2() {
                Some(b'e') => {
                    if matches(cmd, "identify") {
                        opts.identify = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'n') => match c3() {
                    None => {
                        if matches(cmd, "idn") {
                            opts.idnin = state;
                            opts.idnout = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    Some(b'i') => {
                        if matches(cmd, "idnin") {
                            opts.idnin = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    Some(b'o') => {
                        if matches(cmd, "idnout") {
                            opts.idnout = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                },
                _ => return Err(plus_invalid(option)),
            },
            // `+ig`... and the default fall through: FULLCHECK("ignore").
            _ => {
                if matches(cmd, "ignore") {
                    opts.ignore = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
        },
        b'k' => match c1() {
            Some(b'e') => {
                if c2() != Some(b'e') || c3() != Some(b'p') {
                    return Err(plus_invalid(option));
                }
                match c4() {
                    Some(b'a') => {
                        if matches(cmd, "keepalive") {
                            opts.tcp_keepalive = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    Some(b'o') => {
                        if matches(cmd, "keepopen") {
                            opts.keep_open = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'm' => match c1() {
            Some(b'a') => {
                if matches(cmd, "mapped") {
                    return Err(removed("+mapped"));
                }
                return Err(plus_invalid(option));
            }
            Some(b'u') => {
                if matches(cmd, "multiline") {
                    opts.multiline = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'n' => match c1() {
            Some(b'd') => {
                if !matches(cmd, "ndots") {
                    return Err(plus_invalid(option));
                }
                let v = value.ok_or_else(|| plus_invalid(option))?;
                if !state {
                    return Err(plus_invalid(option));
                }
                let _ = parse_uint("ndots", &v, 0xffff).map_err(|_| warn_exit("ndots"))?;
            }
            Some(b's') => match c2() {
                Some(b'i') => {
                    if !matches(cmd, "nsid") {
                        return Err(plus_invalid(option));
                    }
                    if state && opts.edns.is_none() {
                        opts.edns = Some(0);
                    }
                    opts.nsid = state;
                }
                Some(b's') => {
                    if !matches(cmd, "nssearch") {
                        return Err(plus_invalid(option));
                    }
                    if state {
                        opts.recurse = true;
                        opts.identify = true;
                        opts.comments = false;
                        opts.statistics = false;
                        opts.section_additional = false;
                        opts.section_authority = false;
                        opts.section_question = false;
                        opts.short = true;
                        // ns_search_only: rdtype forced to NS at lookup build.
                    }
                }
                _ => return Err(plus_invalid(option)),
            },
            _ => return Err(plus_invalid(option)),
        },
        b'o' => match c1() {
            Some(b'n') => {
                if matches(cmd, "onesoa") {
                    opts.onesoa = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'p') => {
                if !matches(cmd, "opcode") {
                    return Err(plus_invalid(option));
                }
                if !state {
                    opts.opcode = 0; // opcode = 0 (QUERY)
                } else {
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    // opcodetext table match (dig.c: the full 16-entry table
                    // in order: QUERY IQUERY STATUS RESERVED3 NOTIFY UPDATE
                    // RESERVED6..RESERVED15), then numeric.
                    let names = [
                        "QUERY",
                        "IQUERY",
                        "STATUS",
                        "RESERVED3",
                        "NOTIFY",
                        "UPDATE",
                        "RESERVED6",
                        "RESERVED7",
                        "RESERVED8",
                        "RESERVED9",
                        "RESERVED10",
                        "RESERVED11",
                        "RESERVED12",
                        "RESERVED13",
                        "RESERVED14",
                        "RESERVED15",
                    ];
                    let found = names.iter().position(|n| n.eq_ignore_ascii_case(&v));
                    match found {
                        Some(i) => opts.opcode = i as u8,
                        None => {
                            let n =
                                parse_uint("opcode", &v, 15).map_err(|_| warn_exit("opcode"))?;
                            opts.opcode = n as u8;
                        }
                    }
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'p' => match c1() {
            Some(b'a') => {
                if !matches(cmd, "padding") {
                    return Err(plus_invalid(option));
                }
                if state && opts.edns.is_none() {
                    opts.edns = Some(0);
                }
                if state {
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    let n = parse_uint("padding", &v, 512).map_err(|_| warn_exit("padding"))?;
                    opts.padding = Some(n as u16);
                } else {
                    opts.padding = None;
                }
            }
            Some(b'r') => {
                // +proxy* (plus_proxy_options): accepted, transport-level.
                if !matches(cmd, "proxy") {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'q' => match c1() {
            Some(b'i') => {
                if !matches(cmd, "qid") {
                    return Err(plus_invalid(option));
                }
                if state {
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    let n = parse_uint("qid", &v, 0xffff).map_err(|_| warn_exit("qid"))?;
                    opts.qid = Some(n as u16);
                } else {
                    opts.qid = None;
                }
            }
            Some(b'r') => {
                if matches(cmd, "qr") {
                    opts.print_qr = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'u') => {
                if matches(cmd, "question") {
                    opts.section_question = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'r' => match c1() {
            Some(b'a') => {
                if matches(cmd, "raflag") {
                    opts.raflag = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'd') => {
                if matches(cmd, "rdflag") {
                    opts.recurse = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'e') => match c2() {
                Some(b'c') => {
                    if matches(cmd, "recurse") {
                        opts.recurse = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b't') => {
                    if !(matches(cmd, "retry") || matches(cmd, "retries")) {
                        return Err(plus_invalid(option));
                    }
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    if !state {
                        return Err(plus_invalid(option));
                    }
                    let n = parse_uint("retries", &v, u32::MAX as u64 - 1)
                        .map_err(|_| warn_exit("retries"))?;
                    opts.tries = n as u32 + 1;
                }
                _ => return Err(plus_invalid(option)),
            },
            Some(b'r') => {
                if matches(cmd, "rrcomments") {
                    // rrcomments = state ? 1 : -1 (rendering nuance; accepted)
                } else {
                    return Err(plus_invalid(option));
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b's' => match c1() {
            Some(b'e') => {
                if matches(cmd, "search") {
                    // usesearch = state (search-list resolution; no-op)
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'h') => {
                if c2() != Some(b'o') {
                    return Err(plus_invalid(option));
                }
                match c3() {
                    Some(b'r') => {
                        if !matches(cmd, "short") {
                            return Err(plus_invalid(option));
                        }
                        opts.short = state;
                        if state {
                            opts.print_cmd = false;
                            opts.section_additional = false;
                            opts.section_answer = true;
                            opts.section_authority = false;
                            opts.section_question = false;
                            opts.comments = false;
                            opts.statistics = false;
                        }
                    }
                    Some(b'w') => match c4() {
                        Some(b'b') => match c7() {
                            Some(b'c') => {
                                if matches(cmd, "showbadcookie") {
                                    // showbadcookie = state
                                } else {
                                    return Err(plus_invalid(option));
                                }
                            }
                            Some(b'v') => {
                                if matches(cmd, "showbadvers") {
                                    // showbadvers = state
                                } else {
                                    return Err(plus_invalid(option));
                                }
                            }
                            _ => return Err(plus_invalid(option)),
                        },
                        Some(b's') => {
                            if matches(cmd, "showsearch") {
                                // usesearch = state
                            } else {
                                return Err(plus_invalid(option));
                            }
                        }
                        _ => return Err(plus_invalid(option)),
                    },
                    _ => return Err(plus_invalid(option)),
                }
            }
            Some(b'i') => {
                if matches(cmd, "sigchase") {
                    return Err(removed("+sigchase"));
                }
                return Err(plus_invalid(option));
            }
            Some(b'p') => {
                if !matches(cmd, "split") {
                    return Err(plus_invalid(option));
                }
                if value.is_some() && !state {
                    return Err(plus_invalid(option));
                }
                if !state {
                    // splitwidth = 0
                } else if let Some(v) = value {
                    let mut n = parse_uint("split", &v, 1023).map_err(|_| warn_exit("split"))?;
                    if n % 4 != 0 {
                        n = ((n + 3) / 4) * 4;
                        eprintln!(";; Warning, split must be a multiple of 4; adjusting to {n}");
                    }
                }
            }
            Some(b't') => {
                if matches(cmd, "stats") {
                    opts.statistics = state;
                } else {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'u') => {
                if !matches(cmd, "subnet") {
                    return Err(plus_invalid(option));
                }
                if state && value.is_none() {
                    return Err(plus_invalid(option));
                }
                if state {
                    if opts.edns.is_none() {
                        opts.edns = Some(0);
                    }
                    let v = value.unwrap();
                    // parse_netprefix: accepted; the ECS option is encoded
                    // from this text at query build (dighost.c setup_lookup
                    // stores the parsed prefix in ecs_addr).
                    opts.subnet = Some(v);
                } else {
                    opts.subnet = None;
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b't' => match c1() {
            Some(b'c') => match c2() {
                Some(b'f') => {
                    if matches(cmd, "tcflag") {
                        opts.tcflag = state;
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'p') => {
                    if matches(cmd, "tcp") {
                        set_transport(
                            opts,
                            names,
                            if state {
                                Transport::Tcp
                            } else {
                                Transport::Udp
                            },
                            true,
                        );
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                _ => return Err(plus_invalid(option)),
            },
            Some(b'i') => {
                if !matches(cmd, "timeout") {
                    return Err(plus_invalid(option));
                }
                let v = value.ok_or_else(|| plus_invalid(option))?;
                if !state {
                    return Err(plus_invalid(option));
                }
                let mut n = parse_uint("timeout", &v, 0xffff).map_err(|_| warn_exit("timeout"))?;
                if n == 0 {
                    n = 1;
                }
                opts.timeout_secs = n;
            }
            Some(b'l') => {
                // +tls* (plus_tls_options): accepted, transport-level.
                if c2() != Some(b's') || !matches(cmd, "tls") {
                    return Err(plus_invalid(option));
                }
            }
            Some(b'o') => {
                if matches(cmd, "topdown") {
                    return Err(removed("+topdown"));
                }
                return Err(plus_invalid(option));
            }
            Some(b'r') => match c2() {
                Some(b'a') => {
                    if matches(cmd, "trace") {
                        if state {
                            opts.recurse = true;
                            opts.identify = true;
                            opts.comments = false;
                            opts.statistics = false;
                            opts.section_additional = false;
                            opts.section_authority = true;
                            opts.section_question = false;
                            opts.dnssec = true;
                            opts.sendcookie = true;
                        }
                    } else {
                        return Err(plus_invalid(option));
                    }
                }
                Some(b'i') => {
                    if !matches(cmd, "tries") {
                        return Err(plus_invalid(option));
                    }
                    let v = value.ok_or_else(|| plus_invalid(option))?;
                    if !state {
                        return Err(plus_invalid(option));
                    }
                    let mut n =
                        parse_uint("tries", &v, u32::MAX as u64).map_err(|_| warn_exit("tries"))?;
                    if n == 0 {
                        n = 1;
                    }
                    opts.tries = n as u32;
                }
                Some(b'u') => {
                    if matches(cmd, "trusted-key") {
                        return Err(removed("+trusted-key"));
                    }
                    return Err(plus_invalid(option));
                }
                _ => return Err(plus_invalid(option)),
            },
            Some(b't') => {
                if c2() != Some(b'l') {
                    return Err(plus_invalid(option));
                }
                match c3() {
                    None | Some(b'i') => {
                        if matches(cmd, "ttl") || matches(cmd, "ttlid") {
                            opts.nottl = !state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    Some(b'u') => {
                        if matches(cmd, "ttlunits") {
                            opts.nottl = false;
                            opts.ttlunits = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            _ => return Err(plus_invalid(option)),
        },
        b'u' => {
            // dig.c case 'u' has no default: `+u`, `+ux`, ... are silently
            // accepted no-ops (archived quirk; verified against the oracle).
            if c1() == Some(b'n') {
                match c2() {
                    Some(b'e') => {
                        if matches(cmd, "unexpected") {
                            return Err(removed("+unexpected"));
                        }
                        return Err(plus_invalid(option));
                    }
                    Some(b'k') => {
                        if matches(cmd, "unknownformat") {
                            opts.print_unknown_format = state;
                        } else {
                            return Err(plus_invalid(option));
                        }
                    }
                    _ => return Err(plus_invalid(option)),
                }
            }
            // else: silently accepted (BIND quirk).
        }
        b'v' => {
            if !matches(cmd, "vc") {
                return Err(plus_invalid(option));
            }
            set_transport(
                opts,
                names,
                if state {
                    Transport::Tcp
                } else {
                    Transport::Udp
                },
                true,
            );
        }
        b'y' => {
            if !matches(cmd, "yaml") {
                return Err(plus_invalid(option));
            }
            opts.yaml = state;
            if state {
                opts.print_cmd = false;
                opts.statistics = false;
            }
        }
        b'z' => {
            if matches(cmd, "zflag") {
                opts.zflag = state;
            } else {
                return Err(plus_invalid(option));
            }
        }
        _ => return Err(plus_invalid(option)),
    }
    Ok(())
}

/// dighost.c `save_opt`: resolve the option code by name or number and store
/// (hex-decoded) value.
fn save_ednsopt(opts: &mut DigOptions, code: &str, value: Option<&str>) -> Result<(), ParseError> {
    let num = match OPTNAMES.iter().find(|(n, _)| n.eq_ignore_ascii_case(code)) {
        Some((_, c)) => *c,
        None => {
            let n = parse_uint("ednsopt", code, 65535).map_err(|_| {
                // fatal("bad edns code point: %s")
                ParseError::Fatal(format!("bad edns code point: {code}"))
            })?;
            n as u16
        }
    };
    let data = match value {
        None => Vec::new(),
        Some(v) => {
            // isc_hex_decodestring
            let bytes = hex_decode(v)
                .map_err(|_| ParseError::Fatal("couldn't decode ednsopt value".to_string()))?;
            bytes
        }
    };
    opts.ednsopts.push((num, data));
    Ok(())
}

/// Decode a hex string (even length, no separator).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or(())?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
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

        // AXFR forces TCP (dig.c) on the *current lookup*.
        let o = parse_args(&["example.com".to_string(), "AXFR".to_string()]).unwrap();
        assert_eq!(o.lookups[0].transport, Transport::Tcp);

        // -q sets the name directly.
        let o = parse_args(&["-q".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
    }

    /// The `+c` prefix quirks (dig.c `case 'c'` switch on cmd[1]): `+cd`,
    /// `+co`, `+cl`, `+cmd`, `+com`, `+coo` are valid; bare `+c` is not.
    #[test]
    fn c_chain_prefix_quirks() {
        assert!(matches!(
            parse_args(&["+c".to_string(), "example.com".to_string()]),
            Err(ParseError::Usage(_))
        ));
        let o = parse_args(&["+cd".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.cdflag);
        let o = parse_args(&["+co".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.coflag);
        let o = parse_args(&["+cl".to_string(), "example.com".to_string()]).unwrap();
        // `+cl` is a back-compat synonym for `+class` (noclass = !state).
        assert!(!o.noclass);
        let o = parse_args(&["+nocl".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.noclass);
        let o = parse_args(&["+com".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.comments);
        let o = parse_args(&["+nocom".to_string(), "example.com".to_string()]).unwrap();
        assert!(!o.comments);
        let o = parse_args(&["+coo".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.sendcookie);
        let o = parse_args(&["+nocoo".to_string(), "example.com".to_string()]).unwrap();
        assert!(!o.sendcookie);
        let o = parse_args(&["+cmd".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.print_cmd);
    }

    /// `+sh`/`+sho` are rejected; `+shor` works (dig.c `case 's'` cmd[2]/[3]
    /// dispatch).  `+u` is a silently accepted no-op (no default in case 'u').
    #[test]
    fn short_and_u_quirks() {
        assert!(matches!(
            parse_args(&["+sh".to_string(), "example.com".to_string()]),
            Err(ParseError::Usage(_))
        ));
        assert!(matches!(
            parse_args(&["+sho".to_string(), "example.com".to_string()]),
            Err(ParseError::Usage(_))
        ));
        let o = parse_args(&["+shor".to_string(), "example.com".to_string()]).unwrap();
        assert!(o.short);
        let o = parse_args(&["+u".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.lookups.len(), 1);
    }

    /// The error taxonomy: `+time`/`+tries`/`+bufsize`/`+retry`/`+edns`
    /// parse failures are `Warn` (exit 10); `-p`/`-t ixfr` are `Fatal` (exit
    /// 1); removed options are `Fatal`; `+` alone is a stdout warning.
    #[test]
    fn error_taxonomy() {
        assert!(matches!(
            parse_args(&["+time=abc".to_string(), "example.com".to_string()]),
            Err(ParseError::Warn(_))
        ));
        assert!(matches!(
            parse_args(&["+tries=abc".to_string(), "example.com".to_string()]),
            Err(ParseError::Warn(_))
        ));
        assert!(matches!(
            parse_args(&["+bufsize=abc".to_string(), "example.com".to_string()]),
            Err(ParseError::Warn(_))
        ));
        assert!(matches!(
            parse_args(&["+retry=abc".to_string(), "example.com".to_string()]),
            Err(ParseError::Warn(_))
        ));
        assert!(matches!(
            parse_args(&["-p".to_string(), "99999".to_string()]),
            Err(ParseError::Fatal(_))
        ));
        assert!(matches!(
            parse_args(&["-t".to_string(), "ixfr=abc".to_string()]),
            Err(ParseError::Fatal(_))
        ));
        assert!(matches!(
            parse_args(&["+topdown".to_string(), "example.com".to_string()]),
            Err(ParseError::Fatal(_))
        ));
        assert!(matches!(
            parse_args(&["-i".to_string()]),
            Err(ParseError::Fatal(_))
        ));
        assert!(matches!(
            parse_args(&["-b".to_string(), "bad".to_string()]),
            Err(ParseError::Fatal(_))
        ));
    }

    /// The greeting build-time capture: `dig example.com +noall` records
    /// (true, false, …) at the first name; `dig +noall example.com` records
    /// (false, …) and therefore never builds a greeting.
    #[test]
    fn greeting_build_time_capture() {
        let o = parse_args(&["example.com".to_string(), "+noall".to_string()]).unwrap();
        assert_eq!(o.first_name_greeting, Some((true, false, false)));
        let o = parse_args(&["+noall".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.first_name_greeting, Some((false, false, false)));
        // `-x` before `@server`: the server was not yet seen at build time.
        let o = parse_args(&[
            "-x".to_string(),
            "192.0.2.1".to_string(),
            "@127.0.0.1".to_string(),
        ])
        .unwrap();
        assert_eq!(o.first_name_greeting, Some((true, false, false)));
        let o = parse_args(&["@127.0.0.1".to_string(), "example.com".to_string()]).unwrap();
        assert_eq!(o.first_name_greeting, Some((true, false, true)));
    }
}
