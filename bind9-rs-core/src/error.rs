//! Shared error taxonomy.
//!
//! The names deliberately echo the DNS/ISC result codes whose observable
//! behavior we reproduce (`ISC_R_SUCCESS`, `DNS_R_FORMERR`, `DNS_R_SERVFAIL`,
//! ...).  Mapping to the historical result-code names is done in comments so
//! that archaeology records and courts can refer to either name.
//!
//! The BIND result-code universe is much larger than this enum; it grows as
//! the corresponding semantics are implemented.  Never flatten a distinct
//! BIND failure into `Other` without a court that proves the observable
//! behavior is identical (§13 — residuals are evidence).

use std::fmt;

/// Result of a DNS operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// Operation succeeded.
    ///
    /// BIND: `ISC_R_SUCCESS`.
    Success,
    /// Out of memory (BIND: `ISC_R_NOMEMORY`).
    NoMemory,
    /// Not enough space in a fixed-size target buffer (BIND:
    /// `ISC_R_NOSPACE`, text "ran out of space").  Notably, BIND's
    /// `dns_name_fromtext` returns this — never `DNS_R_NAMETOOLONG` — when a
    /// name exceeds 255 wire octets, because its target buffer is clamped to
    /// `DNS_NAME_MAXWIRE`.
    NoSpace,
    /// The operation timed out (BIND: `ISC_R_TIMEDOUT`).
    TimedOut,
    /// Not implemented (BIND: `ISC_R_NOTIMPLEMENTED`).
    NotImplemented,
    /// Refused (BIND: `ISC_R_REFUSED`, `DNS_R_REFUSED`).
    Refused,
    /// Server failure (BIND: `DNS_R_SERVFAIL`).
    ServFail,
    /// Format error — malformed message (BIND: `DNS_R_FORMERR`).
    FormErr,
    /// Not found (BIND: `ISC_R_NOTFOUND`, `DNS_R_NXRRSET`, ...).
    NotFound,
    /// The object already exists (BIND: `ISC_R_EXISTS`, `DNS_R_DUPLICATE`).
    Exists,
    /// Invalid argument (BIND: `ISC_R_FAILURE` / `ISC_R_INVALIDARG` family).
    InvalidArgument,
    /// Bad/invalid data (BIND: `ISC_R_BADBASE64`, `DNS_R_BADDB`, ...).
    BadData,
    /// A malformed IPv4 dotted quad (BIND: `DNS_R_BADDOTTEDQUAD`, text
    /// "bad dotted quad" — `inet_pton` semantics: exactly four decimal
    /// parts, no leading zeros except "0", each ≤ 255).
    BadDottedQuad,
    /// A malformed IPv6 address (BIND: `DNS_R_BADAAAAA`, text
    /// "bad IPv6 address" — `inet_pton` AF_INET6 semantics).
    BadIpv6,
    /// A numeric field outside its legal range (BIND: `ISC_R_RANGE`, text
    /// "out of range" — e.g. MX preference 65536, SOA serial 2^32).
    Range,
    /// A token that is not a valid number (BIND: `ISC_R_BADNUMBER`, text
    /// "not a valid number" — e.g. a negative serial).
    BadNumber,
    /// Bad hexadecimal encoding (BIND: `DNS_R_BADHEX`, text
    /// "bad hex encoding" — non-hex digit or odd digit count).
    BadHex,
    /// Syntax error in a TTL/counter (BIND: `DNS_R_SYNTAX`, text
    /// "syntax error" — `bind_ttl`'s non-digit start).
    Syntax,
    /// Truncated input (BIND: `ISC_R_UNEXPECTEDEND` — the probe-visible
    /// text is "unexpected end of input").
    UnexpectedEnd,
    /// The message parser recovered from one or more malformed records in
    /// best-effort mode (BIND: `DNS_R_RECOVERABLE`, text "recoverable
    /// error occurred").
    Recoverable,
    /// A TSIG record in the wrong place (BIND: `DNS_R_BADTSIG`, text "TSIG
    /// in wrong location").
    BadTsig,
    /// A SIG(0) record in the wrong place (BIND: `DNS_R_BADSIG0`, text
    /// "SIG(0) in wrong location").
    BadSig0,
    /// An owner name failing the NSEC3 base32hex first-label rule (BIND:
    /// `DNS_R_BADOWNERNAME`, text "bad owner name (check-names)").
    BadOwnerName,
    /// A malformed EDNS option (BIND: `DNS_R_OPTERR`, text "malformed OPT
    /// option").
    Opterr,
    /// An RR of a singleton type with conflicting RDATA in one RRset
    /// (BIND: `DNS_R_SINGLETON`, text "multiple RRs of singleton type").
    Singleton,
    /// A name/type/class token that matches no table entry (BIND:
    /// `DNS_R_UNKNOWN`, text "unknown class/type" — fromtext lookups).
    UnknownClassType,
    /// An unmatched `)` in multiline mode (BIND: `ISC_R_UNBALANCED`, text
    /// "unbalanced parentheses").
    Unbalanced,
    /// A newline inside an unterminated quoted string (BIND:
    /// `ISC_R_UNBALANCEDQUOTES`, text "unbalanced quotes").
    UnbalancedQuotes,
    /// End of input without the EOF-token option (BIND: `ISC_R_EOF`, text
    /// "end of file").
    Eof,
    /// A token of an unexpected type (BIND: `ISC_R_UNEXPECTEDTOKEN`, text
    /// "unexpected token").
    UnexpectedToken,
    /// The message is too long / over an allowed bound
    /// (BIND: `ISC_R_MESSAGETOOLONG`, `DNS_R_FORMERR`-adjacent).
    MessageTooLong,
    /// Disallowed by configuration or policy (BIND: `ISC_R_PERMISSIONDENIED`).
    PermissionDenied,
    /// A name/record is out of the zone when one is required in-zone.
    OutOfZone,
    /// CNAME conflict or other RRset consistency violation
    /// (BIND: `DNS_R_CNAME`).
    CnameConflict,
    /// An empty label in a name (BIND: `DNS_R_EMPTYLABEL`, text
    /// "empty label").
    EmptyLabel,
    /// A label longer than 63 octets (BIND: `DNS_R_LABELTOOLONG`,
    /// "label too long").
    LabelTooLong,
    /// A malformed escape sequence (BIND: `DNS_R_BADESCAPE`, "bad escape").
    BadEscape,
    /// A label length octet with a reserved prefix (BIND:
    /// `DNS_R_BADLABELTYPE`, "bad label type").
    BadLabelType,
    /// A name exceeding 255 wire octets (BIND: `DNS_R_NAMETOOLONG`,
    /// "name too long").
    NameTooLong,
    /// A name failing check-names (BIND: `DNS_R_BADNAME`,
    /// "bad name (check-names)").
    BadName,
    /// A compression pointer violating the backwards rule (BIND:
    /// `DNS_R_BADPOINTER`, "bad compression pointer").
    BadPointer,
    /// Compression used where disallowed (BIND: `DNS_R_DISALLOWED`,
    /// "disallowed (by application policy)").
    Disallowed,
    /// RDATA that does not consume its declared length on the wire (BIND:
    /// `DNS_R_EXTRADATA`, "extra input data").
    ExtraData,
    /// Trailing tokens after the RDATA fields in text form (BIND:
    /// `DNS_R_EXTRATOKEN`, text "extra input text" — emitted by
    /// `dns_rdata_fromtext`'s consume-to-eol wrapper).
    ExtraToken,
    /// Invalid use of a meta type (BIND: `DNS_R_METATYPE`,
    /// "invalid use of a meta type").
    MetaType,
    /// DNSSEC-related failures (BIND: `DNS_R_BADKEY`/`DNS_R_SIGEXPIRED`/...)
    /// — expanded as the DNSSEC machinery lands.
    Dnssec,
    /// Network/transport failure (BIND: `ISC_R_NETUNREACH`, `ISC_R_CONNREFUSED`).
    Network,
    /// Any other condition; always carries an explanation.
    ///
    /// New variants are preferred over `Other` whenever the condition is
    /// observable in BIND.  `Other` exists only for genuinely internal
    /// conditions with no external compatibility consequence.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.bind_totext())
    }
}

impl Error {
    /// The BIND `isc_result_totext` / `dns_result_totext` string for this
    /// error (the text dig prints in `;; Got bad packet: <text>` and in
    /// fatal messages).  Kept separate from `Display` so internal
    /// explanations stay distinct from the compatibility-facing text.
    #[must_use]
    pub fn bind_totext(&self) -> &str {
        match self {
            Error::Success => "success",
            Error::NoMemory => "out of memory",
            Error::NoSpace => "ran out of space",
            Error::TimedOut => "timed out",
            Error::NotImplemented => "not implemented",
            Error::Refused => "refused",
            Error::ServFail => "server failure",
            Error::FormErr => "FORMERR",
            Error::NotFound => "not found",
            Error::Exists => "already exists",
            Error::InvalidArgument => "invalid argument",
            Error::BadData => "bad data",
            Error::BadDottedQuad => "bad dotted quad",
            Error::BadIpv6 => "bad IPv6 address",
            Error::Range => "out of range",
            Error::BadNumber => "not a valid number",
            Error::BadHex => "bad hex encoding",
            Error::Syntax => "syntax error",
            Error::UnexpectedEnd => "unexpected end of input",
            Error::Recoverable => "recoverable error occurred",
            Error::BadTsig => "TSIG in wrong location",
            Error::BadSig0 => "SIG(0) in wrong location",
            Error::BadOwnerName => "bad owner name (check-names)",
            Error::Opterr => "malformed OPT option",
            Error::Singleton => "multiple RRs of singleton type",
            Error::UnknownClassType => "unknown class/type",
            Error::Unbalanced => "unbalanced parentheses",
            Error::UnbalancedQuotes => "unbalanced quotes",
            Error::Eof => "end of file",
            Error::UnexpectedToken => "unexpected token",
            Error::MessageTooLong => "message too long",
            Error::PermissionDenied => "permission denied",
            Error::OutOfZone => "out of zone",
            Error::CnameConflict => "cname",
            Error::EmptyLabel => "empty label",
            Error::LabelTooLong => "label too long",
            Error::BadEscape => "bad escape",
            Error::BadLabelType => "bad label type",
            Error::NameTooLong => "name too long",
            Error::BadName => "bad name (check-names)",
            Error::BadPointer => "bad compression pointer",
            Error::Disallowed => "disallowed (by application policy)",
            Error::ExtraData => "extra input data",
            Error::ExtraToken => "extra input text",
            Error::MetaType => "invalid use of a meta type",
            Error::Dnssec => "DNSSEC error",
            Error::Network => "network failure",
            Error::Other(s) => s,
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
