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
    /// Truncated input (BIND: `ISC_R_UNEXPECTEDEND` — the probe-visible
    /// text is "unexpected end of input").
    UnexpectedEnd,
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
    /// RDATA that does not consume its declared length (BIND:
    /// `DNS_R_EXTRADATA`, "extra input data").
    ExtraData,
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
        match self {
            Error::Success => f.write_str("success"),
            Error::NoMemory => f.write_str("out of memory"),
            Error::NoSpace => f.write_str("ran out of space"),
            Error::TimedOut => f.write_str("timed out"),
            Error::NotImplemented => f.write_str("not implemented"),
            Error::Refused => f.write_str("refused"),
            Error::ServFail => f.write_str("server failure"),
            Error::FormErr => f.write_str("format error"),
            Error::NotFound => f.write_str("not found"),
            Error::Exists => f.write_str("already exists"),
            Error::InvalidArgument => f.write_str("invalid argument"),
            Error::BadData => f.write_str("bad data"),
            Error::UnexpectedEnd => f.write_str("unexpected end of input"),
            Error::MessageTooLong => f.write_str("message too long"),
            Error::PermissionDenied => f.write_str("permission denied"),
            Error::OutOfZone => f.write_str("out of zone"),
            Error::CnameConflict => f.write_str("cname"),
            Error::EmptyLabel => f.write_str("empty label"),
            Error::LabelTooLong => f.write_str("label too long"),
            Error::BadEscape => f.write_str("bad escape"),
            Error::BadLabelType => f.write_str("bad label type"),
            Error::NameTooLong => f.write_str("name too long"),
            Error::BadName => f.write_str("bad name (check-names)"),
            Error::BadPointer => f.write_str("bad compression pointer"),
            Error::Disallowed => f.write_str("disallowed (by application policy)"),
            Error::ExtraData => f.write_str("extra input data"),
            Error::MetaType => f.write_str("invalid use of a meta type"),
            Error::Dnssec => f.write_str("DNSSEC error"),
            Error::Network => f.write_str("network failure"),
            Error::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
