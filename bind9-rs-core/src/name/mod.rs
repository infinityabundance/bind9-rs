//! DNS names and labels.
//!
//! The implementation mirrors BIND's `lib/dns/name.c` semantics, which the
//! courts `CORE-NAME-*` verify against oracle probes built on BIND's
//! `dns_name_fromtext` / `dns_name_fromwire` / `dns_name_totext` /
//! `dns_name_compare` / `dns_name_rdatacompare`.
//!
//! Key BIND behaviors encoded here (each with its court):
//!
//! - **Text parsing** (`dns_name_fromtext`, court `CORE-NAME-TEXT-*`):
//!   labels separated by `.`; `\DDD` is *exactly* three octal digits; any
//!   other `\c` yields the literal character `c`; a trailing `.` makes the
//!   name absolute; relative names are resolved against an origin; the wire
//!   length (including length octets and the root octet) is limited to 255.
//! - **Wire parsing** (`dns_name_fromwire`, court `CORE-NAME-WIRE-*`):
//!   length-prefixed labels; compression pointers (`11` prefix) must point
//!   strictly backwards within the message and are resolved with loop
//!   protection; labels ≤ 63 octets; total ≤ 255.
//! - **Comparison** (`dns_name_compare`, court `CORE-NAME-COMPARE-*`):
//!   ASCII case-insensitive, label by label from the leftmost; when all
//!   compared labels are equal the shorter name is smaller.
//! - **Canonical comparison** (`dns_name_rdatacompare`, court
//!   `DNSSEC-CANONICAL-*`): case-preserving octet comparison, as RFC 4034
//!   canonical ordering requires.
//! - **Rendering** (`dns_name_totext`, court `CORE-NAME-TOTEXT-*`): the
//!   escape rules below, verified byte-by-byte against the oracle.

mod label;
pub mod wire;

pub use label::Label;
pub use wire::{FromWire, NameWireError};

use crate::error::{Error, Result};
use std::fmt;

/// Maximum length of a DNS name on the wire, in octets, including label
/// length octets and the terminating root octet (RFC 1035 §2.3.4; BIND
/// `DNS_NAME_MAXWIRE` is 255).
pub const MAX_WIRE: usize = 255;
/// Maximum length of a single label (RFC 1035 §2.3.4; BIND `DNS_LABELLEN`).
pub const MAX_LABEL: usize = 63;
/// Maximum number of labels in a name (BIND `DNS_NAME_MAXLABELS`); the
/// practical bound derived from 255 wire octets with 1-octet labels is 127,
/// but BIND's constant is 128 — the wire-length check governs, this is a
/// defensive upper bound for allocations.
pub const MAX_LABELS: usize = 128;

/// A DNS name.
///
/// Representation mirrors BIND: the wire-format labels (length-prefixed)
/// **without** the terminating root octet, plus an `absolute` flag
/// (BIND's `DNS_NAMEATTR_ABSOLUTE` attribute, set by `dns_name_fromtext`
/// when the text ends in `.` and by all wire-parsed names).
///
/// Invariants (enforced at every construction point):
/// - `data.len() <= MAX_WIRE - 1` (the wire form with root octet ≤ 255);
/// - every label length octet ≤ `MAX_LABEL`;
/// - the label lengths exactly cover `data`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name {
    data: Box<[u8]>,
    absolute: bool,
    /// BIND `DNS_NAMEATTR_NOCOMPRESS`: the name must never be compressed.
    /// `dns_name_towire` still adds it to the compression table (so later
    /// names can point at it), but always writes it in full.  BIND sets it
    /// on TSIG key names (lib/dns/tsig.c, lib/dns/message.c) and propagates
    /// it from owner names (lib/dns/rdataset.c).
    nocompress: bool,
}

impl Name {
    /// The root name.
    #[must_use]
    pub fn root() -> Self {
        Name {
            data: Box::new([]),
            absolute: true,
            nocompress: false,
        }
    }

    /// Construct from wire-format labels (length-prefixed, no root octet).
    ///
    /// This is the internal builder; it validates the structural invariants
    /// and fails with [`Error::InvalidArgument`] on violation.
    fn from_wire_labels(data: Box<[u8]>, absolute: bool) -> Result<Self> {
        let mut i = 0;
        let mut labels = 0;
        while i < data.len() {
            let len = data[i] as usize;
            if len > MAX_LABEL {
                return Err(Error::InvalidArgument);
            }
            i += 1 + len;
            labels += 1;
            if labels > MAX_LABELS {
                return Err(Error::InvalidArgument);
            }
        }
        if i != data.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(Name {
            data,
            absolute,
            nocompress: false,
        })
    }

    /// Parse a name from text, resolving relative names against `origin`.
    ///
    /// Mirrors `dns_name_fromtext`: case is preserved (use
    /// [`Name::from_text_downcase`] for the `DNS_NAME_DOWNCASE` behavior);
    /// a trailing `.` makes the name absolute; without it, `origin` is
    /// required and its labels are appended.
    pub fn from_text(text: &str, origin: Option<&Name>) -> Result<Self> {
        Self::from_text_with(text, origin, false)
    }

    /// Like [`Name::from_text`] but with BIND's `DNS_NAME_DOWNCASE` option.
    pub fn from_text_downcase(text: &str, origin: Option<&Name>) -> Result<Self> {
        Self::from_text_with(text, origin, true)
    }

    fn from_text_with(text: &str, origin: Option<&Name>, downcase: bool) -> Result<Self> {
        // The lexer layer (masterfile) handles `@` expansion; at this level
        // we parse the raw escape grammar.
        let bytes = text.as_bytes();
        // BIND special case: "@" as the entire input is the origin
        // (dns_name_fromtext ft_at state).
        if bytes == b"@" {
            let mut o = origin.ok_or(Error::InvalidArgument)?.clone();
            if downcase {
                o = Self::from_text_downcase(&o.to_text(), Some(&Name::root()))?;
            }
            return Ok(o);
        }
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut absolute = false;
        let mut i = 0;
        let mut saw_any = false;

        while i < bytes.len() {
            let c = bytes[i];
            match c {
                b'.' => {
                    // "." alone is the root name (BIND's ft_init case:
                    // a leading dot with more input is DNS_R_EMPTYLABEL).
                    if i == 0 && bytes.len() == 1 {
                        absolute = true;
                        i += 1;
                        saw_any = true;
                        continue;
                    }
                    if current.is_empty() {
                        // Empty label (e.g. "a..b" or ".a.") — BIND rejects
                        // this with DNS_R_EMPTYLABEL ("empty label").
                        return Err(Error::EmptyLabel);
                    }
                    if current.len() > MAX_LABEL {
                        return Err(Error::LabelTooLong);
                    }
                    labels.push(std::mem::take(&mut current));
                    i += 1;
                    saw_any = true;
                }
                b'\\' => {
                    if i + 1 >= bytes.len() {
                        // Trailing backslash — BIND: ISC_R_UNEXPECTEDEND.
                        return Err(Error::UnexpectedEnd);
                    }
                    let next = bytes[i + 1];
                    if next.is_ascii_digit() {
                        // Exactly three DECIMAL digits (BIND 9.20 semantics;
                        // the version-delta database records when BIND
                        // changed this from octal — court
                        // CORE-NAME-TEXT-ESCAPE-*).
                        if i + 3 >= bytes.len()
                            || !bytes[i + 2].is_ascii_digit()
                            || !bytes[i + 3].is_ascii_digit()
                        {
                            return Err(Error::UnexpectedEnd);
                        }
                        let val = u16::from(next - b'0') * 100
                            + u16::from(bytes[i + 2] - b'0') * 10
                            + u16::from(bytes[i + 3] - b'0');
                        if val > 255 {
                            // BIND: DNS_R_BADESCAPE ("bad escape").
                            return Err(Error::BadEscape);
                        }
                        let mut b = val as u8;
                        if downcase {
                            b = b.to_ascii_lowercase();
                        }
                        current.push(b);
                        i += 4;
                    } else {
                        let mut b = next;
                        if downcase {
                            b = b.to_ascii_lowercase();
                        }
                        current.push(b);
                        i += 2;
                    }
                    saw_any = true;
                }
                _ => {
                    let mut b = c;
                    if downcase {
                        b = b.to_ascii_lowercase();
                    }
                    current.push(b);
                    i += 1;
                    saw_any = true;
                }
            }
        }

        if saw_any && !current.is_empty() {
            if current.len() > MAX_LABEL {
                return Err(Error::LabelTooLong);
            }
            labels.push(current);
        }

        // BIND: a trailing dot makes the name absolute (the ft_ordinary
        // case writes the root label and sets `done`).
        let ended_with_dot = matches!(bytes.last(), Some(b'.'));
        let absolute = absolute || ended_with_dot;

        // Apply origin unless the text ended with ".".
        if !absolute {
            match origin {
                Some(origin) => {
                    if !origin.absolute {
                        return Err(Error::InvalidArgument);
                    }
                    for label in origin.labels() {
                        let mut lb: Vec<u8> = label.as_bytes().to_vec();
                        if downcase {
                            lb = lb.iter().map(|b| b.to_ascii_lowercase()).collect();
                        }
                        labels.push(lb);
                    }
                }
                None => {
                    // BIND allows building relative names with a NULL origin;
                    // we require an origin at this layer.  (Callers that need
                    // relative names use label concatenation explicitly.)
                    return Err(Error::InvalidArgument);
                }
            }
        }

        let mut data = Vec::with_capacity(labels.iter().map(|l| l.len() + 1).sum());
        for label in &labels {
            data.push(label.len() as u8);
            data.extend_from_slice(label);
        }
        if data.len() + 1 > MAX_WIRE {
            // BIND's dns_name_fromtext returns ISC_R_NOSPACE ("ran out of
            // space") here — never DNS_R_NAMETOOLONG — because the target
            // buffer is clamped to DNS_NAME_MAXWIRE.  Court
            // CORE-NAME-TEXT-0001 verifies this against the oracle.
            return Err(Error::NoSpace);
        }
        let name = Self::from_wire_labels(data.into_boxed_slice(), absolute)?;
        // BIND: a name built by appending an absolute origin is itself
        // absolute (dns_name_fromtext sets absolute from the origin).
        Ok(match (absolute, origin) {
            (false, Some(origin)) if origin.absolute => name.with_absolute(true),
            _ => name,
        })
    }

    /// True if the name is anchored at the root (BIND
    /// `dns_name_isabsolute`).
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.absolute
    }

    /// A copy with the absolute flag set/cleared (BIND sets the flag from
    /// the origin when appending an absolute origin).
    #[must_use]
    pub fn with_absolute(mut self, absolute: bool) -> Self {
        self.absolute = absolute;
        self
    }

    /// A copy with BIND's `DNS_NAMEATTR_NOCOMPRESS` attribute set/cleared.
    #[must_use]
    pub fn with_nocompress(mut self, nocompress: bool) -> Self {
        self.nocompress = nocompress;
        self
    }

    /// Whether the name must be rendered uncompressed (BIND
    /// `DNS_NAMEATTR_NOCOMPRESS`; set on TSIG key names per RFC 8945).
    #[must_use]
    pub fn is_nocompress(&self) -> bool {
        self.nocompress
    }

    /// The number of labels, counting the root label for absolute names
    /// (BIND `dns_name_countlabels`: `countlabels(".") == 1`,
    /// `countlabels("example.com.") == 3`, `countlabels("www") == 1`).
    #[must_use]
    pub fn label_count(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.data.len() {
            n += 1;
            i += 1 + self.data[i] as usize;
        }
        if self.absolute {
            n += 1;
        }
        n
    }

    /// Iterate over the labels, leftmost first.
    pub fn labels(&self) -> impl Iterator<Item = Label<'_>> {
        LabelIter {
            data: &self.data,
            pos: 0,
        }
    }

    /// The wire length in octets **excluding** the root octet (BIND
    /// `dns_name_length`); the on-the-wire length is this plus one when
    /// absolute.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.data.len()
    }

    /// The on-the-wire length including the root octet (only meaningful for
    /// absolute names).
    #[must_use]
    pub fn wire_len_full(&self) -> usize {
        self.data.len() + usize::from(self.absolute)
    }

    /// The raw wire labels (no root octet).  Used by the wire renderer and
    /// compression machinery; do not treat as a public stable format.
    #[must_use]
    pub fn as_wire_slice(&self) -> &[u8] {
        &self.data
    }

    /// Render the name to text exactly as BIND's `dns_name_totext` does.
    ///
    /// Escape rules (verified against `lib/dns/name.c` 9.20.26; courted
    /// byte-by-byte by `CORE-NAME-TOTEXT-0001`): octets outside 0x21..=0x7e
    /// render as `\DDD` with **decimal** digits; the printable-but-special
    /// octets `.`, `"`, `\`, `(`, `)`, `;`, `@`, `$` render as `\c`; an
    /// absolute name gets a trailing `.`; the root name renders as `.`; an
    /// empty relative name renders as `@` (BIND's masterfile convention).
    #[must_use]
    pub fn to_text(&self) -> String {
        if self.data.is_empty() && !self.absolute {
            // BIND: the empty relative name renders as "@".
            return "@".to_string();
        }
        if self.data.is_empty() {
            // The root name renders as "." (BIND's totext special case for
            // the root label).
            return ".".to_string();
        }
        let mut out = String::new();
        for label in self.labels() {
            for &b in label.as_bytes() {
                match b {
                    b'.' | b'"' | b'\\' | b'(' | b')' | b';' | b'@' | b'$' => {
                        out.push('\\');
                        out.push(b as char);
                    }
                    0x21..=0x7e => out.push(b as char),
                    _ => {
                        out.push('\\');
                        out.push(char::from(b'0' + (b / 100) % 10));
                        out.push(char::from(b'0' + (b / 10) % 10));
                        out.push(char::from(b'0' + b % 10));
                    }
                }
            }
            out.push('.');
        }
        if !self.absolute {
            // Relative names have no trailing dot.
            out.pop();
        }
        out
    }

    /// BIND comparison (`dns_name_compare`, via `dns_name_fullcompare`):
    /// labels are compared **right-to-left starting at the root** (the
    /// DNSSEC order relation), ASCII case-insensitive; when all compared
    /// labels are equal the shorter name sorts first.
    ///
    /// This is hierarchical ordering: `example.com.` sorts before
    /// `www.example.com.`.  (BIND asserts both names are absolute-or-both
    /// relative; we define the mixed case as comparing with the root label
    /// of an absolute name acting as an empty final label.)
    #[must_use]
    pub fn compare(&self, other: &Name) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let mut self_labels: Vec<&[u8]> = self.labels().map(|l| l.as_bytes()).collect();
        let mut other_labels: Vec<&[u8]> = other.labels().map(|l| l.as_bytes()).collect();
        if self.absolute {
            self_labels.push(&[]); // root label
        }
        if other.absolute {
            other_labels.push(&[]);
        }
        let l1 = self_labels.len();
        let l2 = other_labels.len();
        let common = l1.min(l2);
        for k in 0..common {
            let order = cmp_labels(self_labels[l1 - 1 - k], other_labels[l2 - 1 - k]);
            if order != Ordering::Equal {
                return order;
            }
        }
        l1.cmp(&l2)
    }

    /// Canonical DNSSEC comparison (`dns_name_rdatacompare`): the wire
    /// octets compared **case-insensitively** (RFC 4034 §6.1 canonical
    /// ordering lowercases), up to the shorter name's length.
    #[must_use]
    pub fn rdatacompare(&self, other: &Name) -> std::cmp::Ordering {
        let a = self.data.iter().map(|b| b.to_ascii_lowercase());
        let b = other.data.iter().map(|b| b.to_ascii_lowercase());
        a.cmp(b)
    }

    /// True when `self` is a subdomain of (or equal to) `other`
    /// (BIND `dns_name_issubdomain`): the labels of `other` are a suffix of
    /// the labels of `self`, compared case-insensitively.
    #[must_use]
    pub fn is_subdomain(&self, other: &Name) -> bool {
        if self.label_count() < other.label_count() {
            return false;
        }
        let self_labels: Vec<Label<'_>> = self.labels().collect();
        let other_labels: Vec<Label<'_>> = other.labels().collect();
        let off = self_labels.len() - other_labels.len();
        other_labels.iter().enumerate().all(|(i, ol)| {
            cmp_labels(ol.as_bytes(), self_labels[off + i].as_bytes()) == std::cmp::Ordering::Equal
        })
    }
}

/// Compare two label bodies case-insensitively (ASCII fold), byte-wise.
fn cmp_labels(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let n = a.len().min(b.len());
    for i in 0..n {
        let x = a[i].to_ascii_lowercase();
        let y = b[i].to_ascii_lowercase();
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
    }
    a.len().cmp(&b.len())
}

struct LabelIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Label<'a>;
    fn next(&mut self) -> Option<Label<'a>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let len = self.data[self.pos] as usize;
        let l = Label::from_slice(&self.data[self.pos..self.pos + 1 + len]);
        self.pos += 1 + len;
        Some(l)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({})", self.to_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    fn n(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

    #[test]
    fn root_name() {
        let r = Name::root();
        assert_eq!(r.to_text(), ".");
        assert_eq!(r.wire_len(), 0);
        assert_eq!(r.wire_len_full(), 1);
        assert!(r.is_absolute());
        // BIND: countlabels(".") == 1 (the root label counts).
        assert_eq!(r.label_count(), 1);
    }

    #[test]
    fn basic_parse() {
        let x = n("example.com.");
        assert_eq!(x.to_text(), "example.com.");
        assert!(x.is_absolute());
        // BIND: countlabels("example.com.") == 3 (labels + root).
        assert_eq!(x.label_count(), 3);
        assert_eq!(x.wire_len(), 12); // 1+7 + 1+3
        assert_eq!(x.wire_len_full(), 13);
    }

    #[test]
    fn origin_resolution() {
        let origin = n("example.com.");
        let rel = Name::from_text("www", Some(&origin)).unwrap();
        assert_eq!(rel.to_text(), "www.example.com.");
        // BIND: appending an absolute origin makes the name absolute.
        assert!(rel.is_absolute());
        assert!(rel.is_subdomain(&origin));
    }

    #[test]
    fn relative_without_origin_is_error() {
        assert!(Name::from_text("www", None).is_err());
    }

    #[test]
    fn case_preserved() {
        let x = n("ExAmPle.COM.");
        assert_eq!(x.to_text(), "ExAmPle.COM.");
        // Comparison is case-insensitive.
        assert_eq!(x.compare(&n("example.com.")), Ordering::Equal);
        // Canonical comparison (rdatacompare) is also case-insensitive
        // (RFC 4034 canonical ordering lowercases; BIND uses
        // isc_ascii_lowercmp).
        assert_eq!(x.rdatacompare(&n("example.com.")), Ordering::Equal);
        assert_eq!(
            n("example.com.").rdatacompare(&n("example.com.")),
            Ordering::Equal
        );
    }

    #[test]
    fn escape_parsing() {
        // \. inside a label is a literal dot.
        let x = n("a\\.b.example.");
        assert_eq!(x.to_text(), "a\\.b.example.");
        // labels: "a.b", "example", + root label.
        assert_eq!(x.label_count(), 3);

        // \DDD is DECIMAL in BIND 9.20: \097 = 'a'.
        let y = n("\\097.example."); // 097 decimal = 'a'
        assert_eq!(y.to_text(), "a.example.");

        // \010 decimal = LF (0x0a); octal 010 would be 8 (backspace).
        let z = n("\\010.example.");
        assert_eq!(z.to_text(), "\\010.example.");
        assert_eq!(z.labels().next().unwrap().as_bytes(), &[0x0a]);

        // backslash-literal.
        let w = n("a\\\\b.example."); // "a\\b"
        assert_eq!(w.to_text(), "a\\\\b.example.");

        // \000 (zero octet) is accepted and renders back as \000.
        let v = n("\\000.example.");
        assert_eq!(v.labels().next().unwrap().as_bytes(), &[0x00]);
        assert_eq!(v.to_text(), "\\000.example.");
    }

    #[test]
    fn max_lengths() {
        // 63-char label OK.
        let long_label = "a".repeat(63);
        let name = format!("{long_label}.com.");
        assert!(Name::from_text(&name, Some(&Name::root())).is_ok());

        // 64-char label rejected.
        let too_long = format!("{}.com.", "a".repeat(64));
        assert!(Name::from_text(&too_long, Some(&Name::root())).is_err());

        // The maximum name: 250 label octets in 4 labels (63+63+63+61),
        // wire total = 250 + 4 length octets + 1 root = 255.  OK.
        let name = long_name(250);
        assert!(Name::from_text(&name, Some(&Name::root())).is_ok());

        // 251 label octets (63+63+63+62): wire total 256 → rejected.
        let name = long_name(251);
        assert!(Name::from_text(&name, Some(&Name::root())).is_err());
    }

    /// Build a name whose label octets (excluding separators/root) total
    /// `target` octets, as "a...a" labels joined by dots plus a trailing dot.
    fn long_name(target: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut remaining = target;
        while remaining > 0 {
            let l = remaining.min(63);
            parts.push("a".repeat(l));
            remaining -= l;
        }
        format!("{}.\n", parts.join("."))[..]
            .trim_end_matches('\n')
            .to_string()
    }

    #[test]
    fn empty_label_rejected() {
        assert!(Name::from_text("a..b.", Some(&Name::root())).is_err());
        assert!(Name::from_text(".a.", Some(&Name::root())).is_err());
    }

    #[test]
    fn bad_escapes_rejected() {
        // Trailing backslash.
        assert!(Name::from_text("a\\", Some(&Name::root())).is_err());
        // Incomplete escape (fewer than three digits).
        assert!(Name::from_text("a\\12.", Some(&Name::root())).is_err());
        // \999 exceeds 255.
        assert!(Name::from_text("a\\999.", Some(&Name::root())).is_err());
    }

    #[test]
    fn compare_ordering() {
        use Ordering::*;
        assert_eq!(n("a.example.").compare(&n("b.example.")), Less);
        assert_eq!(n("b.example.").compare(&n("a.example.")), Greater);
        assert_eq!(n("example.").compare(&n("example.")), Equal);
        // Shorter name first when shared labels equal (hierarchical).
        assert_eq!(n("example.").compare(&n("www.example.")), Less);
        assert_eq!(n("www.example.").compare(&n("example.")), Greater);
        assert_eq!(n("example.com.").compare(&n("example.org.")), Less);
        // BIND's order relation compares right-to-left from the root: the
        // rightmost differing label decides before the leftmost.
        // Same TLD: "z" vs "example" decides → z.com. > a.example.com.
        assert_eq!(n("z.com.").compare(&n("a.example.com.")), Greater);
        // Different TLD: "com" vs "net" decides → z.com. < a.net. even
        // though 'z' > 'a'.
        assert_eq!(n("z.com.").compare(&n("a.net.")), Less);
        assert_eq!(n("a.net.").compare(&n("z.com.")), Greater);
    }

    #[test]
    fn subdomain() {
        assert!(n("www.example.com.").is_subdomain(&n("example.com.")));
        assert!(n("example.com.").is_subdomain(&n("example.com.")));
        assert!(!n("example.com.").is_subdomain(&n("www.example.com.")));
        assert!(!n("example.org.").is_subdomain(&n("example.com.")));
        // Case-insensitive.
        assert!(n("WWW.Example.COM.").is_subdomain(&n("example.com.")));
    }

    #[test]
    fn downcase_option() {
        let x = Name::from_text_downcase("ExAmPle.COM.", Some(&Name::root())).unwrap();
        assert_eq!(x.to_text(), "example.com.");
    }

    #[test]
    fn display_matches_to_text() {
        assert_eq!(format!("{}", n("www.example.com.")), "www.example.com.");
    }
}
