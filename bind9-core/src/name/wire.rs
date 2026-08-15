//! Wire-format parsing and rendering of names.
//!
//! Mirrors `dns_name_fromwire`/`dns_name_towire` (uncompressed form).
//! Compression-pointer resolution used by message parsing lives here too;
//! the *compressor* (pointer selection when rendering) lives in
//! [`crate::message::compression`].

use super::{Name, MAX_LABELS, MAX_WIRE};
use crate::error::{Error, Result};

/// Result of wire-parsing a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromWire {
    /// The parsed name.
    pub name: Name,
    /// Octets consumed in the source buffer, including any compression
    /// pointer (the name "ends" here even though labels continue via the
    /// pointer target).
    pub consumed: usize,
}

/// Error category for wire parsing, mapped onto BIND's observable results:
/// `DNS_R_FORMERR` for structural violations, `DNS_R_BADNAME` where BIND
/// distinguishes.  Courts `CORE-NAME-WIRE-*` pin these down per case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameWireError {
    /// Structural violation (label > 63, name > 255, bad pointer, ...).
    FormErr,
    /// Ran out of buffer.
    UnexpectedEnd,
    /// Empty label.
    EmptyLabel,
}

impl From<NameWireError> for Error {
    fn from(e: NameWireError) -> Self {
        match e {
            NameWireError::FormErr => Error::FormErr,
            NameWireError::UnexpectedEnd => Error::UnexpectedEnd,
            NameWireError::EmptyLabel => Error::FormErr,
        }
    }
}

/// Parse a possibly-compressed name from `buf` starting at `offset`.
///
/// BIND's rules encoded here (courts `CORE-NAME-WIRE-0001..`):
/// - labels are length-prefixed; a zero octet terminates the name;
/// - a compression pointer (top two bits `11`) redirects to an offset in the
///   low 14 bits, which must be **strictly less than the offset of the
///   pointer itself** (forward pointers are rejected — court
///   `CORE-NAME-WIRE-FORWARDPTR`);
/// - pointer chains are followed with loop protection (visited-set) and a
///   hard bound so hostile input cannot cause unbounded work (§4.2);
/// - the total name (labels + length octets + root) must not exceed 255
///   octets; a label may not exceed 63 octets.
///
/// When `allow_compression` is false (zone-file contexts), any pointer bits
/// in a label length octet are a format error.
pub fn from_wire(buf: &[u8], offset: usize, allow_compression: bool) -> Result<FromWire> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut total = 1usize; // root octet
    let mut consumed = offset;
    let mut pos = offset;
    let mut jumped = false;
    let mut visited: [bool; MAX_WIRE] = [false; MAX_WIRE];

    // BIND's "marker": the start of the current segment.  A compression
    // pointer must point strictly before the marker (RFC 1035 §4.1.4
    // "prior occurrence"; BIND rejects pointers into the current segment —
    // dns_name_fromwire: `if (pointer >= marker) return DNS_R_BADPOINTER`).
    let mut segment_start = offset;

    if offset >= buf.len() {
        return Err(Error::UnexpectedEnd);
    }

    loop {
        if pos >= buf.len() {
            return Err(Error::UnexpectedEnd);
        }
        if visited[pos] {
            return Err(Error::FormErr);
        }
        visited[pos] = true;
        let len = buf[pos];
        if len == 0 {
            // Root terminator.
            consumed = if jumped { consumed } else { pos + 1 };
            break;
        }
        if len & 0xc0 == 0xc0 {
            if !allow_compression {
                // BIND: DNS_R_DISALLOWED ("disallowed (by application
                // policy)") when the decompression context forbids it.
                return Err(Error::Disallowed);
            }
            // Compression pointer.
            if pos + 1 >= buf.len() {
                return Err(Error::UnexpectedEnd);
            }
            let target = (((len & 0x3f) as usize) << 8) | buf[pos + 1] as usize;
            // BIND: pointer must point strictly before the current segment
            // start (DNS_R_BADPOINTER, "bad compression pointer").
            if target >= segment_start {
                return Err(Error::BadPointer);
            }
            if !jumped {
                consumed = pos + 2;
                jumped = true;
            }
            pos = target;
            segment_start = target;
            continue;
        }
        if len & 0xc0 != 0 {
            // Reserved bits set (10 or 01 prefix) — not a valid label
            // length (BIND: DNS_R_BADLABELTYPE, "bad label type").
            return Err(Error::BadLabelType);
        }
        let end = pos + 1 + len as usize;
        if end > buf.len() {
            return Err(Error::UnexpectedEnd);
        }
        total += 1 + len as usize;
        if total > MAX_WIRE {
            // BIND: DNS_R_NAMETOOLONG ("name too long").
            return Err(Error::NameTooLong);
        }
        if labels.len() >= MAX_LABELS {
            return Err(Error::FormErr);
        }
        labels.push(&buf[pos + 1..end]);
        pos = end;
    }

    let data_len: usize = labels.iter().map(|l| l.len() + 1).sum();
    let mut data = Vec::with_capacity(data_len);
    for l in &labels {
        data.push(l.len() as u8);
        data.extend_from_slice(l);
    }
    let name = Name::from_wire_labels(data.into_boxed_slice(), true).map_err(|_| Error::FormErr)?;
    Ok(FromWire { name, consumed })
}

/// Append the uncompressed wire form of `name` to `out`.
///
/// Requires an absolute name; BIND refuses to render relative names on the
/// wire (`dns_name_towire` asserts `dns_name_isabsolute`).
pub fn to_wire_uncompressed(name: &Name, out: &mut Vec<u8>) -> Result<()> {
    if !name.is_absolute() {
        return Err(Error::InvalidArgument);
    }
    out.extend_from_slice(name.as_wire_slice());
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_roundtrip() {
        let n = Name::from_text("www.example.com.", Some(&Name::root())).unwrap();
        let mut wire = Vec::new();
        to_wire_uncompressed(&n, &mut wire).unwrap();
        assert_eq!(wire, b"\x03www\x07example\x03com\x00");
        let parsed = from_wire(&wire, 0, true).unwrap();
        assert_eq!(parsed.name, n);
        assert_eq!(parsed.consumed, wire.len());
    }

    #[test]
    fn root_wire() {
        let r = Name::root();
        let mut wire = Vec::new();
        to_wire_uncompressed(&r, &mut wire).unwrap();
        assert_eq!(wire, b"\x00");
        let parsed = from_wire(&wire, 0, true).unwrap();
        assert_eq!(parsed.name, r);
        assert_eq!(parsed.consumed, 1);
    }

    #[test]
    fn compression_basic() {
        // Message: "foo." at 0..5, then a pointer at 5 back to 0.
        let wire = b"\x03foo\x00\xc0\x00";
        let parsed = from_wire(wire, 5, true).unwrap();
        assert_eq!(
            parsed.name,
            Name::from_text("foo.", Some(&Name::root())).unwrap()
        );
        assert_eq!(parsed.consumed, 7);
    }

    #[test]
    fn pointer_chain() {
        // 0: \x01a \x01b \x01c \x00 (6 bytes); 7: \x01x \xc0\x02
        // (pointer to 2 → b.c); 11: \x01y \xc0\x04 (pointer to 4 → c).
        let wire = b"\x01a\x01b\x01c\x00\x01x\xc0\x02\x01y\xc0\x04";
        let parsed = from_wire(wire, 11, true).unwrap();
        assert_eq!(
            parsed.name,
            Name::from_text("y.c.", Some(&Name::root())).unwrap()
        );
        assert_eq!(parsed.consumed, 15);
    }

    #[test]
    fn forward_pointer_rejected() {
        // Pointer at offset 2 pointing forward to offset 4 (which is beyond
        // the pointer) — BIND: DNS_R_BADPOINTER.
        let wire = b"\x01a\xc0\x04\x01b\x00";
        assert_eq!(from_wire(wire, 0, true).map(|_| ()), Err(Error::BadPointer));
    }

    #[test]
    fn pointer_loop_rejected() {
        // Self-referential pointer: at offset 0, pointer to offset 0.
        let wire = b"\xc0\x00";
        assert_eq!(from_wire(wire, 0, true).map(|_| ()), Err(Error::BadPointer));

        // Two-pointer loop.
        let wire = b"\xc0\x02\xc0\x00";
        assert_eq!(from_wire(wire, 0, true).map(|_| ()), Err(Error::BadPointer));
    }

    #[test]
    fn reserved_length_rejected() {
        // Length octets 64..=191 are a reserved prefix (BIND:
        // DNS_R_BADLABELTYPE).  (A 64-octet wire label cannot exist: 0x40
        // is the 01 prefix.)
        let wire = b"\x40aaaa";
        assert_eq!(
            from_wire(wire, 0, true).map(|_| ()),
            Err(Error::BadLabelType)
        );
    }

    #[test]
    fn reserved_prefix_rejected() {
        let wire = b"\x80abc"; // 10 prefix
        assert_eq!(
            from_wire(wire, 0, true).map(|_| ()),
            Err(Error::BadLabelType)
        );
        let wire2 = b"\x40abc"; // 01 prefix
        assert_eq!(
            from_wire(wire2, 0, true).map(|_| ()),
            Err(Error::BadLabelType)
        );
    }

    #[test]
    fn truncated_rejected() {
        // Label claims 5 octets but only 2 remain.
        let wire = b"\x05ab";
        assert_eq!(
            from_wire(wire, 0, true).map(|_| ()),
            Err(Error::UnexpectedEnd)
        );
        // Pointer missing second octet.
        let wire2 = b"\xc0";
        assert_eq!(
            from_wire(wire2, 0, true).map(|_| ()),
            Err(Error::UnexpectedEnd)
        );
    }

    #[test]
    fn name_too_long_rejected() {
        // 4 labels of 63 octets each: 256 wire octets > 255 (BIND:
        // DNS_R_NAMETOOLONG).
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.push(63);
            wire.extend([b'a'; 63]);
        }
        wire.push(0);
        assert_eq!(
            from_wire(&wire, 0, true).map(|_| ()),
            Err(Error::NameTooLong)
        );
    }

    #[test]
    fn compression_rejected_when_disallowed() {
        // Pointer bytes are an error in zone-file (uncompressed) mode
        // (BIND: DNS_R_DISALLOWED): the label 'a' is followed by a pointer.
        let wire = b"\x01a\xc0\x00";
        assert_eq!(
            from_wire(wire, 0, false).map(|_| ()),
            Err(Error::Disallowed)
        );
        // A name that terminates before any pointer is fine either way.
        let wire2 = b"\x01a\x00";
        assert!(from_wire(wire2, 0, false).is_ok());
    }
}
