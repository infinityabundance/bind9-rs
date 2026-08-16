//! The DNS message header (RFC 1035 §4.1.1) with BIND's observable flag
//! handling (court `WIRE-HEADER-*`).

use crate::error::{Error, Result};
use crate::rcode::Rcode;

/// Message ID.
pub type Id = u16;

/// The 16-bit flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags {
    /// Query/response (bit 15).
    pub qr: bool,
    /// Opcode (bits 14-11).
    pub opcode: u8,
    /// Authoritative answer (bit 10).
    pub aa: bool,
    /// Truncated (bit 9).
    pub tc: bool,
    /// Recursion desired (bit 8).
    pub rd: bool,
    /// Recursion available (bit 7).
    pub ra: bool,
    /// Reserved Z (bit 6).  BIND rejects messages with Z set (court
    /// `WIRE-HEADER-ZBIT`).
    pub z: bool,
    /// Authenticated data (bit 5).
    pub ad: bool,
    /// Checking disabled (bit 4).
    pub cd: bool,
}

impl Flags {
    /// The 4-bit header rcode (the extended rcode travels in EDNS).
    #[must_use]
    pub fn header_rcode(&self, raw: u16) -> u8 {
        (raw & 0x000f) as u8
    }

    /// Build the 16-bit flags word from parts (used by the renderer).
    #[must_use]
    pub fn to_word(self, rcode_low: u8) -> u16 {
        let mut w: u16 = 0;
        if self.qr {
            w |= 0x8000;
        }
        w |= ((self.opcode as u16) & 0x0f) << 11;
        if self.aa {
            w |= 0x0400;
        }
        if self.tc {
            w |= 0x0200;
        }
        if self.rd {
            w |= 0x0100;
        }
        if self.ra {
            w |= 0x0080;
        }
        if self.z {
            w |= 0x0040;
        }
        if self.ad {
            w |= 0x0020;
        }
        if self.cd {
            w |= 0x0010;
        }
        w |= (rcode_low as u16) & 0x0f;
        w
    }

    /// Parse the flags word.
    #[must_use]
    pub fn from_word(w: u16) -> Self {
        Flags {
            qr: w & 0x8000 != 0,
            opcode: ((w >> 11) & 0x0f) as u8,
            aa: w & 0x0400 != 0,
            tc: w & 0x0200 != 0,
            rd: w & 0x0100 != 0,
            ra: w & 0x0080 != 0,
            z: w & 0x0040 != 0,
            ad: w & 0x0020 != 0,
            cd: w & 0x0010 != 0,
        }
    }
}

/// Parsed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: Id,
    pub flags: Flags,
    /// Raw 4-bit rcode from the flags word (extended via EDNS).
    pub rcode_low: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// Parse the 12-octet header.  Returns FORMERR if the input is shorter than
/// 12 octets (BIND's parser requires a full header before anything else).
pub fn parse(buf: &[u8]) -> Result<Header> {
    if buf.len() < 12 {
        return Err(Error::FormErr);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let w = u16::from_be_bytes([buf[2], buf[3]]);
    let flags = Flags::from_word(w);
    Ok(Header {
        id,
        flags,
        rcode_low: flags.header_rcode(w),
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
        nscount: u16::from_be_bytes([buf[8], buf[9]]),
        arcount: u16::from_be_bytes([buf[10], buf[11]]),
    })
}

/// Render the 12-octet header.
pub fn render(h: &Header, out: &mut Vec<u8>) {
    out.extend_from_slice(&h.id.to_be_bytes());
    out.extend_from_slice(&h.flags.to_word(h.rcode_low).to_be_bytes());
    out.extend_from_slice(&h.qdcount.to_be_bytes());
    out.extend_from_slice(&h.ancount.to_be_bytes());
    out.extend_from_slice(&h.nscount.to_be_bytes());
    out.extend_from_slice(&h.arcount.to_be_bytes());
}

/// Convenience: full rcode combining header and EDNS extended bits.
#[must_use]
pub fn full_rcode(header_low: u8, ext: u8) -> Rcode {
    Rcode::combine(header_low, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_render_roundtrip() {
        let mut out = Vec::new();
        let h = Header {
            id: 0x1234,
            flags: Flags {
                qr: true,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                z: false,
                ad: false,
                cd: false,
            },
            rcode_low: 0,
            qdcount: 1,
            ancount: 2,
            nscount: 0,
            arcount: 1,
        };
        render(&h, &mut out);
        assert_eq!(out.len(), 12);
        let parsed = parse(&out).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn truncation_rejected() {
        assert!(parse(&[0; 11]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn flag_bit_positions() {
        let w = Flags {
            qr: true,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
        }
        .to_word(0);
        assert_eq!(w, 0x8000);
        assert!(Flags::from_word(0x8000).qr);

        // Opcode 4 (NOTIFY) with QR.
        let w = Flags {
            qr: true,
            opcode: 4,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
        }
        .to_word(0);
        assert_eq!(w, 0x8000 | (4 << 11));
        assert_eq!(Flags::from_word(w).opcode, 4);
    }

    #[test]
    fn rcode_bits() {
        let w = Flags::default().to_word(3);
        assert_eq!(Flags::from_word(w).header_rcode(w), 3);
    }
}
