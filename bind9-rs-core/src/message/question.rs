//! The question section (RFC 1035 §4.1.2).
//!
//! BIND parses the question name with compression enabled and does not
//! compress it when rendering (court `RENDER-QUESTION-COMPRESSION`).

use crate::class::Class;
use crate::error::{Error, Result};
use crate::message::compression::Compressor;
use crate::name::Name;
use crate::rrtype::RrType;

/// A question: qname / qtype / qclass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: Name,
    pub qtype: RrType,
    pub qclass: Class,
}

impl Question {
    /// Parse from the wire at `pos`, returning the new position.
    pub fn from_wire(buf: &[u8], pos: usize) -> Result<(Question, usize)> {
        let fw = crate::name::wire::from_wire(buf, pos, true)?;
        if fw.consumed + 4 > buf.len() {
            return Err(Error::UnexpectedEnd);
        }
        let qtype = RrType::from_u16(u16::from_be_bytes([buf[fw.consumed], buf[fw.consumed + 1]]));
        let qclass = Class::from_u16(u16::from_be_bytes([
            buf[fw.consumed + 2],
            buf[fw.consumed + 3],
        ]));
        Ok((
            Question {
                qname: fw.name,
                qtype,
                qclass,
            },
            fw.consumed + 4,
        ))
    }

    /// Render; the qname is written uncompressed (BIND behavior).
    pub fn to_wire(&self, out: &mut Vec<u8>) {
        Compressor::render_uncompressed(&self.qname, out);
        out.extend_from_slice(&self.qtype.to_u16().to_be_bytes());
        out.extend_from_slice(&self.qclass.to_u16().to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;

    #[test]
    fn wire_roundtrip() {
        let q = Question {
            qname: Name::from_text("www.example.com.", Some(&Name::root())).unwrap(),
            qtype: RrType::A,
            qclass: Class::In,
        };
        let mut out = Vec::new();
        q.to_wire(&mut out);
        let (parsed, pos) = Question::from_wire(&out, 0).unwrap();
        assert_eq!(parsed, q);
        assert_eq!(pos, out.len());
    }

    #[test]
    fn truncated_rejected() {
        assert!(Question::from_wire(b"\x03www\x00", 0).is_err());
    }
}
