//! Generic unknown RDATA (RFC 3597): `\# <length> <hex>`.
//!
//! BIND renders any type it has no concrete implementation for (and any
//! truly unknown type number) in this generic form, and accepts it in input.
//! The wire form is opaque octets.

use crate::error::{Error, Result};
use crate::presentation::lexer::{resolve_escapes, Lexer, Token};
use crate::rrtype::RrType;
use crate::wire::hex::{from_hex, to_hex};

/// Unknown/generic RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRdata {
    type_: RrType,
    data: Vec<u8>,
}

impl UnknownRdata {
    /// The associated RR type (a known type with no concrete implementation,
    /// or a truly unknown type number).
    #[must_use]
    pub fn rrtype(&self) -> RrType {
        self.type_
    }

    /// The opaque octets.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn from_wire(buf: &[u8], pos: &mut usize, end: usize) -> Result<UnknownRdata> {
        if end < *pos {
            return Err(Error::FormErr);
        }
        let data = buf[*pos..end].to_vec();
        *pos = end;
        Ok(UnknownRdata {
            type_: RrType::Unknown(0), // set by caller via set_type
            data,
        })
    }

    /// Attach the type after generic parse (the caller knows it).
    #[must_use]
    pub fn with_type(mut self, type_: RrType) -> Self {
        self.type_ = type_;
        self
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.data);
        Ok(())
    }

    /// BIND's `unknown_fromtext` (rdata.c): reads a length number token,
    /// then hex tokens; the decoded length must equal the declared length.
    /// (The `\#` marker is checked by the caller — `dns_rdata_fromtext`.)
    pub fn from_text(lex: &mut Lexer) -> Result<UnknownRdata> {
        let len_t = lex.next()?;
        let len: usize = std::str::from_utf8(len_t.bytes())
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::BadData)?;
        if len > 65535 {
            return Err(Error::BadData);
        }
        let mut data = Vec::with_capacity(len);
        loop {
            let t = lex.next()?;
            match &t {
                Token::String(_) | Token::Quoted(_) => {}
                _ => break,
            }
            let raw = resolve_escapes(t.bytes())?;
            let decoded = from_hex(&raw).map_err(|_| Error::BadData)?;
            data.extend_from_slice(&decoded);
            if data.len() > len {
                return Err(Error::BadData);
            }
        }
        if data.len() != len {
            // BIND: ISC_R_UNEXPECTEDEND (fewer octets than declared).
            return Err(Error::UnexpectedEnd);
        }
        Ok(UnknownRdata {
            type_: RrType::Unknown(0),
            data,
        })
    }

    /// Render as `\# <len> <hex>` (BIND's `dns_rdata_unknown_totext`).
    #[must_use]
    pub fn to_text(&self) -> String {
        format!("\\# {} {}", self.data.len(), to_hex(&self.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::lexer::Lexer;

    fn lex(s: &str) -> Lexer<'_> {
        Lexer::new(s.as_bytes())
    }

    #[test]
    fn roundtrip() {
        // The `\#` marker is consumed by the rdata layer; this parser
        // starts at the length token.
        let u = UnknownRdata::from_text(&mut lex(r"4 01020304")).unwrap();
        assert_eq!(u.to_text(), r"\# 4 01020304");
        assert_eq!(u.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn length_mismatch_rejected() {
        assert!(UnknownRdata::from_text(&mut lex(r"5 01020304")).is_err());
    }

    #[test]
    fn bad_hex_rejected() {
        assert!(UnknownRdata::from_text(&mut lex(r"2 zz")).is_err());
    }
}
