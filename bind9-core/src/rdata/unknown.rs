//! Generic unknown RDATA (RFC 3597): `\# <length> <hex>`.
//!
//! BIND renders any type it has no concrete implementation for (and any
//! truly unknown type number) in this generic form, and accepts it in input.
//! The wire form is opaque octets.

use crate::error::{Error, Result};
use crate::presentation::lexer::{resolve_escapes, Lexer, Token};
use crate::rrtype::RrType;

/// Decode one hex digit (BIND `isc_hex_char`), or None for non-hex.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Uppercase hex, exactly like BIND's `isc_hex_totext` ("0123456789ABCDEF").
fn to_hex_upper(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

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

    /// BIND's `unknown_fromtext` (rdata.c) after the `\#` marker: reads a
    /// length number token, then hex tokens.  Error semantics
    /// (oracle-verified): a non-number length is ISC_R_BADNUMBER; a length
    /// > 65535 is ISC_R_RANGE; a hex token with a non-hex character is
    /// DNS_R_BADHEX; a decoded byte past the declared length is
    /// ISC_R_NOSPACE; fewer octets than declared is ISC_R_UNEXPECTEDEND.
    /// (The meta-type rejection for type 0 and meta types happens in the
    /// caller — `Rdata::from_text`.)
    pub fn from_text(lex: &mut Lexer) -> Result<UnknownRdata> {
        let len_t = lex.next()?;
        if matches!(len_t, Token::Eof) {
            // BIND getmastertoken(number) at end-of-line.
            return Err(Error::UnexpectedEnd);
        }
        let len_b = len_t.bytes();
        if len_b.is_empty() || !len_b.iter().all(u8::is_ascii_digit) {
            return Err(Error::BadNumber);
        }
        let len_s = std::str::from_utf8(len_b).map_err(|_| Error::BadNumber)?;
        let len: usize = len_s.parse().map_err(|_| Error::Range)?;
        if len > 65535 {
            return Err(Error::Range);
        }
        let mut data = Vec::with_capacity(len);
        if len > 0 {
            // BIND: the hex tokens are read only for a nonzero declared
            // length (`if (token.value.as_ulong != 0U)`); a token after
            // `\# 0` is therefore left for the EXTRATOKEN check.
            let mut odd: Option<u8> = None;
            'tokens: loop {
                let t = lex.next()?;
                let raw = match &t {
                    Token::String(_) | Token::Quoted(_) => resolve_escapes(t.bytes())?,
                    Token::Eof => break 'tokens,
                    // BIND's loop also stops on eol tokens; no distinct
                    // Eol variant exists in this lexer.
                    _ => break 'tokens,
                };
                for &c in &raw {
                    let Some(v) = hex_nibble(c) else {
                        return Err(Error::BadHex);
                    };
                    match odd.take() {
                        Some(hi) => {
                            if data.len() >= len {
                                // BIND: a full byte beyond the declared
                                // length runs into the exactly-sized
                                // allocation.
                                return Err(Error::NoSpace);
                            }
                            data.push((hi << 4) | v);
                        }
                        None => odd = Some(v),
                    }
                }
            }
            if odd.is_some() {
                // BIND hex_decode_finish: odd digit count → DNS_R_BADHEX.
                return Err(Error::BadHex);
            }
        }
        if data.len() != len {
            // BIND: fewer octets than declared → ISC_R_UNEXPECTEDEND.
            return Err(Error::UnexpectedEnd);
        }
        Ok(UnknownRdata {
            type_: RrType::Unknown(0),
            data,
        })
    }

    /// Render as `\# <len> <hex>` (BIND `unknown_totext`): the hex digits
    /// are UPPERCASE (`isc_hex_totext`), and the trailing space appears
    /// only when there is data.
    #[must_use]
    pub fn to_text(&self) -> String {
        if self.data.is_empty() {
            return format!("\\# {}", self.data.len());
        }
        format!("\\# {} {}", self.data.len(), to_hex_upper(&self.data))
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
    fn totext_is_uppercase_and_no_trailing_space() {
        // Oracle-verified (WIRE-RDATA-0001): isc_hex_totext uses
        // "0123456789ABCDEF", and `\# 0` has no trailing space.
        let u = UnknownRdata::from_text(&mut lex(r"2 00ff")).unwrap();
        assert_eq!(u.to_text(), r"\# 2 00FF");
        let z = UnknownRdata::from_text(&mut lex(r"0")).unwrap();
        assert_eq!(z.to_text(), r"\# 0");
    }

    #[test]
    fn error_codes_match_bind() {
        // Oracle-verified error taxonomy (WIRE-RDATA-0001): non-number
        // length, out-of-range length, non-hex digit, odd digits, too many
        // bytes, too few bytes.
        assert_eq!(
            UnknownRdata::from_text(&mut lex("x 1")).map(|_| ()),
            Err(Error::BadNumber)
        );
        assert_eq!(
            UnknownRdata::from_text(&mut lex("65536")).map(|_| ()),
            Err(Error::Range)
        );
        assert_eq!(
            UnknownRdata::from_text(&mut lex("2 zz")).map(|_| ()),
            Err(Error::BadHex)
        );
        assert_eq!(
            UnknownRdata::from_text(&mut lex("2 0")).map(|_| ()),
            Err(Error::BadHex)
        );
        assert_eq!(
            UnknownRdata::from_text(&mut lex("2 010203")).map(|_| ()),
            Err(Error::NoSpace)
        );
        assert_eq!(
            UnknownRdata::from_text(&mut lex("4 0102")).map(|_| ()),
            Err(Error::UnexpectedEnd)
        );
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
