//! Character-string RDATA: TXT (RFC 1035 §3.3.14) and SPF (RFC 7208).
//!
//! Wire form: a sequence of character-strings, each `length + octets` with
//! length ≤ 255.
//!
//! Text form (BIND `commatxt_fromtext`/`txt_totext` in rdata.c): each
//! string renders as a quoted string; parsing accepts both quoted and
//! unquoted tokens (one token per string) and resolves masterfile escapes
//! (`\DDD` decimal, `\c` literal) exactly like the other rdata consumers.
//! An empty TXT (no strings at all) is an error (`ISC_R_UNEXPECTEDEND`),
//! matching BIND's `generic_fromtext_txt`.

use super::escape_char_string;
use crate::error::{Error, Result};
use crate::presentation::lexer::{resolve_escapes, Lexer, Token};

/// TXT/SPF RDATA: one or more character-strings (each ≤ 255 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txt {
    strings: Vec<Vec<u8>>,
}

impl Txt {
    #[must_use]
    pub fn new(strings: Vec<Vec<u8>>) -> Result<Self> {
        for s in &strings {
            if s.len() > 255 {
                return Err(Error::MessageTooLong);
            }
        }
        Ok(Txt { strings })
    }

    #[must_use]
    pub fn strings(&self) -> &[Vec<u8>] {
        &self.strings
    }

    pub fn from_wire(buf: &[u8], pos: &mut usize, end: usize) -> Result<Txt> {
        let mut strings = Vec::new();
        while *pos < end {
            let len = buf[*pos] as usize;
            *pos += 1;
            if *pos + len > end {
                return Err(Error::UnexpectedEnd);
            }
            strings.push(buf[*pos..*pos + len].to_vec());
            *pos += len;
        }
        Self::new(strings)
    }

    pub fn to_wire(&self, out: &mut Vec<u8>) -> Result<()> {
        for s in &self.strings {
            out.push(s.len() as u8);
            out.extend_from_slice(s);
        }
        Ok(())
    }

    /// BIND's `generic_fromtext_txt`: one token per character-string;
    /// both quoted and unquoted tokens are accepted; escapes resolved.
    pub fn from_text(lex: &mut Lexer) -> Result<Txt> {
        let mut strings = Vec::new();
        loop {
            let t = lex.next()?;
            match &t {
                Token::String(_) | Token::Quoted(_) => {}
                _ => break,
            }
            strings.push(resolve_escapes(t.bytes())?);
        }
        if strings.is_empty() {
            // BIND: generic_fromtext_txt returns ISC_R_UNEXPECTEDEND when no
            // strings were read.
            return Err(Error::UnexpectedEnd);
        }
        Self::new(strings)
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (i, s) in self.strings.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&escape_char_string(s));
        }
        out
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
    fn empty_txt_is_error() {
        // BIND: generic_fromtext_txt with no strings → ISC_R_UNEXPECTEDEND.
        assert!(Txt::from_text(&mut lex("")).is_err());
    }

    #[test]
    fn escapes_roundtrip() {
        // `\"` resolves to a quote; `\d` resolves to a literal 'd'.
        let t = Txt::from_text(&mut lex(r#""a\"b" "c\d""#)).unwrap();
        assert_eq!(t.to_text(), r#""a\"b" "cd""#);
        let mut out = Vec::new();
        t.to_wire(&mut out).unwrap();
        assert_eq!(out, [3, b'a', b'"', b'b', 2, b'c', b'd']);
    }

    #[test]
    fn unquoted_accepted() {
        let t = Txt::from_text(&mut lex("hello")).unwrap();
        assert_eq!(t.to_text(), "\"hello\"");
    }

    #[test]
    fn max_string_length() {
        assert!(Txt::new(vec![vec![0u8; 255]]).is_ok());
        assert!(Txt::new(vec![vec![0u8; 256]]).is_err());
    }
}
