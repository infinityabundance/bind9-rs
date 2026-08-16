//! The masterfile lexer, mirroring `isc_lex` + `isc_lex_getmastertoken`.
//!
//! Token semantics courted against the oracle (`named-checkzone` behavior):
//! - `;` introduces a comment running to end of line;
//! - `(` and `)` group continuation; newlines inside a group are treated as
//!   whitespace (BIND's DNS multiline mode); groups nest; a stray `)` is
//!   `ISC_R_UNBALANCED`;
//! - quoted strings `"..."` (with `\"` allowed inside via the escape flag);
//! - **escapes are NOT resolved here**: like `isc_lex`, the lexer only
//!   tracks the escape flag so that specials after `\` are not delimiters,
//!   and the raw bytes (backslashes included) are returned in the token.
//!   The consumers resolve `\DDD` (decimal, three digits) and `\c`
//!   (`dns_name_fromtext`, `commatxt_fromtext` in rdata.c, ...);
//! - unquoted tokens end at whitespace, `;`, `(`, `)`, `"`, or EOL;
//! - positions (line, column) are tracked for diagnostics, which are a
//!   courted surface (`named-checkzone` error lines, §18).

use crate::error::{Error, Result};

/// A lexer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// An unquoted token, raw bytes (backslashes preserved).
    String(Vec<u8>),
    /// A quoted string, raw bytes (backslashes preserved).
    Quoted(Vec<u8>),
    /// End of input.
    Eof,
}

impl Token {
    /// The token bytes (both string forms); empty for EOF.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Token::String(b) | Token::Quoted(b) => b,
            Token::Eof => b"",
        }
    }

    /// True for EOF.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        matches!(self, Token::Eof)
    }
}

/// Position of a token for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// 1-based line.
    pub line: u32,
    /// 1-based column (in bytes).
    pub column: u32,
}

impl Position {
    #[must_use]
    pub const fn new(line: u32, column: u32) -> Self {
        Position { line, column }
    }
}

/// The masterfile lexer.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    column: u32,
    /// Paren nesting depth (BIND's `paren_count`); a newline inside parens
    /// is whitespace, not a token boundary.
    paren_depth: u32,
    /// Single-token pushback (BIND's `isc_lex_ungettoken`); the rdata
    /// layer peeks the first token to detect the `\#` generic form.
    pushed_back: Option<Token>,
}

impl<'a> Lexer<'a> {
    /// Create a lexer over `src`.
    #[must_use]
    pub fn new(src: &'a [u8]) -> Self {
        Lexer {
            src,
            pos: 0,
            line: 1,
            column: 1,
            paren_depth: 0,
            pushed_back: None,
        }
    }

    /// The next token, consuming whitespace/comments first.
    pub fn next(&mut self) -> Result<Token> {
        if let Some(t) = self.pushed_back.take() {
            return Ok(t);
        }
        loop {
            self.skip_whitespace()?;
            if self.pos >= self.src.len() {
                return Ok(Token::Eof);
            }
            let c = self.src[self.pos];
            match c {
                b';' => {
                    // Comment to end of line.
                    while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                        self.bump();
                    }
                    continue;
                }
                b'(' => {
                    self.bump();
                    self.paren_depth += 1;
                    continue;
                }
                b')' => {
                    if self.paren_depth == 0 {
                        // BIND: ISC_R_UNBALANCED.
                        return Err(Error::BadData);
                    }
                    self.bump();
                    self.paren_depth -= 1;
                    continue;
                }
                b'"' => return self.quoted_string(),
                _ => return self.unquoted_string(),
            }
        }
    }

    fn bump(&mut self) {
        if self.pos < self.src.len() {
            if self.src[self.pos] == b'\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.pos += 1;
        }
    }

    fn skip_whitespace(&mut self) -> Result<()> {
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c == b'\n' && self.paren_depth > 0 {
                // Newline inside a group: whitespace (multiline mode).
                self.bump();
            } else if c.is_ascii_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
        Ok(())
    }

    fn unquoted_string(&mut self) -> Result<Token> {
        let mut out = Vec::new();
        let mut escaped = false;
        loop {
            if self.pos >= self.src.len() {
                break;
            }
            let c = self.src[self.pos];
            if !escaped
                && (c.is_ascii_whitespace() || c == b';' || c == b'(' || c == b')' || c == b'"')
            {
                break;
            }
            if c == b'\\' && !escaped {
                escaped = true;
            } else {
                escaped = false;
            }
            out.push(c);
            self.bump();
        }
        if out.is_empty() {
            return Err(Error::BadData);
        }
        if escaped {
            // Trailing backslash at end of input: BIND returns
            // ISC_R_UNEXPECTEDEND from the tokenizer's escape handling.
            return Err(Error::UnexpectedEnd);
        }
        Ok(Token::String(out))
    }

    fn quoted_string(&mut self) -> Result<Token> {
        // Opening quote.
        self.bump();
        let mut out = Vec::new();
        let mut escaped = false;
        loop {
            if self.pos >= self.src.len() {
                // Unterminated string — BIND: ISC_R_UNEXPECTEDEND.
                return Err(Error::UnexpectedEnd);
            }
            let c = self.src[self.pos];
            if c == b'"' && !escaped {
                self.bump();
                break;
            }
            if c == b'\\' && !escaped {
                escaped = true;
            } else {
                escaped = false;
            }
            out.push(c);
            self.bump();
        }
        Ok(Token::Quoted(out))
    }

    /// Push a token back (single slot), mirroring `isc_lex_ungettoken`.
    pub fn unget(&mut self, t: Token) {
        assert!(self.pushed_back.is_none(), "lexer pushback slot full");
        self.pushed_back = Some(t);
    }

    /// Current position (line, column).
    #[must_use]
    pub const fn position(&self) -> Position {
        Position::new(self.line, self.column)
    }
}

/// Resolve masterfile escapes in a raw token, the way BIND consumers do:
/// `\DDD` (exactly three **decimal** digits, ≤ 255) and `\c` (literal `c`).
///
/// Used by name parsing and character-string parsing (the lexer itself does
/// not resolve escapes).  Returns an error on a trailing backslash or an
/// incomplete digit sequence.
pub fn resolve_escapes(raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'\\' {
            if i + 1 >= raw.len() {
                return Err(Error::UnexpectedEnd);
            }
            let next = raw[i + 1];
            if next.is_ascii_digit() {
                if i + 3 >= raw.len()
                    || !raw[i + 2].is_ascii_digit()
                    || !raw[i + 3].is_ascii_digit()
                {
                    return Err(Error::UnexpectedEnd);
                }
                let val = u16::from(next - b'0') * 100
                    + u16::from(raw[i + 2] - b'0') * 10
                    + u16::from(raw[i + 3] - b'0');
                if val > 255 {
                    return Err(Error::BadData);
                }
                out.push(val as u8);
                i += 4;
            } else {
                out.push(next);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex_all(src: &str) -> Vec<Token> {
        let mut lx = Lexer::new(src.as_bytes());
        let mut out = Vec::new();
        loop {
            let t = lx.next().unwrap();
            let done = t.is_eof();
            out.push(t);
            if done {
                break;
            }
        }
        out
    }

    fn bytes(t: &Token) -> Vec<u8> {
        t.bytes().to_vec()
    }

    #[test]
    fn simple_tokens() {
        let ts = lex_all("www example.com 3600 IN A 192.0.2.1");
        assert_eq!(bytes(&ts[0]), b"www");
        assert_eq!(bytes(&ts[1]), b"example.com");
        assert_eq!(bytes(&ts[2]), b"3600");
        assert_eq!(bytes(&ts[3]), b"IN");
        assert_eq!(bytes(&ts[4]), b"A");
        assert_eq!(bytes(&ts[5]), b"192.0.2.1");
        assert!(ts[6].is_eof());
    }

    #[test]
    fn comments() {
        let ts = lex_all("a ; comment here\nb ; another\n");
        assert_eq!(bytes(&ts[0]), b"a");
        assert_eq!(bytes(&ts[1]), b"b");
        assert!(ts[2].is_eof());
    }

    #[test]
    fn parens_group_lines() {
        let ts = lex_all("a (\n  b\n  c\n) d");
        assert_eq!(bytes(&ts[0]), b"a");
        assert_eq!(bytes(&ts[1]), b"b");
        assert_eq!(bytes(&ts[2]), b"c");
        assert_eq!(bytes(&ts[3]), b"d");
        assert!(ts[4].is_eof());
    }

    #[test]
    fn quoted_strings() {
        let ts = lex_all("\"hello world\" \"with \\\" escape\"");
        assert_eq!(ts[0], Token::Quoted(b"hello world".to_vec()));
        // The lexer keeps raw bytes; the consumer resolves the \" .
        assert_eq!(ts[1], Token::Quoted(b"with \\\" escape".to_vec()));
    }

    #[test]
    fn escapes_preserved_raw() {
        // The lexer does NOT resolve escapes (isc_lex semantics); it only
        // keeps the token together.  Consumers resolve them.
        let ts = lex_all(r"a\.b");
        assert_eq!(bytes(&ts[0]), br"a\.b");
        let ts = lex_all(r"\097");
        assert_eq!(bytes(&ts[0]), br"\097");
        // An escaped ';' stays inside the token.
        let ts = lex_all(r"a\;b");
        assert_eq!(bytes(&ts[0]), br"a\;b");
    }

    #[test]
    fn stray_paren_rejected() {
        let mut lx = Lexer::new(b")");
        assert!(lx.next().is_err());
    }

    #[test]
    fn unterminated_quote_rejected() {
        let mut lx = Lexer::new(b"\"abc");
        assert!(lx.next().is_err());
    }

    #[test]
    fn line_tracking() {
        let mut lx = Lexer::new(b"a\nb");
        let _ = lx.next().unwrap();
        let t = lx.next().unwrap();
        assert_eq!(bytes(&t), b"b");
        assert_eq!(lx.position().line, 2);
    }

    #[test]
    fn escape_resolution_decimal() {
        assert_eq!(resolve_escapes(br"\097").unwrap(), b"a");
        assert_eq!(resolve_escapes(br"\010").unwrap(), &[0x0a]);
        assert_eq!(resolve_escapes(br"a\.b").unwrap(), b"a.b");
        assert_eq!(resolve_escapes(br"a\;b").unwrap(), b"a;b");
        assert!(resolve_escapes(br"\999").is_err());
        assert!(resolve_escapes(br"\12").is_err());
        assert!(resolve_escapes(br"a\").is_err());
    }
}
