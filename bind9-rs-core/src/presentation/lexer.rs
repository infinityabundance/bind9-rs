//! The masterfile lexer, mirroring `isc_lex` + `isc_lex_getmastertoken`
//! (lib/isc/lex.c, 9.20.26) with the masterfile specials (`\0`, `(`, `)`,
//! `"`) and `ISC_LEXCOMMENT_DNSMASTERFILE` comments (lib/dns/master.c).
//!
//! Token semantics courted against the oracle (`ISC-LEX-0001`):
//! - `;` introduces a comment running to end of line;
//! - `(` and `)` group continuation; newlines inside a group are treated as
//!   whitespace (BIND's DNS multiline mode); groups nest; a stray `)` or an
//!   unclosed group at EOF is `ISC_R_UNBALANCED` ("unbalanced
//!   parentheses");
//! - quoted strings `"..."`: a `\"` inside resolves to a bare `"` (BIND
//!   overwrites the backslash), other escapes stay raw; a newline inside a
//!   quoted string is `ISC_R_UNBALANCEDQUOTES`; an unterminated string at
//!   EOF is `ISC_R_UNEXPECTEDEND`;
//! - unquoted tokens end at whitespace, `;`-comments, `(`, `)`, `"`, NUL,
//!   CR, LF, or EOF; `\` (with the ESCAPE option) makes the next character
//!   non-delimiting; a trailing backslash at EOF is
//!   `ISC_R_UNEXPECTEDEND`;
//! - a digit-starting token (with the NUMBER option) is a number; junk
//!   after the digits falls back to a string token; numeric overflow is
//!   `ISC_R_RANGE`.
//!
//! [`Lexer::next`] is the masterfile-friendly view used by the rdata
//! layer (EOL skipped, numbers as strings); [`Lexer::next_token`] exposes
//! the full tokenizer with explicit options.

use crate::error::{Error, Result};

/// A lexer token (the masterfile-friendly view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// An unquoted token, raw bytes (backslashes preserved).
    String(Vec<u8>),
    /// A quoted string, raw bytes (`\"` already resolved to `"`).
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

/// A token with its BIND type (the full tokenizer view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexToken {
    /// `isc_tokentype_string`: raw bytes.
    String(Vec<u8>),
    /// `isc_tokentype_qstring`: raw bytes with `\"` resolved.
    Quoted(Vec<u8>),
    /// `isc_tokentype_number`: the parsed value.
    Number(u32),
    /// `isc_tokentype_special`: the special character.
    Special(u8),
    /// `isc_tokentype_eol`.
    Eol,
    /// `isc_tokentype_eof`.
    Eof,
}

/// Tokenizer options (BIND `ISC_LEXOPT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LexOptions {
    /// `ISC_LEXOPT_EOL`: emit EOL tokens for newlines.
    pub eol: bool,
    /// `ISC_LEXOPT_EOF`: emit an EOF token at end of input.
    pub eof: bool,
    /// `ISC_LEXOPT_QSTRING`: recognize quoted strings.
    pub qstring: bool,
    /// `ISC_LEXOPT_NUMBER`: recognize numbers.
    pub number: bool,
    /// `ISC_LEXOPT_DNSMULTILINE`: handle `(`/`)` grouping.
    pub dns_multiline: bool,
    /// `ISC_LEXOPT_ESCAPE`: backslash escapes the next character.
    pub escape: bool,
}

impl LexOptions {
    /// The options `isc_lex_gettoken` runs with in the probe's `lex` mode.
    #[must_use]
    pub const fn all() -> Self {
        LexOptions {
            eol: true,
            eof: true,
            qstring: true,
            number: true,
            dns_multiline: true,
            escape: true,
        }
    }

    /// The options `isc_lex_getmastertoken(STRING, eol=true)` runs with.
    #[must_use]
    pub const fn master() -> Self {
        LexOptions {
            eol: true,
            eof: true,
            qstring: false,
            number: false,
            dns_multiline: true,
            escape: true,
        }
    }

    /// The options `isc_lex_getmastertoken(STRING, eol=true)` runs with,
    /// plus QSTRING — the rdata layer's view (character strings are quoted
    /// tokens there, but the NUMBER option stays off so digit runs keep
    /// their raw bytes).
    #[must_use]
    pub const fn master_qstring() -> Self {
        LexOptions {
            eol: true,
            eof: true,
            qstring: true,
            number: false,
            dns_multiline: true,
            escape: true,
        }
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

/// The masterfile specials (lib/dns/master.c): NUL, `(`, `)`, `"`.
fn is_special(c: u8) -> bool {
    c == 0 || c == b'(' || c == b')' || c == b'"'
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
    /// One-character pushback inside the tokenizer (BIND's
    /// `pushandgrow`/`pushback` on the source).
    pushback: Option<u8>,
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
            pushback: None,
        }
    }

    /// The next token, consuming whitespace/comments first (the
    /// masterfile-friendly view used by the rdata layer: EOL skipped,
    /// numbers stay raw string tokens).  This mirrors BIND's
    /// `isc_lex_getmastertoken` path, which runs without the NUMBER option
    /// (digits keep their raw bytes, e.g. `01020304` in `\#` RDATA), plus
    /// QSTRING for character strings.
    pub fn next(&mut self) -> Result<Token> {
        if let Some(t) = self.pushed_back.take() {
            return Ok(t);
        }
        loop {
            let t = self.next_token(LexOptions::master_qstring())?;
            match t {
                LexToken::String(b) => return Ok(Token::String(b)),
                LexToken::Quoted(b) => return Ok(Token::Quoted(b)),
                LexToken::Eol => continue,
                LexToken::Eof => return Ok(Token::Eof),
                // In the rdata view every special except ( ) " is
                // unreachable (NUL only appears in binary input); the
                // master-token path reports it as an unexpected token.
                LexToken::Special(_) | LexToken::Number(_) => return Err(Error::BadData),
            }
        }
    }

    /// The next token with explicit options (BIND `isc_lex_gettoken`).
    pub fn next_token(&mut self, options: LexOptions) -> Result<LexToken> {
        if let Some(c) = self.pushback.take() {
            return self.tokenize_from(c, options);
        }
        let c = self.read()?;
        self.tokenize_from(c, options)
    }

    /// The tokenizer state machine, given the first character (BIND's
    /// `lexstate_*` transitions).
    fn tokenize_from(&mut self, c0: u8, options: LexOptions) -> Result<LexToken> {
        let mut c = c0;
        loop {
            // Comments (DNSMASTERFILE: `;` to end of line).  The C checks
            // `!escaped && c == ';'` before the state switch; at the start
            // state the escape flag is always reset, so `;` always begins a
            // comment here (escaped `;` is consumed inside the string state).
            if c == b';' {
                self.eat_comment()?;
                c = match self.read()? {
                    EOF_SENTINEL => return self.at_eof(options),
                    c => c,
                };
                continue;
            }
            // End of input re-enters the start state (BIND's `at_eof` check
            // at the top of each call).
            if c == EOF_SENTINEL {
                return self.at_eof(options);
            }

            // Start state.
            if c == b' ' || c == b'\t' {
                c = match self.read()? {
                    EOF_SENTINEL => return self.at_eof(options),
                    c => c,
                };
                continue;
            }
            if c == b'\n' {
                // Inside parens (DNSMULTILINE) the C clears IWSEOL, so a
                // newline is whitespace, not an EOL token.
                if options.eol && self.paren_depth == 0 {
                    return Ok(LexToken::Eol);
                }
                c = match self.read()? {
                    EOF_SENTINEL => return self.at_eof(options),
                    c => c,
                };
                continue;
            }
            if c == b'\r' {
                if options.eol && self.paren_depth == 0 {
                    // lexstate_crlf: consume the following '\n' if present.
                    match self.read()? {
                        b'\n' => {}
                        EOF_SENTINEL => {}
                        other => self.pushback = Some(other),
                    }
                    return Ok(LexToken::Eol);
                }
                c = match self.read()? {
                    EOF_SENTINEL => return self.at_eof(options),
                    c => c,
                };
                continue;
            }
            if c == b'"' && options.qstring {
                return self.quoted_string(options);
            }
            if is_special(c) {
                if options.dns_multiline && (c == b'(' || c == b')') {
                    if c == b'(' {
                        self.paren_depth += 1;
                    } else if self.paren_depth == 0 {
                        return Err(Error::Unbalanced);
                    } else {
                        self.paren_depth -= 1;
                    }
                    c = match self.read()? {
                        EOF_SENTINEL => return self.at_eof(options),
                        c => c,
                    };
                    continue;
                }
                return Ok(LexToken::Special(c));
            }
            if c.is_ascii_digit() && options.number {
                return self.number_token(c, options);
            }
            return self.string_token(c, options);
        }
    }

    /// End-of-input handling (BIND's `lexstate_start` EOF branch).
    fn at_eof(&mut self, options: LexOptions) -> Result<LexToken> {
        if options.dns_multiline && self.paren_depth != 0 {
            self.paren_depth = 0;
            return Err(Error::Unbalanced);
        }
        if options.eof {
            Ok(LexToken::Eof)
        } else {
            Err(Error::Eof)
        }
    }

    /// `lexstate_number`.
    fn number_token(&mut self, first: u8, options: LexOptions) -> Result<LexToken> {
        let mut digits = Vec::new();
        digits.push(first);
        loop {
            let c = match self.read()? {
                EOF_SENTINEL => break,
                c => c,
            };
            if c == b';' {
                // DNSMASTERFILE comment; the escape flag is always false in
                // the number state, so `;` always begins a comment here
                // (BIND checks before the number state switches).
                self.eat_comment()?;
                continue;
            }
            if !c.is_ascii_digit() {
                if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' || is_special(c) {
                    // Delimiter: push back and parse the digits.
                    self.pushback = Some(c);
                    break;
                }
                // Junk after the digits: fall back to the string state.  The
                // junk byte is appended without touching the escape state
                // (BIND's number->string fall-through), so it is pre-appended
                // here and the string loop starts at the next character.
                digits.push(c);
                return self.string_continue(digits, None, options);
            }
            digits.push(c);
        }
        let text = String::from_utf8_lossy(&digits);
        match text.parse::<u32>() {
            Ok(n) => Ok(LexToken::Number(n)),
            Err(_) => Err(Error::Range),
        }
    }

    /// `lexstate_string` from the start state: the first character is
    /// re-processed by the string state (BIND's `goto no_read` after the
    /// transition), so a leading backslash sets the escape state.
    fn string_token(&mut self, first: u8, options: LexOptions) -> Result<LexToken> {
        self.string_continue(Vec::new(), Some(first), options)
    }

    /// `lexstate_string`: accumulate until a delimiter.  `pending` is a
    /// character already read (the string-state entry char); the number-junk
    /// path pre-appends its junk byte and passes `None`, since BIND appends
    /// that byte without touching the escape state.
    fn string_continue(
        &mut self,
        mut out: Vec<u8>,
        pending: Option<u8>,
        options: LexOptions,
    ) -> Result<LexToken> {
        let mut escaped = false;
        let mut pending = pending;
        loop {
            let c = match pending.take() {
                Some(c) => c,
                None => match self.read()? {
                    EOF_SENTINEL => {
                        if escaped {
                            return Err(Error::UnexpectedEnd);
                        }
                        return Ok(LexToken::String(out));
                    }
                    c => c,
                },
            };
            if !escaped && c == b';' {
                // DNSMASTERFILE comment: the C's comment check fires before
                // the string state, so `;` ends the token here (the comment
                // itself is consumed; the resuming newline stays a delimiter).
                self.eat_comment()?;
                continue;
            }
            if c == b'\r' || c == b'\n' || (!escaped && (c == b' ' || c == b'\t' || is_special(c)))
            {
                self.pushback = Some(c);
                return Ok(LexToken::String(out));
            }
            if options.escape {
                escaped = !escaped && c == b'\\';
            }
            out.push(c);
        }
    }

    /// `lexstate_qstring`.  The C never processes comments inside a quoted
    /// string (`no_comments` is set at entry); escape tracking is
    /// unconditional there, so the options are unused.
    fn quoted_string(&mut self, _options: LexOptions) -> Result<LexToken> {
        let mut out = Vec::new();
        let mut escaped = false;
        loop {
            let c = match self.read()? {
                EOF_SENTINEL => return Err(Error::UnexpectedEnd),
                c => c,
            };
            if c == b'"' {
                if escaped {
                    escaped = false;
                    // BIND overwrites the preceding backslash with the quote.
                    out.pop();
                    out.push(b'"');
                } else {
                    return Ok(LexToken::Quoted(out));
                }
            } else {
                if c == b'\n' && !escaped {
                    self.pushback = Some(c);
                    return Err(Error::UnbalancedQuotes);
                }
                if c == b'\\' && !escaped {
                    escaped = true;
                } else {
                    escaped = false;
                }
                out.push(c);
            }
        }
    }

    /// DNSMASTERFILE `;` comment: consume to end of line.  The terminating
    /// newline is pushed back so the resuming state sees it as a delimiter,
    /// mirroring BIND's eatline `goto no_read` re-processing of the newline.
    fn eat_comment(&mut self) -> Result<()> {
        loop {
            match self.read()? {
                b'\n' => {
                    self.pushback = Some(b'\n');
                    return Ok(());
                }
                EOF_SENTINEL => return Ok(()),
                _ => {}
            }
        }
    }

    fn read(&mut self) -> Result<u8> {
        if let Some(c) = self.pushback.take() {
            return Ok(c);
        }
        if self.pos >= self.src.len() {
            return Ok(EOF_SENTINEL);
        }
        let c = self.src[self.pos];
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Ok(c)
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

/// Sentinel returned by `read` at end of input.
const EOF_SENTINEL: u8 = 0xff;

/// Resolve masterfile escapes in a raw token, the way BIND consumers do:
/// `\DDD` (exactly three **decimal** digits, ≤ 255) and `\c` (literal `c`).
///
/// Used by name parsing and character-string parsing (the lexer itself only
/// resolves `\"` inside quoted strings).  Returns an error on a trailing
/// backslash or an incomplete digit sequence.
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
        // BIND resolves \" inside a quoted string to a bare ".
        assert_eq!(ts[1], Token::Quoted(b"with \" escape".to_vec()));
    }

    #[test]
    fn escapes_preserved_raw() {
        // The lexer does NOT resolve escapes outside quoted strings
        // (isc_lex semantics); it only keeps the token together.
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
    fn newline_in_quote_rejected() {
        let mut lx = Lexer::new(b"\"abc\ndef");
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

    #[test]
    fn number_tokens() {
        let mut lx = Lexer::new(b"42 42x 0x10 99999999999999999999");
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::Number(42)
        );
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"42x".to_vec())
        );
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"0x10".to_vec())
        );
        assert_eq!(lx.next_token(LexOptions::all()), Err(Error::Range));
    }

    #[test]
    fn eol_tokens() {
        let mut lx = Lexer::new(b"a\nb\n");
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"a".to_vec())
        );
        assert_eq!(lx.next_token(LexOptions::all()).unwrap(), LexToken::Eol);
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"b".to_vec())
        );
        assert_eq!(lx.next_token(LexOptions::all()).unwrap(), LexToken::Eol);
        assert_eq!(lx.next_token(LexOptions::all()).unwrap(), LexToken::Eof);
    }

    #[test]
    fn nul_is_special() {
        let mut lx = Lexer::new(b"x\x00y");
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"x".to_vec())
        );
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::Special(0)
        );
        assert_eq!(
            lx.next_token(LexOptions::all()).unwrap(),
            LexToken::String(b"y".to_vec())
        );
    }
}
