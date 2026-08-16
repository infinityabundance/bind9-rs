//! `compat::json_c` — json-c 0.19 conservation (§35).
//!
//! Native-Rust custodian implementation of the json-c parser (tokener),
//! object model, and serializer, not a serde-style JSON library:
//!
//! - the full tokener state machine (json_tokener.c): comments, single or
//!   double quoted strings, `\u` escapes with surrogate pairs and the
//!   U+FFFD replacement policy, case-insensitive null/true/false/NaN and
//!   Infinity/-Infinity (non-strict), the number state machine with its
//!   sign/exponent acceptance rules and the "123e+" trimming, `strtoll`/
//!   `strtoull`/`strtod` number conversion semantics (clamping + ERANGE),
//!   the nesting depth limit, and the exact error taxonomy;
//! - the object model with json-c's value semantics (int64/uint64 split,
//!   doubles that carry their original source text, string lengths that
//!   preserve embedded NULs, object keys truncated at the first NUL by
//!   strdup), insertion-ordered objects with replace-on-duplicate-key;
//! - the serializer (json_object.c json_object_to_json_string_ext):
//!   PLAIN/SPACED/PRETTY/PRETTY_TAB/NOZERO/NOSLASHESCAPE/COLOR flags, the
//!   `%.17g` double path with the ".0" append and NOZERO trimming, NaN/
//!   Infinity rendering, and the byte-level escaping.
//!
//! Every function maps to the pinned C source:
//! `forensics/sources/json-c-0.19.tar.gz` (workspace root).
//! Courts: JSON-* (C json-c oracle ↔ this module, byte-exact stdout).

// ---------------------------------------------------------------------------
// Constants (json_object.h, json_tokener.h)
// ---------------------------------------------------------------------------

pub const JSON_C_TO_STRING_PLAIN: u32 = 0;
pub const JSON_C_TO_STRING_SPACED: u32 = 1 << 0;
pub const JSON_C_TO_STRING_PRETTY: u32 = 1 << 1;
pub const JSON_C_TO_STRING_NOZERO: u32 = 1 << 2;
pub const JSON_C_TO_STRING_PRETTY_TAB: u32 = 1 << 3;
pub const JSON_C_TO_STRING_NOSLASHESCAPE: u32 = 1 << 4;
pub const JSON_C_TO_STRING_COLOR: u32 = 1 << 5;

pub const JSON_TOKENER_DEFAULT_DEPTH: i32 = 32;
pub const JSON_TOKENER_STRICT: u32 = 0x01;
pub const JSON_TOKENER_ALLOW_TRAILING_CHARS: u32 = 0x02;
pub const JSON_TOKENER_VALIDATE_UTF8: u32 = 0x10;

pub const JSON_TOKENER_SUCCESS: i32 = 0;
pub const JSON_TOKENER_CONTINUE: i32 = 1;
pub const JSON_TOKENER_ERROR_DEPTH: i32 = 2;
pub const JSON_TOKENER_ERROR_PARSE_EOF: i32 = 3;
pub const JSON_TOKENER_ERROR_PARSE_UNEXPECTED: i32 = 4;
pub const JSON_TOKENER_ERROR_PARSE_NULL: i32 = 5;
pub const JSON_TOKENER_ERROR_PARSE_BOOLEAN: i32 = 6;
pub const JSON_TOKENER_ERROR_PARSE_NUMBER: i32 = 7;
pub const JSON_TOKENER_ERROR_PARSE_ARRAY: i32 = 8;
pub const JSON_TOKENER_ERROR_PARSE_OBJECT_KEY_NAME: i32 = 9;
pub const JSON_TOKENER_ERROR_PARSE_OBJECT_KEY_SEP: i32 = 10;
pub const JSON_TOKENER_ERROR_PARSE_OBJECT_VALUE_SEP: i32 = 11;
pub const JSON_TOKENER_ERROR_PARSE_STRING: i32 = 12;
pub const JSON_TOKENER_ERROR_PARSE_COMMENT: i32 = 13;
pub const JSON_TOKENER_ERROR_PARSE_UTF8_STRING: i32 = 14;
pub const JSON_TOKENER_ERROR_SIZE: i32 = 15;
pub const JSON_TOKENER_ERROR_MEMORY: i32 = 16;

/// `json_tokener_error_desc` — the exact strings (json_tokener.c).
#[must_use]
pub fn json_tokener_error_desc(jerr: i32) -> &'static str {
    const ERRORS: [&str; 17] = [
        "success",
        "continue",
        "nesting too deep",
        "unexpected end of data",
        "unexpected character",
        "null expected",
        "boolean expected",
        "number expected",
        "array value separator ',' expected",
        "quoted object property name expected",
        "object property name separator ':' expected",
        "object value separator ',' expected",
        "invalid string sequence",
        "expected comment",
        "invalid utf-8 string",
        "buffer size overflow",
        "out of memory",
    ];
    if jerr < 0 || jerr as usize >= ERRORS.len() {
        return "Unknown error, invalid json_tokener_error value passed to json_tokener_error_desc()";
    }
    ERRORS[jerr as usize]
}

pub const ANSI_COLOR_RESET: &str = "\u{1b}[0m";
pub const ANSI_COLOR_FG_GREEN: &str = "\u{1b}[0;32m";
pub const ANSI_COLOR_FG_BLUE: &str = "\u{1b}[0;34m";
pub const ANSI_COLOR_FG_MAGENTA: &str = "\u{1b}[0;35m";

/// `json_c_version()` of the pinned release.
#[must_use]
pub const fn json_c_version() -> &'static str {
    "0.19"
}

pub const JSON_C_VERSION_NUM: i32 = 0x0013_00;

// ---------------------------------------------------------------------------
// The value model (json_object.c)
// ---------------------------------------------------------------------------

/// `json_type` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonType {
    Null,
    Boolean,
    Double,
    Int,
    Object,
    Array,
    String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Boolean(bool),
    /// int64 or uint64 (the C keeps them distinct; INT64_MAX+1..UINT64_MAX
    /// stays uint64)
    Int64(i64),
    Uint64(u64),
    /// double with its original source text when parsed from input
    /// (`json_object_new_double_s`), matching the serializer that prints the
    /// original text verbatim
    Double(f64, Option<Vec<u8>>),
    /// string bytes; length-preserving (embedded NULs survive) exactly like
    /// `json_object_new_string_len`
    String(Vec<u8>),
    Array(Vec<JsonValue>),
    /// insertion-ordered; duplicate keys replace the value in place
    Object(Vec<(Vec<u8>, JsonValue)>),
}

impl JsonValue {
    pub fn json_type(&self) -> JsonType {
        match self {
            JsonValue::Null => JsonType::Null,
            JsonValue::Boolean(_) => JsonType::Boolean,
            JsonValue::Int64(_) | JsonValue::Uint64(_) => JsonType::Int,
            JsonValue::Double(..) => JsonType::Double,
            JsonValue::String(_) => JsonType::String,
            JsonValue::Array(_) => JsonType::Array,
            JsonValue::Object(_) => JsonType::Object,
        }
    }
}

// ---------------------------------------------------------------------------
// Serializer (json_object.c json_object_to_json_string_ext)
// ---------------------------------------------------------------------------

const JSON_HEX_CHARS: &[u8; 22] = b"0123456789abcdefABCDEF";

fn indent_str(out: &mut Vec<u8>, level: usize, flags: u32) {
    if flags & JSON_C_TO_STRING_PRETTY != 0 {
        if flags & JSON_C_TO_STRING_PRETTY_TAB != 0 {
            for _ in 0..level {
                out.push(b'\t');
            }
        } else {
            for _ in 0..level * 2 {
                out.push(b' ');
            }
        }
    }
}

/// `json_escape_str` — byte-level escaping; note `json_hex_chars[c >> 4]`
/// indexes the LOW nibble first (the array is "0123456789abcdefABCDEF", so
/// nibbles 0-15 map to "0123456789abcdef", and 16-21 never occur).
fn json_escape_str(out: &mut Vec<u8>, str: &[u8], flags: u32) {
    let mut pos = 0usize;
    let mut start_offset = 0usize;
    while pos < str.len() {
        let c = str[pos];
        match c {
            b'\x08' | b'\n' | b'\r' | b'\t' | b'\x0c' | b'"' | b'\\' | b'/' => {
                if flags & JSON_C_TO_STRING_NOSLASHESCAPE != 0 && c == b'/' {
                    pos += 1;
                    continue;
                }
                if pos > start_offset {
                    out.extend_from_slice(&str[start_offset..pos]);
                }
                out.extend_from_slice(match c {
                    b'\x08' => b"\\b",
                    b'\n' => b"\\n",
                    b'\r' => b"\\r",
                    b'\t' => b"\\t",
                    b'\x0c' => b"\\f",
                    b'"' => b"\\\"",
                    b'\\' => b"\\\\",
                    _ => b"\\/",
                });
                pos += 1;
                start_offset = pos;
            }
            _ => {
                if c < b' ' {
                    if pos > start_offset {
                        out.extend_from_slice(&str[start_offset..pos]);
                    }
                    let mut sbuf = [0u8; 7];
                    sbuf[..4].copy_from_slice(b"\\u00");
                    sbuf[4] = JSON_HEX_CHARS[(c >> 4) as usize];
                    sbuf[5] = JSON_HEX_CHARS[(c & 0xf) as usize];
                    out.extend_from_slice(&sbuf[..6]);
                    pos += 1;
                    start_offset = pos;
                } else {
                    pos += 1;
                }
            }
        }
    }
    if pos > start_offset {
        out.extend_from_slice(&str[start_offset..pos]);
    }
}

/// C `%.17g` rendering with the json-c ".0" append and NOZERO trimming
/// (json_object.c json_object_double_to_json_string_format).
fn format_double(v: f64, flags: u32) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let mut buf = json_printf_g17(v);
    // json-c: ensure it looks like a float unless a custom format drops decimals
    if !buf.contains('.') && !buf.contains('e') && looks_numeric(&buf) {
        buf.push_str(".0");
    }
    if buf.contains('.') && flags & JSON_C_TO_STRING_NOZERO != 0 {
        // drop trailing zeroes, always keep one zero
        let p = buf.find('.').unwrap();
        let mut last_nonzero = p + 1;
        let mut q = p + 1;
        while q < buf.len() {
            if buf.as_bytes()[q] != b'0' {
                last_nonzero = q;
            }
            q += 1;
        }
        buf.truncate(last_nonzero + 1);
    }
    buf
}

fn looks_numeric(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_digit() || (b.len() > 1 && b[0] == b'-' && b[1].is_ascii_digit()))
}

/// glibc `%.17g`: 17 significant digits, %e style when the exponent is < -4
/// or >= 17, %f style otherwise, trailing zeros stripped.
pub fn json_printf_g17(v: f64) -> String {
    if v == 0.0 {
        // glibc %.17g prints "-0" for negative zero; json-c appends ".0"
        return if v.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }
    let negative = v < 0.0;
    let a = v.abs();
    // 16 digits after the point = 17 significant digits
    let s = format!("{a:.16e}");
    // s = "d.dddddddddddddddd e<exp>"
    let (mantissa, exp) = s.split_once('e').unwrap();
    let mut digits: Vec<u8> = mantissa.bytes().filter(|&b| b != b'.').collect();
    // strip trailing zeros (17 significant digits -> %g strips)
    while digits.len() > 1 && *digits.last().unwrap() == b'0' {
        digits.pop();
    }
    let x: i32 = exp.parse().unwrap();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if x < -4 || x >= 17 {
        // %e style: d.ddd e±XX (at least two exponent digits)
        out.push(digits[0] as char);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&String::from_utf8_lossy(&digits[1..]));
        }
        let sign = if x < 0 { '-' } else { '+' };
        out.push('e');
        out.push(sign);
        out.push_str(&format!("{:02}", x.abs()));
    } else if x < 0 {
        // %f style below 1: 0.00..ddd
        out.push('0');
        out.push('.');
        for _ in 0..(-x - 1) {
            out.push('0');
        }
        out.push_str(&String::from_utf8_lossy(&digits));
    } else {
        // %f style with (17 - 1 - x) decimals, trailing zeros stripped
        // digits represent d.ddd * 10^x
        let int_len = (x + 1) as usize; // digits before the point
        if int_len >= digits.len() {
            out.push_str(&String::from_utf8_lossy(&digits));
            for _ in digits.len()..int_len {
                out.push('0');
            }
        } else {
            out.push_str(&String::from_utf8_lossy(&digits[..int_len]));
            out.push('.');
            out.push_str(&String::from_utf8_lossy(&digits[int_len..]));
        }
    }
    out
}

fn serialize_object(out: &mut Vec<u8>, obj: &JsonValue, level: usize, flags: u32) {
    match obj {
        JsonValue::Null => {
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_FG_MAGENTA.as_bytes());
            }
            out.extend_from_slice(b"null");
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
            }
        }
        JsonValue::Boolean(b) => {
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_FG_MAGENTA.as_bytes());
            }
            out.extend_from_slice(if *b { b"true" } else { b"false" });
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
            }
        }
        JsonValue::Int64(v) => out.extend_from_slice(format!("{v}").as_bytes()),
        JsonValue::Uint64(v) => out.extend_from_slice(format!("{v}").as_bytes()),
        JsonValue::Double(v, orig) => match orig {
            Some(bytes) => out.extend_from_slice(bytes),
            None => out.extend_from_slice(format_double(*v, flags).as_bytes()),
        },
        JsonValue::String(s) => {
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_FG_GREEN.as_bytes());
            }
            out.push(b'"');
            json_escape_str(out, s, flags);
            out.push(b'"');
            if flags & JSON_C_TO_STRING_COLOR != 0 {
                out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
            }
        }
        JsonValue::Array(items) => {
            out.push(b'[');
            let mut had_children = false;
            for val in items {
                if had_children {
                    out.push(b',');
                }
                if flags & JSON_C_TO_STRING_PRETTY != 0 {
                    out.push(b'\n');
                }
                had_children = true;
                if flags & JSON_C_TO_STRING_SPACED != 0 && flags & JSON_C_TO_STRING_PRETTY == 0 {
                    out.push(b' ');
                }
                indent_str(out, level + 1, flags);
                match val {
                    JsonValue::Null => {
                        if flags & JSON_C_TO_STRING_COLOR != 0 {
                            out.extend_from_slice(ANSI_COLOR_FG_MAGENTA.as_bytes());
                        }
                        out.extend_from_slice(b"null");
                        if flags & JSON_C_TO_STRING_COLOR != 0 {
                            out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
                        }
                    }
                    _ => serialize_object(out, val, level + 1, flags),
                }
            }
            if flags & JSON_C_TO_STRING_PRETTY != 0 && had_children {
                out.push(b'\n');
                indent_str(out, level, flags);
            }
            if flags & JSON_C_TO_STRING_SPACED != 0 && flags & JSON_C_TO_STRING_PRETTY == 0 {
                out.extend_from_slice(b" ]");
            } else {
                out.push(b']');
            }
        }
        JsonValue::Object(entries) => {
            out.push(b'{');
            let mut had_children = false;
            for (key, val) in entries {
                if had_children {
                    out.push(b',');
                }
                if flags & JSON_C_TO_STRING_PRETTY != 0 {
                    out.push(b'\n');
                }
                had_children = true;
                if flags & JSON_C_TO_STRING_SPACED != 0 && flags & JSON_C_TO_STRING_PRETTY == 0 {
                    out.push(b' ');
                }
                indent_str(out, level + 1, flags);
                if flags & JSON_C_TO_STRING_COLOR != 0 {
                    out.extend_from_slice(ANSI_COLOR_FG_BLUE.as_bytes());
                }
                out.push(b'"');
                json_escape_str(out, key, flags);
                out.push(b'"');
                if flags & JSON_C_TO_STRING_COLOR != 0 {
                    out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
                }
                if flags & JSON_C_TO_STRING_SPACED != 0 {
                    out.extend_from_slice(b": ");
                } else {
                    out.push(b':');
                }
                match val {
                    JsonValue::Null => {
                        if flags & JSON_C_TO_STRING_COLOR != 0 {
                            out.extend_from_slice(ANSI_COLOR_FG_MAGENTA.as_bytes());
                        }
                        out.extend_from_slice(b"null");
                        if flags & JSON_C_TO_STRING_COLOR != 0 {
                            out.extend_from_slice(ANSI_COLOR_RESET.as_bytes());
                        }
                    }
                    _ => serialize_object(out, val, level + 1, flags),
                }
            }
            if flags & JSON_C_TO_STRING_PRETTY != 0 && had_children {
                out.push(b'\n');
                indent_str(out, level, flags);
            }
            if flags & JSON_C_TO_STRING_SPACED != 0 && flags & JSON_C_TO_STRING_PRETTY == 0 {
                out.extend_from_slice(b" }");
            } else {
                out.push(b'}');
            }
        }
    }
}

/// `json_object_to_json_string_ext(jso, flags)` — bytes, no NUL terminator.
#[must_use]
pub fn json_object_to_json_string_ext(v: &JsonValue, flags: u32) -> Vec<u8> {
    let mut out = Vec::new();
    serialize_object(&mut out, v, 0, flags);
    out
}

/// `json_object_to_json_string(jso)` — the default (SPACED).
#[must_use]
pub fn json_object_to_json_string(v: &JsonValue) -> Vec<u8> {
    json_object_to_json_string_ext(v, JSON_C_TO_STRING_SPACED)
}

// ---------------------------------------------------------------------------
// Tokener (json_tokener.c) — the state machine, faithfully ported
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum TState {
    Eatws,
    Start,
    Finish,
    Inf,
    Null,
    CommentStart,
    Comment,
    CommentEol,
    CommentEnd,
    String,
    StringEscape,
    EscapeUnicode,
    EscapeUnicodeNeedEscape,
    EscapeUnicodeNeedU,
    Boolean,
    Number,
    ArrayAfterSep,
    Array,
    ArrayAdd,
    ArraySep,
    ObjectFieldStart,
    ObjectFieldStartAfterSep,
    ObjectField,
    ObjectFieldEnd,
    ObjectValue,
    ObjectValueAdd,
    ObjectSep,
}

struct Srec {
    state: TState,
    saved_state: TState,
    current: Option<JsonValue>,
    obj_field_name: Option<Vec<u8>>,
}

impl Srec {
    fn new() -> Self {
        Srec {
            state: TState::Eatws,
            saved_state: TState::Start,
            current: None,
            obj_field_name: None,
        }
    }
}

fn is_ws_char(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
}

fn is_hex_char(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

fn jt_hexdigit(x: u8) -> u32 {
    if x <= b'9' {
        (x - b'0') as u32
    } else {
        ((x & 7) + 9) as u32
    }
}

const UTF8_REPLACEMENT_CHAR: [u8; 3] = [0xEF, 0xBF, 0xBD];

fn is_high_surrogate(uc: u32) -> bool {
    (uc & 0xFFFF_FC00) == 0xD800
}
fn is_low_surrogate(uc: u32) -> bool {
    (uc & 0xFFFF_FC00) == 0xDC00
}
fn decode_surrogate_pair(hi: u32, lo: u32) -> u32 {
    (((hi) & 0x3FF) << 10) + ((lo) & 0x3FF) + 0x10000
}

pub struct Tokener {
    depth: usize,
    max_depth: usize,
    err: i32,
    stack: Vec<Srec>,
    char_offset: usize,
    pb: Vec<u8>,
    st_pos: usize,
    quote_char: u8,
    is_double: bool,
    ucs_char: u32,
    high_surrogate: u32,
    flags: u32,
}

impl Tokener {
    pub fn new_ex(depth: i32) -> Option<Self> {
        if depth < 1 {
            return None;
        }
        Some(Tokener {
            depth: 0,
            max_depth: depth as usize,
            err: JSON_TOKENER_SUCCESS,
            stack: vec![Srec::new()],
            char_offset: 0,
            pb: Vec::new(),
            st_pos: 0,
            quote_char: b'"',
            is_double: false,
            ucs_char: 0,
            high_surrogate: 0,
            flags: 0,
        })
    }

    pub fn new() -> Self {
        Tokener::new_ex(JSON_TOKENER_DEFAULT_DEPTH).unwrap()
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    pub fn get_error(&self) -> i32 {
        self.err
    }

    pub fn get_parse_end(&self) -> usize {
        self.char_offset
    }

    fn reset_level(&mut self, depth: usize) {
        let s = &mut self.stack[depth];
        s.state = TState::Eatws;
        s.saved_state = TState::Start;
        s.current = None;
        s.obj_field_name = None;
    }

    fn reset(&mut self) {
        for i in (0..=self.depth).rev() {
            self.reset_level(i);
        }
        self.depth = 0;
        self.err = JSON_TOKENER_SUCCESS;
    }

    /// The C reads through the string's NUL terminator when len == -1; we
    /// append a sentinel NUL so peek always succeeds, and clamp to 0 beyond
    /// the buffer (the C reads past the end there — UB; 0 is the only sane
    /// bound, and no court corpus input reaches it; see JSONC-LORE-0001).
    fn peek(&self, input: &[u8]) -> u8 {
        if self.char_offset < input.len() {
            input[self.char_offset]
        } else {
            0
        }
    }

    /// ADVANCE_CHAR: move forward by one character.
    fn advance(&mut self) {
        self.char_offset += 1;
    }

    /// `json_tokener_parse_ex(tok, str, -1)` for a complete input.
    ///
    /// Faithful port of the json_tokener.c state machine with the len == -1
    /// contract: the NUL terminator is processed as a character, inner
    /// loops stop when the current char is 0 (the C's `!ADVANCE_CHAR`
    /// check, since ADVANCE returns the old char), and the `out:` label
    /// turns any error reached while c == 0 (with neither state nor
    /// saved_state being `finish`) into json_tokener_error_parse_eof.
    pub fn parse_ex(&mut self, input: &[u8]) -> Option<JsonValue> {
        // bytes plus a sentinel NUL (the C's own terminator)
        let mut bytes: Vec<u8> = input.to_vec();
        bytes.push(0);
        self.char_offset = 0;
        self.err = JSON_TOKENER_SUCCESS;
        let mut c: u8 = 0;
        let mut obj: Option<JsonValue> = None;

        // The C loop:
        //   while (PEEK_CHAR(c, tok)) { redo: switch(state) {...} ADVANCE; if (!c) break; }
        // `out:` handles error/EOF normalization.
        'outer: loop {
            c = self.peek(&bytes);
            'redo: loop {
                let state = self.stack[self.depth].state;
                match state {
                    TState::Eatws => {
                        while is_ws_char(c) {
                            self.advance();
                            if c == 0 {
                                break 'outer; // !ADVANCE_CHAR -> goto out
                            }
                            c = self.peek(&bytes);
                        }
                        if c == b'/' && self.flags & JSON_TOKENER_STRICT == 0 {
                            self.pb.clear();
                            self.pb.push(c);
                            self.stack[self.depth].state = TState::CommentStart;
                        } else {
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                            continue 'redo; // redo_char
                        }
                    }
                    TState::Start => match c {
                        b'{' => {
                            self.stack[self.depth].state = TState::Eatws;
                            self.stack[self.depth].saved_state = TState::ObjectFieldStart;
                            self.stack[self.depth].current = Some(JsonValue::Object(Vec::new()));
                        }
                        b'[' => {
                            self.stack[self.depth].state = TState::Eatws;
                            self.stack[self.depth].saved_state = TState::Array;
                            self.stack[self.depth].current = Some(JsonValue::Array(Vec::new()));
                        }
                        b'I' | b'i' => {
                            self.stack[self.depth].state = TState::Inf;
                            self.pb.clear();
                            self.st_pos = 0;
                            continue 'redo;
                        }
                        b'N' | b'n' => {
                            self.stack[self.depth].state = TState::Null;
                            self.pb.clear();
                            self.st_pos = 0;
                            continue 'redo;
                        }
                        b'\'' => {
                            if self.flags & JSON_TOKENER_STRICT != 0 {
                                self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
                                break 'outer;
                            }
                            self.stack[self.depth].state = TState::String;
                            self.pb.clear();
                            self.quote_char = c;
                        }
                        b'"' => {
                            self.stack[self.depth].state = TState::String;
                            self.pb.clear();
                            self.quote_char = c;
                        }
                        b'T' | b't' | b'F' | b'f' => {
                            self.stack[self.depth].state = TState::Boolean;
                            self.pb.clear();
                            self.st_pos = 0;
                            continue 'redo;
                        }
                        b'0'..=b'9' | b'-' => {
                            self.stack[self.depth].state = TState::Number;
                            self.pb.clear();
                            self.is_double = false;
                            continue 'redo;
                        }
                        _ => {
                            self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
                            break 'outer;
                        }
                    },
                    TState::Finish => {
                        if self.depth == 0 {
                            break 'outer;
                        }
                        obj = self.stack[self.depth].current.clone();
                        self.reset_level(self.depth);
                        self.depth -= 1;
                        continue 'redo;
                    }
                    TState::Inf => {
                        let mut is_negative = false;
                        while self.st_pos < b"Infinity".len() {
                            let inf_char = c;
                            let ok = inf_char == b"Infinity"[self.st_pos]
                                || (self.flags & JSON_TOKENER_STRICT == 0
                                    && inf_char == b"iNFINITY"[self.st_pos]);
                            if !ok {
                                self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
                                break 'outer;
                            }
                            self.st_pos += 1;
                            self.advance();
                            c = self.peek(&bytes);
                        }
                        if !self.pb.is_empty() && self.pb[0] == b'-' {
                            is_negative = true;
                        }
                        self.stack[self.depth].current = Some(JsonValue::Double(
                            if is_negative {
                                f64::NEG_INFINITY
                            } else {
                                f64::INFINITY
                            },
                            None,
                        ));
                        self.stack[self.depth].saved_state = TState::Finish;
                        self.stack[self.depth].state = TState::Eatws;
                        continue 'redo;
                    }
                    TState::Null => {
                        self.pb.push(c);
                        let size = (self.st_pos + 1).min(4);
                        let size_nan = (self.st_pos + 1).min(3);
                        let null_ok = if self.flags & JSON_TOKENER_STRICT == 0 {
                            self.pb[..size].eq_ignore_ascii_case(&b"null"[..size])
                        } else {
                            &self.pb[..size] == &b"null"[..size]
                        };
                        let nan_ok = if self.flags & JSON_TOKENER_STRICT == 0 {
                            self.pb[..size_nan].eq_ignore_ascii_case(&b"NaN"[..size_nan])
                        } else {
                            &self.pb[..size_nan] == &b"NaN"[..size_nan]
                        };
                        if null_ok {
                            if self.st_pos == 4 {
                                self.stack[self.depth].current = Some(JsonValue::Null);
                                self.stack[self.depth].saved_state = TState::Finish;
                                self.stack[self.depth].state = TState::Eatws;
                                continue 'redo;
                            }
                        } else if nan_ok {
                            if self.st_pos == 3 {
                                self.stack[self.depth].current =
                                    Some(JsonValue::Double(f64::NAN, None));
                                self.stack[self.depth].saved_state = TState::Finish;
                                self.stack[self.depth].state = TState::Eatws;
                                continue 'redo;
                            }
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_NULL;
                            break 'outer;
                        }
                        self.st_pos += 1;
                    }
                    TState::CommentStart => {
                        if c == b'*' {
                            self.stack[self.depth].state = TState::Comment;
                        } else if c == b'/' {
                            self.stack[self.depth].state = TState::CommentEol;
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_COMMENT;
                            break 'outer;
                        }
                        self.pb.push(c);
                    }
                    TState::Comment => {
                        let case_start = self.char_offset;
                        while c != b'*' {
                            self.advance();
                            if c == 0 {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                        self.pb
                            .extend_from_slice(&bytes[case_start..self.char_offset + 1]);
                        self.stack[self.depth].state = TState::CommentEnd;
                    }
                    TState::CommentEol => {
                        let case_start = self.char_offset;
                        while c != b'\n' {
                            self.advance();
                            if c == 0 {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                        self.pb
                            .extend_from_slice(&bytes[case_start..self.char_offset]);
                        self.stack[self.depth].state = TState::Eatws;
                    }
                    TState::CommentEnd => {
                        self.pb.push(c);
                        if c == b'/' {
                            self.stack[self.depth].state = TState::Eatws;
                        } else {
                            self.stack[self.depth].state = TState::Comment;
                        }
                    }
                    TState::String => {
                        let case_start = self.char_offset;
                        loop {
                            if c == self.quote_char {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                self.stack[self.depth].current =
                                    Some(JsonValue::String(self.pb.clone()));
                                self.stack[self.depth].saved_state = TState::Finish;
                                self.stack[self.depth].state = TState::Eatws;
                                break;
                            } else if c == b'\\' {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                self.stack[self.depth].saved_state = TState::String;
                                self.stack[self.depth].state = TState::StringEscape;
                                break;
                            } else if self.flags & JSON_TOKENER_STRICT != 0 && c <= 0x1f {
                                self.err = JSON_TOKENER_ERROR_PARSE_STRING;
                                break 'outer;
                            }
                            self.advance();
                            if c == 0 {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                    }
                    TState::StringEscape => match c {
                        b'"' | b'\\' | b'/' => {
                            self.pb.push(c);
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b'b' => {
                            self.pb.push(b'\x08');
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b'n' => {
                            self.pb.push(b'\n');
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b'r' => {
                            self.pb.push(b'\r');
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b't' => {
                            self.pb.push(b'\t');
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b'f' => {
                            self.pb.push(b'\x0c');
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                        }
                        b'u' => {
                            self.ucs_char = 0;
                            self.st_pos = 0;
                            self.stack[self.depth].state = TState::EscapeUnicode;
                        }
                        _ => {
                            self.err = JSON_TOKENER_ERROR_PARSE_STRING;
                            break 'outer;
                        }
                    },
                    TState::EscapeUnicode => {
                        loop {
                            if c == 0 || !is_hex_char(c) {
                                self.err = JSON_TOKENER_ERROR_PARSE_STRING;
                                break 'outer;
                            }
                            self.ucs_char |= jt_hexdigit(c) << ((3 - self.st_pos) * 4);
                            self.st_pos += 1;
                            if self.st_pos >= 4 {
                                break;
                            }
                            self.advance();
                            if c == 0 {
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                        self.st_pos = 0;
                        // process the completed \uNNNN (surrogates, utf8)
                        if self.high_surrogate != 0 {
                            if is_low_surrogate(self.ucs_char) {
                                self.ucs_char =
                                    decode_surrogate_pair(self.high_surrogate, self.ucs_char);
                            } else {
                                self.pb.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                            }
                            self.high_surrogate = 0;
                        }
                        if self.ucs_char < 0x80 {
                            self.pb.push(self.ucs_char as u8);
                        } else if self.ucs_char < 0x800 {
                            self.pb.push(0xc0 | (self.ucs_char >> 6) as u8);
                            self.pb.push(0x80 | (self.ucs_char & 0x3f) as u8);
                        } else if is_high_surrogate(self.ucs_char) {
                            self.high_surrogate = self.ucs_char;
                            self.ucs_char = 0;
                            self.stack[self.depth].state = TState::EscapeUnicodeNeedEscape;
                            // the C `break`s out of the switch here; do NOT
                            // fall through to the saved_state restore
                            break 'redo;
                        } else if is_low_surrogate(self.ucs_char) {
                            self.pb.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                        } else if self.ucs_char < 0x10000 {
                            self.pb.push(0xe0 | (self.ucs_char >> 12) as u8);
                            self.pb.push(0x80 | ((self.ucs_char >> 6) & 0x3f) as u8);
                            self.pb.push(0x80 | (self.ucs_char & 0x3f) as u8);
                        } else if self.ucs_char < 0x110000 {
                            self.pb.push(0xf0 | ((self.ucs_char >> 18) & 0x07) as u8);
                            self.pb.push(0x80 | ((self.ucs_char >> 12) & 0x3f) as u8);
                            self.pb.push(0x80 | ((self.ucs_char >> 6) & 0x3f) as u8);
                            self.pb.push(0x80 | (self.ucs_char & 0x3f) as u8);
                        } else {
                            self.pb.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                        }
                        self.stack[self.depth].state = self.stack[self.depth].saved_state;
                    }
                    TState::EscapeUnicodeNeedEscape => {
                        if c == 0 || c != b'\\' {
                            self.pb.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                            self.high_surrogate = 0;
                            self.ucs_char = 0;
                            self.st_pos = 0;
                            self.stack[self.depth].state = self.stack[self.depth].saved_state;
                            continue 'redo;
                        }
                        self.stack[self.depth].state = TState::EscapeUnicodeNeedU;
                    }
                    TState::EscapeUnicodeNeedU => {
                        if c == 0 || c != b'u' {
                            self.pb.extend_from_slice(&UTF8_REPLACEMENT_CHAR);
                            self.high_surrogate = 0;
                            self.ucs_char = 0;
                            self.st_pos = 0;
                            self.stack[self.depth].state = TState::StringEscape;
                            continue 'redo;
                        }
                        self.stack[self.depth].state = TState::EscapeUnicode;
                    }
                    TState::Boolean => {
                        self.pb.push(c);
                        let size1 = (self.st_pos + 1).min(4);
                        let size2 = (self.st_pos + 1).min(5);
                        let true_ok = if self.flags & JSON_TOKENER_STRICT == 0 {
                            self.pb[..size1].eq_ignore_ascii_case(&b"true"[..size1])
                        } else {
                            &self.pb[..size1] == &b"true"[..size1]
                        };
                        let false_ok = if self.flags & JSON_TOKENER_STRICT == 0 {
                            self.pb[..size2].eq_ignore_ascii_case(&b"false"[..size2])
                        } else {
                            &self.pb[..size2] == &b"false"[..size2]
                        };
                        if true_ok {
                            if self.st_pos == 4 {
                                self.stack[self.depth].current = Some(JsonValue::Boolean(true));
                                self.stack[self.depth].saved_state = TState::Finish;
                                self.stack[self.depth].state = TState::Eatws;
                                continue 'redo;
                            }
                        } else if false_ok {
                            if self.st_pos == 5 {
                                self.stack[self.depth].current = Some(JsonValue::Boolean(false));
                                self.stack[self.depth].saved_state = TState::Finish;
                                self.stack[self.depth].state = TState::Eatws;
                                continue 'redo;
                            }
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_BOOLEAN;
                            break 'outer;
                        }
                        self.st_pos += 1;
                    }
                    TState::Number => {
                        let case_start = self.char_offset;
                        let mut case_len = 0usize;
                        let mut is_exponent = false;
                        let mut neg_sign_ok = true;
                        let mut pos_sign_ok = false;
                        if !self.pb.is_empty() {
                            if let Some(e_loc) =
                                self.pb.iter().rposition(|&b| b == b'e' || b == b'E')
                            {
                                is_exponent = true;
                                pos_sign_ok = true;
                                neg_sign_ok = true;
                                if e_loc != self.pb.len() - 1 {
                                    neg_sign_ok = false;
                                    pos_sign_ok = false;
                                }
                            }
                        }
                        while c != 0
                            && ((b'0'..=b'9').contains(&c)
                                || (!is_exponent && (c == b'e' || c == b'E'))
                                || (neg_sign_ok && c == b'-')
                                || (pos_sign_ok && c == b'+')
                                || (!self.is_double && c == b'.'))
                        {
                            pos_sign_ok = false;
                            neg_sign_ok = false;
                            case_len += 1;
                            match c {
                                b'.' => {
                                    self.is_double = true;
                                    pos_sign_ok = true;
                                    neg_sign_ok = true;
                                }
                                b'e' | b'E' => {
                                    is_exponent = true;
                                    self.is_double = true;
                                    pos_sign_ok = true;
                                    neg_sign_ok = true;
                                }
                                _ => {}
                            }
                            self.advance();
                            if c == 0 {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..case_start + case_len]);
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                        if self.depth > 0
                            && c != b','
                            && c != b']'
                            && c != b'}'
                            && c != b'/'
                            && c != b'I'
                            && c != b'i'
                            && !is_ws_char(c)
                        {
                            self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                            break 'outer;
                        }
                        if case_len > 0 {
                            self.pb
                                .extend_from_slice(&bytes[case_start..case_start + case_len]);
                        }
                        if self.pb.first() == Some(&b'-')
                            && case_len <= 1
                            && (c == b'i' || c == b'I')
                        {
                            self.stack[self.depth].state = TState::Inf;
                            self.st_pos = 0;
                            continue 'redo;
                        }
                        if self.is_double && self.flags & JSON_TOKENER_STRICT == 0 {
                            while self.pb.len() > 1 {
                                let last = self.pb[self.pb.len() - 1];
                                if last != b'e' && last != b'E' && last != b'-' && last != b'+' {
                                    break;
                                }
                                self.pb.pop();
                            }
                        }
                        let buf = self.pb.clone();
                        let value: JsonValue;
                        if !self.is_double && buf.first() == Some(&b'-') {
                            match parse_strtoll(&buf) {
                                Some((v, erange)) => {
                                    if erange && self.flags & JSON_TOKENER_STRICT != 0 {
                                        self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                        break 'outer;
                                    }
                                    value = JsonValue::Int64(v);
                                }
                                None => {
                                    self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                    break 'outer;
                                }
                            }
                        } else if !self.is_double && buf.first() != Some(&b'-') {
                            match parse_strtoull(&buf) {
                                Some((v, erange)) => {
                                    if erange && self.flags & JSON_TOKENER_STRICT != 0 {
                                        self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                        break 'outer;
                                    }
                                    if v != 0
                                        && buf[0] == b'0'
                                        && self.flags & JSON_TOKENER_STRICT != 0
                                    {
                                        self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                        break 'outer;
                                    }
                                    if v <= i64::MAX as u64 {
                                        value = JsonValue::Int64(v as i64);
                                    } else {
                                        value = JsonValue::Uint64(v);
                                    }
                                }
                                None => {
                                    self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                    break 'outer;
                                }
                            }
                        } else if self.is_double {
                            match parse_strtod(&buf) {
                                Some(v) => {
                                    value = JsonValue::Double(v, Some(buf));
                                }
                                None => {
                                    self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                                    break 'outer;
                                }
                            }
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_NUMBER;
                            break 'outer;
                        }
                        self.stack[self.depth].current = Some(value);
                        self.stack[self.depth].saved_state = TState::Finish;
                        self.stack[self.depth].state = TState::Eatws;
                        continue 'redo;
                    }
                    TState::ArrayAfterSep | TState::Array => {
                        if c == b']' {
                            if self.stack[self.depth].state == TState::ArrayAfterSep
                                && self.flags & JSON_TOKENER_STRICT != 0
                            {
                                self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
                                break 'outer;
                            }
                            self.stack[self.depth].saved_state = TState::Finish;
                            self.stack[self.depth].state = TState::Eatws;
                        } else {
                            if self.depth >= self.max_depth - 1 {
                                self.err = JSON_TOKENER_ERROR_DEPTH;
                                break 'outer;
                            }
                            self.stack[self.depth].state = TState::ArrayAdd;
                            self.depth += 1;
                            if self.depth >= self.stack.len() {
                                self.stack.push(Srec::new());
                            }
                            self.reset_level(self.depth);
                            continue 'redo;
                        }
                    }
                    TState::ArrayAdd => {
                        if let (Some(JsonValue::Array(items)), Some(val)) =
                            (self.stack[self.depth].current.as_mut(), obj.as_ref())
                        {
                            items.push(val.clone());
                        } else if let Some(JsonValue::Array(items)) =
                            self.stack[self.depth].current.as_mut()
                        {
                            // the C's json_object_array_add(current, NULL)
                            // appends a NULL entry that serializes as null
                            items.push(JsonValue::Null);
                        }
                        self.stack[self.depth].saved_state = TState::ArraySep;
                        self.stack[self.depth].state = TState::Eatws;
                        continue 'redo;
                    }
                    TState::ArraySep => {
                        if c == b']' {
                            self.stack[self.depth].saved_state = TState::Finish;
                            self.stack[self.depth].state = TState::Eatws;
                        } else if c == b',' {
                            self.stack[self.depth].saved_state = TState::ArrayAfterSep;
                            self.stack[self.depth].state = TState::Eatws;
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_ARRAY;
                            break 'outer;
                        }
                    }
                    TState::ObjectFieldStart | TState::ObjectFieldStartAfterSep => {
                        if c == b'}' {
                            if self.stack[self.depth].state == TState::ObjectFieldStartAfterSep
                                && self.flags & JSON_TOKENER_STRICT != 0
                            {
                                self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
                                break 'outer;
                            }
                            self.stack[self.depth].saved_state = TState::Finish;
                            self.stack[self.depth].state = TState::Eatws;
                        } else if c == b'"' || c == b'\'' {
                            self.quote_char = c;
                            self.pb.clear();
                            self.stack[self.depth].state = TState::ObjectField;
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_OBJECT_KEY_NAME;
                            break 'outer;
                        }
                    }
                    TState::ObjectField => {
                        let case_start = self.char_offset;
                        loop {
                            if c == self.quote_char {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                // strdup truncates the key at the first NUL
                                let end = self
                                    .pb
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(self.pb.len());
                                self.stack[self.depth].obj_field_name =
                                    Some(self.pb[..end].to_vec());
                                self.stack[self.depth].saved_state = TState::ObjectFieldEnd;
                                self.stack[self.depth].state = TState::Eatws;
                                break;
                            } else if c == b'\\' {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                self.stack[self.depth].saved_state = TState::ObjectField;
                                self.stack[self.depth].state = TState::StringEscape;
                                break;
                            } else if self.flags & JSON_TOKENER_STRICT != 0 && c <= 0x1f {
                                self.err = JSON_TOKENER_ERROR_PARSE_STRING;
                                break 'outer;
                            }
                            self.advance();
                            if c == 0 {
                                self.pb
                                    .extend_from_slice(&bytes[case_start..self.char_offset]);
                                break 'outer;
                            }
                            c = self.peek(&bytes);
                        }
                    }
                    TState::ObjectFieldEnd => {
                        if c == b':' {
                            self.stack[self.depth].saved_state = TState::ObjectValue;
                            self.stack[self.depth].state = TState::Eatws;
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_OBJECT_KEY_SEP;
                            break 'outer;
                        }
                    }
                    TState::ObjectValue => {
                        if self.depth >= self.max_depth - 1 {
                            self.err = JSON_TOKENER_ERROR_DEPTH;
                            break 'outer;
                        }
                        self.stack[self.depth].state = TState::ObjectValueAdd;
                        self.depth += 1;
                        if self.depth >= self.stack.len() {
                            self.stack.push(Srec::new());
                        }
                        self.reset_level(self.depth);
                        continue 'redo;
                    }
                    TState::ObjectValueAdd => {
                        let key = self.stack[self.depth].obj_field_name.take();
                        if let (Some(JsonValue::Object(entries)), Some(key)) =
                            (self.stack[self.depth].current.as_mut(), key)
                        {
                            let val = obj.clone().unwrap_or(JsonValue::Null);
                            match entries.iter_mut().find(|(k, _)| *k == key) {
                                Some((_, v)) => *v = val,
                                None => entries.push((key, val)),
                            }
                        }
                        self.stack[self.depth].saved_state = TState::ObjectSep;
                        self.stack[self.depth].state = TState::Eatws;
                        continue 'redo;
                    }
                    TState::ObjectSep => {
                        if c == b'}' {
                            self.stack[self.depth].saved_state = TState::Finish;
                            self.stack[self.depth].state = TState::Eatws;
                        } else if c == b',' {
                            self.stack[self.depth].saved_state = TState::ObjectFieldStartAfterSep;
                            self.stack[self.depth].state = TState::Eatws;
                        } else {
                            self.err = JSON_TOKENER_ERROR_PARSE_OBJECT_VALUE_SEP;
                            break 'outer;
                        }
                    }
                }
                break 'redo;
            }
            // end of the switch: ADVANCE_CHAR; if (!c) break;
            self.advance();
            if c == 0 {
                break 'outer;
            }
        }

        // out: label
        if c != 0
            && self.stack[0].state == TState::Finish
            && self.depth == 0
            && (self.flags & (JSON_TOKENER_STRICT | JSON_TOKENER_ALLOW_TRAILING_CHARS))
                == JSON_TOKENER_STRICT
        {
            self.err = JSON_TOKENER_ERROR_PARSE_UNEXPECTED;
        }
        if c == 0 {
            let s = self.stack[self.depth].state;
            let ss = self.stack[self.depth].saved_state;
            if s != TState::Finish && ss != TState::Finish {
                self.err = JSON_TOKENER_ERROR_PARSE_EOF;
            }
        }

        if self.err == JSON_TOKENER_SUCCESS {
            let ret = self.stack[0].current.clone();
            self.reset();
            return ret;
        }
        None
    }
}

/// `strtoll` semantics for the number buffer (json_util.c json_parse_int64):
/// optional sign, decimal digits, overflow clamps to i64::MAX/MIN with
/// ERANGE; no digits -> error.
fn parse_strtoll(buf: &[u8]) -> Option<(i64, bool)> {
    let mut i = 0usize;
    let mut negative = false;
    if i < buf.len() && (buf[i] == b'+' || buf[i] == b'-') {
        negative = buf[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut val: i64 = 0;
    let mut overflow = false;
    while i < buf.len() && buf[i].is_ascii_digit() {
        let d = (buf[i] - b'0') as i64;
        let next = if negative {
            val.checked_mul(10).and_then(|v| v.checked_sub(d))
        } else {
            val.checked_mul(10).and_then(|v| v.checked_add(d))
        };
        match next {
            Some(v) => val = v,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return None; // end == buf
    }
    if overflow {
        return Some((if negative { i64::MIN } else { i64::MAX }, true));
    }
    Some((val, false))
}

/// `strtoull` semantics (json_parse_uint64): skips spaces, rejects '-',
/// digits, overflow clamps to u64::MAX with ERANGE.
fn parse_strtoull(buf: &[u8]) -> Option<(u64, bool)> {
    let mut i = 0usize;
    while i < buf.len() && buf[i] == b' ' {
        i += 1;
    }
    if i < buf.len() && buf[i] == b'-' {
        return None;
    }
    let start = i;
    let mut val: u64 = 0;
    let mut overflow = false;
    while i < buf.len() && buf[i].is_ascii_digit() {
        let d = (buf[i] - b'0') as u64;
        match val.checked_mul(10).and_then(|v| v.checked_add(d)) {
            Some(v) => val = v,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return None;
    }
    if overflow {
        return Some((u64::MAX, true));
    }
    Some((val, false))
}

/// `strtod` semantics for the number buffer (json_tokener_parse_double):
/// the whole buffer must be consumed; overflow yields infinities (ERANGE
/// does not fail the parse in the non-strict default).
fn parse_strtod(buf: &[u8]) -> Option<f64> {
    let s = std::str::from_utf8(buf).ok()?;
    s.parse::<f64>().ok()
}

/// `json_tokener_parse_verbose(str)` — returns (value, error).
pub fn json_tokener_parse_verbose(input: &str) -> (Option<JsonValue>, i32) {
    let mut tok = Tokener::new();
    let obj = tok.parse_ex(input.as_bytes());
    let err = tok.err;
    if err != JSON_TOKENER_SUCCESS {
        return (None, err);
    }
    (obj, err)
}

/// `json_tokener_parse(str)`.
pub fn json_tokener_parse(input: &str) -> Option<JsonValue> {
    json_tokener_parse_verbose(input).0
}

/// `json_tokener_parse_ex` with tokener flags (STRICT etc.) and a custom
/// depth.
pub fn json_tokener_parse_ex(input: &str, flags: u32, depth: i32) -> (Option<JsonValue>, i32) {
    let mut tok = Tokener::new_ex(depth).unwrap();
    tok.set_flags(flags);
    let obj = tok.parse_ex(input.as_bytes());
    let err = tok.err;
    if err != JSON_TOKENER_SUCCESS {
        return (None, err);
    }
    (obj, err)
}

// ---------------------------------------------------------------------------
// Programmatic constructors (json_object.c)
// ---------------------------------------------------------------------------

pub fn json_object_new_boolean(b: bool) -> JsonValue {
    JsonValue::Boolean(b)
}

pub fn json_object_new_int64(v: i64) -> JsonValue {
    JsonValue::Int64(v)
}

pub fn json_object_new_uint64(v: u64) -> JsonValue {
    JsonValue::Uint64(v)
}

pub fn json_object_new_double(d: f64) -> JsonValue {
    JsonValue::Double(d, None)
}

pub fn json_object_new_string(s: &[u8]) -> JsonValue {
    JsonValue::String(s.to_vec())
}

pub fn json_object_new_object() -> JsonValue {
    JsonValue::Object(Vec::new())
}

pub fn json_object_new_array() -> JsonValue {
    JsonValue::Array(Vec::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> String {
        let (v, err) = json_tokener_parse_verbose(s);
        match v {
            Some(v) => String::from_utf8_lossy(&json_object_to_json_string(&v)).into_owned(),
            None => format!("ERR:{}", json_tokener_error_desc(err)),
        }
    }

    #[test]
    fn error_descs() {
        assert_eq!(json_tokener_error_desc(0), "success");
        assert_eq!(json_tokener_error_desc(2), "nesting too deep");
        assert_eq!(json_tokener_error_desc(3), "unexpected end of data");
        assert_eq!(json_tokener_error_desc(16), "out of memory");
        assert_eq!(
            json_tokener_error_desc(99),
            "Unknown error, invalid json_tokener_error value passed to json_tokener_error_desc()"
        );
    }

    #[test]
    fn scalars() {
        assert_eq!(p("null"), "null");
        assert_eq!(p("true"), "true");
        assert_eq!(p("false"), "false");
        assert_eq!(p("TRUE"), "true");
        assert_eq!(p("FALSE"), "false");
        assert_eq!(p("Null"), "null");
        assert_eq!(p("123"), "123");
        assert_eq!(p("-123"), "-123");
        assert_eq!(p("1.5"), "1.5");
        assert_eq!(p("1e10"), "1e10");
        assert_eq!(p("-1.5e-3"), "-1.5e-3");
        assert_eq!(p("9223372036854775807"), "9223372036854775807");
        assert_eq!(p("9223372036854775808"), "9223372036854775808");
        assert_eq!(p("18446744073709551615"), "18446744073709551615");
        // 2^64 overflows strtoull -> clamped to u64::MAX non-strict
        assert_eq!(p("18446744073709551616"), "18446744073709551615");
        assert_eq!(p("NaN"), "NaN");
        assert_eq!(p("Infinity"), "Infinity");
        assert_eq!(p("-Infinity"), "-Infinity");
        assert_eq!(p("iNFINITY"), "Infinity");
    }

    #[test]
    fn errors() {
        // oracle-pinned: any error reached at the NUL terminator (c == 0)
        // with neither state being finish becomes EOF (out: overwrite)
        assert_eq!(p("nul"), "ERR:unexpected end of data");
        assert_eq!(p("nuX"), "ERR:null expected");
        assert_eq!(p("tru"), "ERR:unexpected end of data");
        assert_eq!(p("truX"), "ERR:boolean expected");
        assert_eq!(p("01"), "1"); // leading zeros accepted non-strict
        assert_eq!(p("[1,"), "ERR:unexpected end of data");
        assert_eq!(p("[1,]"), "[ 1 ]"); // trailing comma tolerated non-strict
        assert_eq!(p("[,1]"), "ERR:unexpected character");
        assert_eq!(p("{"), "ERR:unexpected end of data");
        assert_eq!(p("{a:1}"), "ERR:quoted object property name expected");
        assert_eq!(
            p("{\"a\" 1}"),
            "ERR:object property name separator ':' expected"
        );
        assert_eq!(
            p("{\"a\":1 \"b\":2}"),
            "ERR:object value separator ',' expected"
        );
        assert_eq!(p("[1 2]"), "ERR:array value separator ',' expected");
        assert_eq!(p("\"a\\q\""), "ERR:invalid string sequence");
        assert_eq!(p("/* x"), "ERR:unexpected end of data");
        assert_eq!(p("/x"), "ERR:expected comment");
    }

    #[test]
    fn strict_mode() {
        // leading zeros rejected in strict (error at the NUL -> EOF)
        let (v, err) = json_tokener_parse_ex("01", JSON_TOKENER_STRICT, 32);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_PARSE_EOF);
        // "1e+" (no trim in strict) likewise becomes EOF
        let (v, err) = json_tokener_parse_ex("1e+", JSON_TOKENER_STRICT, 32);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_PARSE_EOF);
        // trailing chars rejected in strict
        let (v, err) = json_tokener_parse_ex("1 2", JSON_TOKENER_STRICT, 32);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_PARSE_UNEXPECTED);
        // single quotes rejected in strict
        let (v, err) = json_tokener_parse_ex("'a'", JSON_TOKENER_STRICT, 32);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_PARSE_UNEXPECTED);
        // NaN is accepted in strict (exact-match strncmp, oracle-pinned)
        let (v, err) = json_tokener_parse_ex("NaN", JSON_TOKENER_STRICT, 32);
        assert_eq!(err, JSON_TOKENER_SUCCESS);
        assert!(matches!(v, Some(JsonValue::Double(d, _)) if d.is_nan()));
        // comments rejected in strict
        let (v, err) = json_tokener_parse_ex("/*x*/1", JSON_TOKENER_STRICT, 32);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_PARSE_UNEXPECTED);
        // strict accepts Infinity (exact case)
        let (v, err) = json_tokener_parse_ex("Infinity", JSON_TOKENER_STRICT, 32);
        assert_eq!(err, JSON_TOKENER_SUCCESS);
        assert!(v.is_some());
    }

    #[test]
    fn nonstrict_quirks() {
        // "1e+" trimmed to "1" (double)
        assert_eq!(p("1e+"), "1");
        // trailing garbage tolerated at top level (non-strict)
        assert_eq!(p("123abc"), "123");
        assert_eq!(p("nullx"), "null");
        // comments
        assert_eq!(p("/* hi */1"), "1");
        assert_eq!(p("// hi\n1"), "1");
        assert_eq!(p("1/*x*/2"), "1"); // top-level scalar wins; rest ignored
                                       // single-quoted strings
        assert_eq!(p("'abc'"), "\"abc\"");
        // hex/octal/leading zeros accepted non-strict as numbers
        assert_eq!(p("01"), "1");
        // number termination error inside containers
        assert_eq!(p("[12x]"), "ERR:number expected");
    }

    #[test]
    fn escapes_and_unicode() {
        assert_eq!(p("\"a\\nb\""), "\"a\\nb\"");
        assert_eq!(p("\"a\\tb\""), "\"a\\tb\"");
        assert_eq!(p("\"a\\/b\""), "\"a\\/b\"");
        assert_eq!(p("\"\\u0041\""), "\"A\"");
        assert_eq!(p("\"\\u00e9\""), "\"\u{00e9}\"");
        // surrogate pair
        assert_eq!(p("\"\\ud83d\\ude00\""), "\"\u{1f600}\"");
        // lone high surrogate -> replacement char
        assert_eq!(p("\"\\ud83d\""), "\"\u{fffd}\"");
        // lone low surrogate -> replacement char
        assert_eq!(p("\"\\ude00\""), "\"\u{fffd}\"");
        // embedded NUL via escape survives in the value
        assert_eq!(p("\"a\\u0000b\""), "\"a\\u0000b\"");
    }

    #[test]
    fn nesting_depth() {
        // max_depth 32: the push check is depth >= max_depth - 1, so 32
        // nested arrays are accepted and 33 hit the limit (oracle-pinned)
        let ok = "[".repeat(32) + &"]".repeat(32);
        assert!(json_tokener_parse(&ok).is_some());
        let deep = "[".repeat(33) + &"]".repeat(33);
        let (v, err) = json_tokener_parse_verbose(&deep);
        assert!(v.is_none());
        assert_eq!(err, JSON_TOKENER_ERROR_DEPTH);
    }

    #[test]
    fn duplicate_keys_keep_position() {
        assert_eq!(p("{\"a\":1,\"b\":2,\"a\":3}"), "{ \"a\": 3, \"b\": 2 }");
    }

    #[test]
    fn serialization_flags() {
        let v = JsonValue::Object(vec![
            (b"a".to_vec(), JsonValue::Int64(1)),
            (
                b"b".to_vec(),
                JsonValue::Array(vec![JsonValue::Null, JsonValue::String(b"x/y".to_vec())]),
            ),
        ]);
        assert_eq!(
            String::from_utf8_lossy(&json_object_to_json_string_ext(&v, JSON_C_TO_STRING_PLAIN)),
            "{\"a\":1,\"b\":[null,\"x\\/y\"]}"
        );
        assert_eq!(
            String::from_utf8_lossy(&json_object_to_json_string_ext(&v, JSON_C_TO_STRING_SPACED)),
            "{ \"a\": 1, \"b\": [ null, \"x\\/y\" ] }"
        );
        assert_eq!(
            String::from_utf8_lossy(&json_object_to_json_string_ext(&v, JSON_C_TO_STRING_PRETTY)),
            // PRETTY alone does not imply SPACED: the colon is bare
            "{\n  \"a\":1,\n  \"b\":[\n    null,\n    \"x\\/y\"\n  ]\n}"
        );
        assert_eq!(
            String::from_utf8_lossy(&json_object_to_json_string_ext(
                &v,
                JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_PRETTY_TAB
            )),
            "{\n\t\"a\":1,\n\t\"b\":[\n\t\tnull,\n\t\t\"x\\/y\"\n\t]\n}"
        );
        assert_eq!(
            String::from_utf8_lossy(&json_object_to_json_string_ext(
                &v,
                JSON_C_TO_STRING_NOSLASHESCAPE
            )),
            "{\"a\":1,\"b\":[null,\"x/y\"]}"
        );
    }

    #[test]
    fn double_serialization() {
        let cases: &[(f64, &str, &str)] = &[
            (0.0, "0.0", "0.0"),
            (1.5, "1.5", "1.5"),
            (42.0, "42.0", "42.0"),
            (0.1, "0.10000000000000001", "0.10000000000000001"),
            (1e300, "1.0000000000000001e+300", "1.0000000000000001e+3"),
            (1e-5, "1.0000000000000001e-05", "1.0000000000000001e-05"),
            (-0.0, "-0.0", "-0.0"),
            (f64::NAN, "NaN", "NaN"),
            (f64::INFINITY, "Infinity", "Infinity"),
            (f64::NEG_INFINITY, "-Infinity", "-Infinity"),
            (2.5, "2.5", "2.5"),
            (1e15, "1000000000000000.0", "1000000000000000.0"),
            (
                3.141592653589793,
                "3.1415926535897931",
                "3.1415926535897931",
            ),
            (
                123456789.123456789,
                "123456789.12345679",
                "123456789.12345679",
            ),
            (
                2.2250738585072014e-308,
                "2.2250738585072014e-308",
                "2.2250738585072014e-308",
            ),
        ];
        for (v, plain, nozero) in cases {
            let dv = JsonValue::Double(*v, None);
            assert_eq!(
                String::from_utf8_lossy(&json_object_to_json_string_ext(
                    &dv,
                    JSON_C_TO_STRING_PLAIN
                )),
                *plain,
                "{v}"
            );
            assert_eq!(
                String::from_utf8_lossy(&json_object_to_json_string_ext(
                    &dv,
                    JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOZERO
                )),
                *nozero,
                "{v}"
            );
        }
    }

    #[test]
    fn parsed_double_keeps_original_text() {
        // json_object_new_double_s stores the source text verbatim
        assert_eq!(p("1.50"), "1.50");
        assert_eq!(p("1e10"), "1e10");
        assert_eq!(p("123e+"), "123");
        assert_eq!(p("0.10000000000000001"), "0.10000000000000001");
    }
}
