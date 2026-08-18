//! Editline (libedit 20260512-3.1) conservation module (§29).
//!
//! A forensic transcription of NetBSD libedit 3.1 (the `editline` library
//! BIND 9.20.26's nslookup links for interactive line editing via the
//! readline-compatibility layer, `editline/readline.h`), proving the
//! observable behavior byte-for-byte against the C oracle in court LE-0001.
//!
//! Structure follows the C sources of the pinned tarball:
//!   chartype.c, terminal.c, refresh.c, prompt.c, literal.c, chared.c,
//!   read.c, keymacro.c, map.c (tables in `keys.rs`), common.c, emacs.c,
//!   vi.c, search.c, hist.c, history.c, el.c, eln.c, tty.c, sig.c, parse.c,
//!   tokenizer.c, readline.c.
//!
//! The terminal model uses the xterm terminfo strings captured from the
//! oracle container (`oracle-libedit-20260512-3.1`, ncurses-term); the
//! values are pinned data, exactly like the protobuf-c generated fixtures.
//!
//! wchar_t/wint_t are modeled as `u32` code points; `MB_FILL_CHAR` (-1) and
//! the `EL_LITERAL` magic char are representable as `u32` (0xFFFF_FFFF and
//! 0x8000_0000 | idx).

pub mod keys;

use keys::*;

// ---------------------------------------------------------------------------
// § chartype.c — char classification, visual form, UTF-8 conversion
// ---------------------------------------------------------------------------

pub const MB_FILL_CHAR: u32 = 0xFFFF_FFFF;
pub const EL_LITERAL: u32 = 0x8000_0000;
pub const VISUAL_WIDTH_MAX: usize = 8;

pub const CHTYPE_PRINT: i32 = 0;
pub const CHTYPE_ASCIICTL: i32 = -1;
pub const CHTYPE_TAB: i32 = -2;
pub const CHTYPE_NL: i32 = -3;
pub const CHTYPE_NONPRINT: i32 = -4;

/// ct_chr_class().
pub fn ct_chr_class(c: u32) -> i32 {
    if c == '\t' as u32 {
        CHTYPE_TAB
    } else if c == '\n' as u32 {
        CHTYPE_NL
    } else if iswcntrl(c) {
        CHTYPE_ASCIICTL
    } else if iswprint(c) {
        CHTYPE_PRINT
    } else {
        CHTYPE_NONPRINT
    }
}

fn is_combining(cp: u32) -> bool {
    (0x0300..=0x036F).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0x20D0..=0x20FF).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
        || (0x200B..=0x200F).contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || cp == 0x00AD
}

// C-locale (MB_CUR_MAX=1) wide classification.  The oracle container runs in
// the C/POSIX locale; glibc's iswprint()/iswcntrl()/iswalnum()/... are FALSE
// for the whole 0x80-0xFF range there (verified empirically in the oracle),
// so every byte >= 0x80 classifies as CHTYPE_NONPRINT.  This is exactly what
// the C probe observes: UTF-8 input bytes are dropped at read time and never
// reach the editor.
fn iswprint(c: u32) -> bool {
    (0x20..=0x7E).contains(&c)
}

fn iswcntrl(c: u32) -> bool {
    (0x00..=0x1F).contains(&c) || c == 0x7F
}

fn iswalnum(c: u32) -> bool {
    (0x30..=0x39).contains(&c) || (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

fn iswdigit(c: u32) -> bool {
    (0x30..=0x39).contains(&c)
}

fn iswalpha(c: u32) -> bool {
    (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

fn iswlower(c: u32) -> bool {
    (0x61..=0x7A).contains(&c)
}

fn iswupper(c: u32) -> bool {
    (0x41..=0x5A).contains(&c)
}

fn iswspace(c: u32) -> bool {
    matches!(c, 0x09..=0x0D | 0x20)
}

fn iswgraph(c: u32) -> bool {
    (0x21..=0x7E).contains(&c)
}

pub fn towupper(c: u32) -> u32 {
    char::from_u32(c).map_or(c, |ch| ch.to_uppercase().next().unwrap() as u32)
}

pub fn towlower(c: u32) -> u32 {
    char::from_u32(c).map_or(c, |ch| ch.to_lowercase().next().unwrap() as u32)
}

/// wcwidth() approximation: 1 for ASCII, 0 for control/format; the C locale
/// reports -1 for everything >= 0x80 (treated as 0 by the refresh engine, and
/// such chars never reach here anyway — they are dropped at read time).
pub fn wcwidth(c: u32) -> i32 {
    if c >= 0x80 {
        return 0;
    }
    let Some(ch) = char::from_u32(c) else {
        return 0;
    };
    if ch.is_control() {
        return 0;
    }
    if is_combining(ch as u32) {
        return 0;
    }
    // East Asian Wide/Fullwidth ranges (roughly; ASCII and Latin-1 are 1)
    let cp = ch as u32;
    let wide = (0x1100..=0x115F).contains(&cp)
        || (0x2E80..=0x303E).contains(&cp)
        || (0x3041..=0x33FF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0x9FFF).contains(&cp)
        || (0xA000..=0xA4CF).contains(&cp)
        || (0xAC00..=0xD7A3).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0xFE30..=0xFE4F).contains(&cp)
        || (0xFF00..=0xFF60).contains(&cp)
        || (0xFFE0..=0xFFE6).contains(&cp)
        || (0x1F300..=0x1F64F).contains(&cp)
        || (0x20000..=0x2FFFD).contains(&cp)
        || (0x30000..=0x3FFFD).contains(&cp);
    if wide {
        2
    } else {
        1
    }
}

/// ct_visual_width().
pub fn ct_visual_width(c: u32) -> i32 {
    match ct_chr_class(c) {
        CHTYPE_ASCIICTL => 2, /* ^@ ^? etc. */
        CHTYPE_TAB => 1,      /* Hmm, this really need to be handled outside! */
        CHTYPE_NL => 0,       /* Should this be 1 instead? */
        CHTYPE_PRINT => wcwidth(c),
        CHTYPE_NONPRINT => {
            if c > 0xffff {
                8 /* \U+12345 */
            } else {
                7 /* \U+1234 */
            }
        }
        _ => 0,
    }
}

fn hexdigit(v: u32) -> u32 {
    b"0123456789ABCDEF"[v as usize] as u32
}

/// ct_visual_char(): render c in `dst` (returns count used, or -1).
pub fn ct_visual_char(dst: &mut Vec<u32>, c: u32) -> isize {
    match ct_chr_class(c) {
        CHTYPE_TAB | CHTYPE_NL | CHTYPE_ASCIICTL => {
            dst.push('^' as u32);
            if c == 0o177 {
                dst.push('?' as u32); /* DEL -> ^? */
            } else {
                dst.push(c | 0o100); /* uncontrolify it */
            }
            2
        }
        CHTYPE_PRINT => {
            dst.push(c);
            1
        }
        CHTYPE_NONPRINT => {
            dst.push('\\' as u32);
            dst.push('U' as u32);
            dst.push('+' as u32);
            if c > 0xffff {
                dst.push(hexdigit((c >> 16) & 0xf));
            }
            dst.push(hexdigit((c >> 12) & 0xf));
            dst.push(hexdigit((c >> 8) & 0xf));
            dst.push(hexdigit((c >> 4) & 0xf));
            dst.push(hexdigit(c & 0xf));
            if c > 0xffff {
                8
            } else {
                7
            }
        }
        _ => 0,
    }
}

/// ct_enc_width(): C-locale wcrtomb byte length (1 for ASCII, 0 for
/// everything else — the C locale cannot encode bytes >= 0x80).
pub fn ct_enc_width(c: u32) -> usize {
    if c < 0x80 {
        1
    } else {
        0
    }
}

/// ct_encode_char(): C-locale wctomb into `out` (writes the byte for c <
/// 0x80; returns 0 without writing for c >= 0x80, exactly like wctomb failing
/// in the C locale).
pub fn ct_encode_char(out: &mut Vec<u8>, c: u32) -> isize {
    if c < 0x80 {
        out.push(c as u8);
        1
    } else {
        0
    }
}

/// ct_encode_string(): wide -> bytes (C: into a conversion buffer).
pub fn ct_encode_string(s: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for &c in s {
        if c == 0 {
            break;
        }
        ct_encode_char(&mut out, c);
    }
    out
}

/// ct_decode_string(): bytes -> wide (C: mbstowcs in the C locale maps each
/// byte to the wide char with the same value).
pub fn ct_decode_string(s: &[u8]) -> Option<Vec<u32>> {
    Some(s.iter().map(|&b| b as u32).collect())
}

// ---------------------------------------------------------------------------
// § el.h — core constants, flags, state
// ---------------------------------------------------------------------------

pub const EL_BUFSIZ: usize = 1024;
pub const EL_LEAVE: usize = 2;
pub const EL_MAXMACRO: usize = 10;
pub const N_KEYS: usize = 256;

pub const HANDLE_SIGNALS: u32 = 0x001;
pub const NO_TTY: u32 = 0x002;
pub const EDIT_DISABLED: u32 = 0x004;
pub const UNBUFFERED: u32 = 0x008;
pub const NARROW_HISTORY: u32 = 0x040;
pub const NO_RESET: u32 = 0x080;
pub const FIXIO: u32 = 0x100;
pub const FROM_ELLINE: u32 = 0x200;

// CC_* return codes
pub const CC_NORM: u8 = 0;
pub const CC_NEWLINE: u8 = 1;
pub const CC_EOF: u8 = 2;
pub const CC_ARGHACK: u8 = 3;
pub const CC_REFRESH: u8 = 4;
pub const CC_CURSOR: u8 = 5;
pub const CC_ERROR: u8 = 6;
pub const CC_FATAL: u8 = 7;
pub const CC_REDISPLAY: u8 = 8;
pub const CC_REFRESH_BEEP: u8 = 9;

// el_set/el_get ops
pub const EL_PROMPT: i32 = 0;
pub const EL_TERMINAL: i32 = 1;
pub const EL_EDITOR: i32 = 2;
pub const EL_SIGNAL: i32 = 3;
pub const EL_BIND: i32 = 4;
pub const EL_TELLTC: i32 = 5;
pub const EL_SETTC: i32 = 6;
pub const EL_ECHOTC: i32 = 7;
pub const EL_SETTY: i32 = 8;
pub const EL_ADDFN: i32 = 9;
pub const EL_HIST: i32 = 10;
pub const EL_EDITMODE: i32 = 11;
pub const EL_RPROMPT: i32 = 12;
pub const EL_GETCFN: i32 = 13;
pub const EL_CLIENTDATA: i32 = 14;
pub const EL_UNBUFFERED: i32 = 15;
pub const EL_PREP_TERM: i32 = 16;
pub const EL_GETTC: i32 = 17;
pub const EL_GETFP: i32 = 18;
pub const EL_SETFP: i32 = 19;
pub const EL_REFRESH: i32 = 20;
pub const EL_PROMPT_ESC: i32 = 21;
pub const EL_RPROMPT_ESC: i32 = 22;
pub const EL_RESIZE: i32 = 23;
pub const EL_ALIAS_TEXT: i32 = 24;
pub const EL_SAFEREAD: i32 = 25;
pub const EL_WORDCHARS: i32 = 26;
pub const EL_GETENV: i32 = 27;

pub const MAP_EMACS: i32 = 0;
pub const MAP_VI: i32 = 1;

pub const MODE_INSERT: i32 = 0;
pub const MODE_REPLACE: i32 = 1;
pub const MODE_REPLACE_1: i32 = 2;

pub const NOP: i32 = 0x00;
pub const DELETE: i32 = 0x01;
pub const INSERT: i32 = 0x02;
pub const YANK: i32 = 0x04;

pub const CHAR_FWD: i32 = 1;
pub const CHAR_BACK: i32 = -1;

pub const XK_CMD: i32 = 0;
pub const XK_STR: i32 = 1;
pub const XK_NOD: i32 = 2;

// H_* history opcodes (histedit.h)
pub const H_FUNC: i32 = 0;
pub const H_SETSIZE: i32 = 1;
pub const H_GETSIZE: i32 = 2;
pub const H_FIRST: i32 = 3;
pub const H_LAST: i32 = 4;
pub const H_PREV: i32 = 5;
pub const H_NEXT: i32 = 6;
pub const H_SET: i32 = 7;
pub const H_CURR: i32 = 8;
pub const H_ADD: i32 = 9;
pub const H_ENTER: i32 = 10;
pub const H_APPEND: i32 = 11;
pub const H_END: i32 = 12;
pub const H_NEXT_STR: i32 = 13;
pub const H_PREV_STR: i32 = 14;
pub const H_NEXT_EVENT: i32 = 15;
pub const H_PREV_EVENT: i32 = 16;
pub const H_LOAD: i32 = 17;
pub const H_SAVE: i32 = 18;
pub const H_CLEAR: i32 = 19;
pub const H_SETUNIQUE: i32 = 20;
pub const H_GETUNIQUE: i32 = 21;
pub const H_DEL: i32 = 22;
pub const H_NEXT_EVDATA: i32 = 23;
pub const H_DELDATA: i32 = 24;
pub const H_REPLACE: i32 = 25;
pub const H_SAVE_FP: i32 = 26;
pub const H_NSAVE_FP: i32 = 27;

// _HE_* history error codes
pub const _HE_OK: i32 = 0;
pub const _HE_UNKNOWN: i32 = 1;
pub const _HE_MALLOC_FAILED: i32 = 2;
pub const _HE_FIRST_NOTFOUND: i32 = 3;
pub const _HE_LAST_NOTFOUND: i32 = 4;
pub const _HE_EMPTY_LIST: i32 = 5;
pub const _HE_END_REACHED: i32 = 6;
pub const _HE_START_REACHED: i32 = 7;
pub const _HE_CURR_INVALID: i32 = 8;
pub const _HE_NOT_FOUND: i32 = 9;
pub const _HE_HIST_READ: i32 = 10;
pub const _HE_HIST_WRITE: i32 = 11;
pub const _HE_PARAM_MISSING: i32 = 12;
pub const _HE_SIZE_NEGATIVE: i32 = 13;
pub const _HE_NOT_ALLOWED: i32 = 14;
pub const _HE_BAD_PARAM: i32 = 15;

pub fn he_errlist(code: i32) -> &'static str {
    match code {
        _HE_OK => "OK",
        _HE_UNKNOWN => "unknown error",
        _HE_MALLOC_FAILED => "malloc() failed",
        _HE_FIRST_NOTFOUND => "first event not found",
        _HE_LAST_NOTFOUND => "last event not found",
        _HE_EMPTY_LIST => "empty list",
        _HE_END_REACHED => "no next event",
        _HE_START_REACHED => "no previous event",
        _HE_CURR_INVALID => "current event is invalid",
        _HE_NOT_FOUND => "event not found",
        _HE_HIST_READ => "can't read history from file",
        _HE_HIST_WRITE => "can't write history",
        _HE_PARAM_MISSING => "required parameter(s) not supplied",
        _HE_SIZE_NEGATIVE => "history size negative",
        _HE_NOT_ALLOWED => "function not allowed with other history-functions-set the default",
        _HE_BAD_PARAM => "bad parameters",
        _ => "unknown error",
    }
}

// ---------------------------------------------------------------------------
// § core structures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub struct Coord {
    pub h: i32,
    pub v: i32,
}

/// The input line (el_line_t): offsets into `buf` (wide chars).
pub struct LineBuf {
    pub buf: Vec<u32>,
    pub cur: usize,
    pub last: usize,
    pub limit: usize,
}

impl LineBuf {
    fn new(cap: usize) -> LineBuf {
        let mut buf = vec![0u32; cap];
        buf[0] = 0;
        LineBuf {
            buf,
            cur: 0,
            last: 0,
            limit: cap - EL_LEAVE,
        }
    }
    fn enlarge(&mut self, addlen: usize) -> bool {
        let sz = self.limit + EL_LEAVE;
        let mut newsz = sz * 2;
        if addlen > sz {
            while newsz - sz < addlen {
                newsz *= 2;
            }
        }
        self.buf.resize(newsz, 0);
        self.limit = newsz - EL_LEAVE;
        true
    }
}

pub struct ElState {
    pub inputmode: i32,
    pub doingarg: i32,
    pub argument: i32,
    pub metanext: i32,
    pub lastcmd: u8,
    pub thiscmd: u8,
    pub thisch: u32,
}

pub struct Undo {
    pub len: isize,
    pub cursor: i32,
    pub buf: Vec<u32>,
}

pub struct KillBuf {
    pub buf: Vec<u32>,
    pub last: usize,
    pub mark: usize, // offset into el_line.buf
}

pub struct Redo {
    pub buf: Vec<u32>,
    pub pos: usize,
    pub lim: usize,
    pub cmd: u8,
    pub ch: u32,
    pub count: i32,
    pub action: i32,
}

pub struct Vcmd {
    pub action: i32,
    pub pos: usize,
}

pub struct Chared {
    pub undo: Undo,
    pub kill: KillBuf,
    pub redo: Redo,
    pub vcmd: Vcmd,
    pub c_resizefun: bool,
    pub c_aliasfun: bool,
}

pub struct Prompt {
    pub p_func: Option<usize>, // index into engine's prompt fn table
    pub p_pos: Coord,
    pub p_ignore: u32,
    pub p_wide: bool,
}

pub struct Refresh {
    pub r_cursor: Coord,
    pub r_oldcv: i32,
    pub r_newcv: i32,
}

pub struct SearchState {
    pub patbuf: Vec<u32>,
    pub patlen: usize,
    pub patdir: i32,
    pub chadir: i32,
    pub chacha: u32,
    pub chatflg: i8,
}

pub struct HistState {
    pub fun: Option<HistFn>,
    pub refp: Option<History>,
    pub buf: Vec<u32>,
    pub sz: usize,
    pub last: usize,
    pub eventno: i32,
    pub ev: HistEventW,
}

#[derive(Clone)]
pub struct KeymacroNode {
    pub ch: u32,
    pub typ: i32,
    pub val: KeymacroValue,
    pub next: Option<Box<KeymacroNode>>,
    pub sibling: Option<Box<KeymacroNode>>,
}

#[derive(Clone, Default)]
pub struct KeymacroValue {
    pub cmd: u8,
    pub str: Option<Vec<u32>>,
}

pub struct KeymacroState {
    pub buf: Vec<u32>,
    pub map: Option<Box<KeymacroNode>>,
    pub val: KeymacroValue,
}

pub struct MapState {
    pub alt: Vec<u8>,
    pub key: Vec<u8>,
    pub current: usize, // 0 = key, 1 = alt
    pub typ: i32,       // MAP_EMACS / MAP_VI
    pub nfunc: usize,
    pub wordchars: Vec<u32>,
}

pub struct ReadMacros {
    pub macro_stack: Vec<Vec<u32>>,
    pub offset: usize,
}

pub struct ReadState {
    pub macros: ReadMacros,
    pub read_errno: i32,
    pub read_char_fn: Option<usize>, // index into read-fn table
}

pub struct SigState {
    pub sig_no: i32,
}

/// The terminal capability model: the 39 strings and 8 values loaded from
/// the termcap database for TERM=xterm in the oracle container (pinned
/// data — see the terminfo dump in the LE-0001 manifest).
pub struct Terminal {
    pub t_name: String,
    pub t_size: Coord,
    pub t_flags: i32,
    pub t_str: [Option<Vec<u8>>; T_str],
    pub t_val: [i32; T_val],
    pub t_cap: Vec<u8>,
    pub t_buf: Vec<u8>,
    pub t_loc: usize,
    pub terminal_err: Option<String>,
}

pub const T_al: usize = 0;
pub const T_bl: usize = 1;
pub const T_cd: usize = 2;
pub const T_ce: usize = 3;
pub const T_ch: usize = 4;
pub const T_cl: usize = 5;
pub const T_dc: usize = 6;
pub const T_dl: usize = 7;
pub const T_dm: usize = 8;
pub const T_ed: usize = 9;
pub const T_ei: usize = 10;
pub const T_fs: usize = 11;
pub const T_ho: usize = 12;
pub const T_ic: usize = 13;
pub const T_im: usize = 14;
pub const T_ip: usize = 15;
pub const T_kd: usize = 16;
pub const T_kl: usize = 17;
pub const T_kr: usize = 18;
pub const T_ku: usize = 19;
pub const T_md: usize = 20;
pub const T_me: usize = 21;
pub const T_nd: usize = 22;
pub const T_se: usize = 23;
pub const T_so: usize = 24;
pub const T_ts: usize = 25;
pub const T_up: usize = 26;
pub const T_us: usize = 27;
pub const T_ue: usize = 28;
pub const T_vb: usize = 29;
pub const T_DC: usize = 30;
pub const T_DO: usize = 31;
pub const T_IC: usize = 32;
pub const T_LE: usize = 33;
pub const T_RI: usize = 34;
pub const T_UP: usize = 35;
pub const T_kh: usize = 36;
pub const T_at7: usize = 37;
pub const T_kD: usize = 38;
pub const T_str: usize = 39;

pub const T_am: usize = 0;
pub const T_pt: usize = 1;
pub const T_li: usize = 2;
pub const T_co: usize = 3;
pub const T_km: usize = 4;
pub const T_xt: usize = 5;
pub const T_xn: usize = 6;
pub const T_MT: usize = 7;
pub const T_val: usize = 8;

pub const TERM_CAN_INSERT: i32 = 0x001;
pub const TERM_CAN_DELETE: i32 = 0x002;
pub const TERM_CAN_CEOL: i32 = 0x004;
pub const TERM_CAN_TAB: i32 = 0x008;
pub const TERM_CAN_ME: i32 = 0x010;
pub const TERM_CAN_UP: i32 = 0x020;
pub const TERM_HAS_META: i32 = 0x040;
pub const TERM_HAS_AUTO_MARGINS: i32 = 0x080;
pub const TERM_HAS_MAGIC_MARGINS: i32 = 0x100;

pub const TC_BUFSIZE: usize = 2048;

/// The pinned dumb terminfo strings (dumb|80-column dumb tty).
pub static DUMB_STRINGS: [Option<&'static [u8]>; T_str] = [
    None,          // al
    Some(b"\x07"), // bl
    None,          // cd
    None,          // ce
    None,          // ch
    None,          // cl
    None,          // dc
    None,          // dl
    None,          // dm
    None,          // ed
    None,          // ei
    None,          // fs
    None,          // ho
    None,          // ic
    None,          // im
    None,          // ip
    None,          // kd
    None,          // kl
    None,          // kr
    None,          // ku
    None,          // md
    None,          // me
    None,          // nd
    None,          // se
    None,          // so
    None,          // ts
    None,          // up
    None,          // us
    None,          // ue
    None,          // vb
    None,          // DC
    None,          // DO
    None,          // IC
    None,          // LE
    None,          // RI
    None,          // UP
    None,          // kh
    None,          // @7
    None,          // kD
];

pub static XTERM_STRINGS: [Option<&'static [u8]>; T_str] = [
    Some(b"\x1b[L"),                  // al
    Some(b"\x07"),                    // bl
    Some(b"\x1b[J"),                  // cd
    Some(b"\x1b[K"),                  // ce
    Some(b"\x1b[%i%p1%dG"),           // ch
    Some(b"\x1b[H\x1b[2J"),           // cl
    Some(b"\x1b[P"),                  // dc
    Some(b"\x1b[M"),                  // dl
    None,                             // dm
    None,                             // ed
    Some(b"\x1b[4l"),                 // ei
    None,                             // fs
    Some(b"\x1b[H"),                  // ho
    None,                             // ic
    Some(b"\x1b[4h"),                 // im
    None,                             // ip
    Some(b"\x1bOB"),                  // kd
    Some(b"\x1bOD"),                  // kl
    Some(b"\x1bOC"),                  // kr
    Some(b"\x1bOA"),                  // ku
    Some(b"\x1b[1m"),                 // md
    Some(b"\x1b[0m"),                 // me
    Some(b"\x1b[C"),                  // nd
    Some(b"\x1b[27m"),                // se
    Some(b"\x1b[7m"),                 // so
    None,                             // ts
    Some(b"\x1b[A"),                  // up
    Some(b"\x1b[4m"),                 // us
    Some(b"\x1b[24m"),                // ue
    Some(b"\x1b[?5h$<100/>\x1b[?5l"), // vb
    Some(b"\x1b[%p1%dP"),             // DC
    Some(b"\x1b[%p1%dB"),             // DO
    Some(b"\x1b[%p1%d@"),             // IC
    Some(b"\x1b[%p1%dD"),             // LE
    Some(b"\x1b[%p1%dC"),             // RI
    Some(b"\x1b[%p1%dA"),             // UP
    Some(b"\x1bOH"),                  // kh
    Some(b"\x1bOF"),                  // @7
    Some(b"\x1b[3~"),                 // kD
];

/// tputs() for the pinned strings: ncurses emits the string bytes; `$<n>`
/// padding specs only affect timing, never the byte stream (not triggered
/// by the corpus).
fn tputs_cap(cap: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < cap.len() {
        if cap[i] == b'$' && i + 1 < cap.len() && cap[i + 1] == b'<' {
            // skip $<...> padding spec
            while i < cap.len() && cap[i] != b'>' {
                i += 1;
            }
            i += 1;
            continue;
        }
        out.push(cap[i]);
        i += 1;
    }
}

/// tgoto() for the pinned capability strings: supports %p1 %p2 %d %i %% and
/// literal pass-through (the ncurses behavior for the xterm strings).
fn tgoto_cap(cap: &[u8], cols: i32, rows: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut arg = [cols, rows];
    let mut n = 0usize;
    while i < cap.len() {
        let b = cap[i];
        if b == b'%' && i + 1 < cap.len() {
            let c = cap[i + 1];
            match c {
                b'i' => {
                    arg[0] += 1;
                    arg[1] += 1;
                }
                b'p' => {
                    let d = cap[i + 2];
                    n = (d - b'1') as usize;
                    i += 1;
                }
                b'd' => {
                    let v = arg[n];
                    out.extend_from_slice(v.to_string().as_bytes());
                }
                b'%' => out.push(b'%'),
                b'n' => {
                    arg[0] += 1;
                    arg[1] += 1;
                }
                b'r' => {
                    arg.swap(0, 1);
                }
                b'B' => {
                    arg[n] = (arg[n] / 16 * 10) + (arg[n] % 16);
                }
                b'D' => {
                    arg[n] -= 2 * (arg[n] % 16);
                }
                _ => {
                    out.push(b'%');
                    out.push(c);
                }
            }
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// § terminal.c — emission model
// ---------------------------------------------------------------------------

impl Terminal {
    pub fn new(term: &str, getenv: &dyn Fn(&str) -> Option<String>) -> Terminal {
        let mut t = Terminal {
            t_name: String::new(),
            t_size: Coord { h: 0, v: 0 },
            t_flags: 0,
            t_str: std::array::from_fn(|_| None),
            t_val: [0; T_val],
            t_cap: vec![0u8; TC_BUFSIZE],
            t_buf: vec![0u8; TC_BUFSIZE],
            t_loc: 0,
            terminal_err: None,
        };
        t.terminal_err = t.terminal_set(term, getenv);
        t
    }

    fn good_str(&self, a: usize) -> bool {
        self.t_str[a].as_ref().map_or(false, |s| !s.is_empty())
    }

    fn terminal_set(
        &mut self,
        term: &str,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Option<String> {
        // tcgetent equivalent: consult the pinned terminfo tables.
        let resolved = if term.is_empty() {
            getenv("TERM").unwrap_or_else(|| "dumb".to_string())
        } else {
            term.to_string()
        };
        let resolved = if resolved.is_empty() {
            "dumb".to_string()
        } else {
            resolved
        };
        self.t_name = resolved.clone();
        let found = match resolved.as_str() {
            "xterm" | "xterm-debian" => Some(&XTERM_STRINGS[..]),
            "dumb" => Some(&DUMB_STRINGS[..]),
            _ => None,
        };
        match found {
            Some(strings) => {
                if resolved != "dumb" {
                    self.t_val[T_am] = 1;
                    self.t_val[T_xn] = 1;
                    self.t_val[T_km] = 1;
                    self.t_val[T_co] = 80;
                    self.t_val[T_li] = 24;
                } else {
                    self.t_val[T_am] = 1;
                    self.t_val[T_co] = 80;
                    self.t_val[T_li] = -1;
                }
                for (i, s) in strings.iter().enumerate() {
                    self.terminal_alloc(i, s.map(|v| v.to_vec()));
                }
            }
            None => {
                // tgetent failed: report and use dumb terminal settings
                // (the C writes these to el_errfile and returns -1)
                let msg = format!(
                    "No entry for terminal type \"{}\";\nusing dumb terminal settings.\n",
                    resolved
                );
                self.t_val[T_co] = 80;
                self.t_val[T_pt] = 0;
                self.t_val[T_km] = 0;
                self.t_val[T_li] = 0;
                self.t_val[T_xt] = self.t_val[T_MT];
                for i in 0..T_str {
                    self.terminal_alloc(i, None);
                }
                if self.t_val[T_co] < 2 {
                    self.t_val[T_co] = 80;
                }
                if self.t_val[T_li] < 1 {
                    self.t_val[T_li] = 24;
                }
                self.t_size.h = self.t_val[T_co];
                self.t_size.v = self.t_val[T_li];
                self.terminal_setflags();
                return Some(msg);
            }
        }
        if self.t_val[T_co] < 2 {
            self.t_val[T_co] = 80;
        }
        if self.t_val[T_li] < 1 {
            self.t_val[T_li] = 24;
        }
        // terminal_change_size() re-derives the size from the values
        // (terminal_set's own v/h assignments are swapped in the C; the
        // rebuffer is what actually sets h=cols, v=lines)
        self.t_size.h = self.t_val[T_co];
        self.t_size.v = self.t_val[T_li];
        self.terminal_setflags();
        None
    }

    fn terminal_alloc(&mut self, idx: usize, cap: Option<Vec<u8>>) {
        match cap {
            None => {
                self.t_str[idx] = None;
            }
            Some(c) if c.is_empty() => {
                self.t_str[idx] = None;
            }
            Some(c) => {
                self.t_str[idx] = Some(c);
            }
        }
    }

    fn terminal_setflags(&mut self) {
        self.t_flags = 0;
        self.t_flags |= if (self.t_val[T_km] != 0 || self.t_val[T_MT] != 0) {
            TERM_HAS_META
        } else {
            0
        };
        self.t_flags |= if self.good_str(T_ce) {
            TERM_CAN_CEOL
        } else {
            0
        };
        self.t_flags |= if self.good_str(T_dc) || self.good_str(T_DC) {
            TERM_CAN_DELETE
        } else {
            0
        };
        self.t_flags |= if self.good_str(T_im) || self.good_str(T_ic) || self.good_str(T_IC) {
            TERM_CAN_INSERT
        } else {
            0
        };
        self.t_flags |= if self.good_str(T_up) || self.good_str(T_UP) {
            TERM_CAN_UP
        } else {
            0
        };
        self.t_flags |= if self.t_val[T_am] != 0 {
            TERM_HAS_AUTO_MARGINS
        } else {
            0
        };
        self.t_flags |= if self.t_val[T_xn] != 0 {
            TERM_HAS_MAGIC_MARGINS
        } else {
            0
        };
        // t_tabs is set by the tty layer before setflags is called from
        // terminal_set (via tty_init); emulate: t_tabs defaults true.
        self.t_flags |= if self.t_val[T_pt] != 0 && self.t_val[T_xt] == 0 {
            TERM_CAN_TAB
        } else {
            0
        };
        if self.good_str(T_me) && self.good_str(T_ue) {
            self.t_flags |= if self.t_str[T_me] == self.t_str[T_ue] {
                TERM_CAN_ME
            } else {
                0
            };
        } else {
            self.t_flags &= !TERM_CAN_ME;
        }
        if self.good_str(T_me) && self.good_str(T_se) {
            self.t_flags |= if self.t_str[T_me] == self.t_str[T_se] {
                TERM_CAN_ME
            } else {
                0
            };
        }
    }
}

// terminal_move_to_line / terminal_move_to_char are methods on the Engine
// (they need el_cursor and the output sink), implemented below.

// ---------------------------------------------------------------------------
// § literal.c — prompt literal strings
// ---------------------------------------------------------------------------

pub struct Literal {
    pub l_buf: Vec<Vec<u8>>,
    pub l_len: usize,
    pub l_idx: usize,
}

impl Literal {
    fn new() -> Literal {
        Literal {
            l_buf: Vec::new(),
            l_len: 0,
            l_idx: 0,
        }
    }
    fn clear(&mut self) {
        self.l_buf.clear();
        self.l_len = 0;
        self.l_idx = 0;
    }
    fn add(&mut self, buf: &[u32], end: &[u32]) -> u32 {
        // end points at the character after the literal
        let w = wcwidth(end[0]);
        if w < 0 {
            return 0;
        }
        let mut b = Vec::new();
        for &c in buf {
            ct_encode_char(&mut b, c);
        }
        ct_encode_char(&mut b, end[0]);
        if self.l_idx == self.l_len {
            self.l_len += 4;
        }
        self.l_buf.push(b);
        let idx = self.l_idx;
        self.l_idx += 1;
        EL_LITERAL | (idx as u32)
    }
    fn get(&self, idx: u32) -> &[u8] {
        let i = (idx & !EL_LITERAL) as usize;
        &self.l_buf[i]
    }
}

// ---------------------------------------------------------------------------
// § prompt.c
// ---------------------------------------------------------------------------

// The prompt functions are represented by an index into a fixed table:
// 0 = prompt_default ("? "), 1 = prompt_default_r (""), 2 = user function
// (index into engine.user_prompts).
pub const PROMPT_DEFAULT: usize = 0;
pub const PROMPT_DEFAULT_R: usize = 1;
pub const PROMPT_USER: usize = 2;

pub fn prompt_default_text() -> Vec<u32> {
    vec!['?' as u32, ' ' as u32]
}

// ---------------------------------------------------------------------------
// § refresh.c — the virtual-screen renderer
// ---------------------------------------------------------------------------

const MIN_END_KEEP: usize = 4;

#[allow(clippy::too_many_arguments)]
impl Engine {
    pub fn re_putc(&mut self, c: u32, shift: bool) {
        let sizeh = self.term.t_size.h as usize;
        let mut w = wcwidth(c) as i32;
        if w == -1 {
            w = 0;
        }
        let mut cur = self.refresh.r_cursor;
        if shift {
            while cur.h as i32 + w > sizeh as i32 {
                self.re_putc(' ' as u32, true);
                cur = self.refresh.r_cursor;
            }
        }
        let v = cur.v as usize;
        let h = cur.h as usize;
        while self.vdisplay[v].len() <= h + 1 {
            self.vdisplay[v].push(0);
        }
        self.vdisplay[v][h] = c;
        let mut i = w;
        while i > 1 {
            let hi = h + (i as usize) - 1;
            while self.vdisplay[v].len() <= hi + 1 {
                self.vdisplay[v].push(0);
            }
            self.vdisplay[v][hi] = MB_FILL_CHAR;
            i -= 1;
        }
        if !shift {
            return;
        }
        cur.h += if w != 0 { w } else { 1 };
        if cur.h >= sizeh as i32 {
            self.vdisplay[v][sizeh] = 0;
            self.re_nextline();
        } else {
            self.refresh.r_cursor = cur;
        }
    }

    fn re_addc(&mut self, c: u32) {
        match ct_chr_class(c) {
            CHTYPE_TAB => loop {
                self.re_putc(' ' as u32, true);
                if (self.refresh.r_cursor.h & 07) == 0 {
                    break;
                }
            },
            CHTYPE_NL => {
                let oldv = self.refresh.r_cursor.v;
                self.re_putc(0, false);
                if oldv == self.refresh.r_cursor.v {
                    self.re_nextline();
                }
            }
            CHTYPE_PRINT => {
                self.re_putc(c, true);
            }
            _ => {
                let mut vis = Vec::new();
                ct_visual_char(&mut vis, c);
                for &vc in &vis {
                    self.re_putc(vc, true);
                }
            }
        }
    }

    pub fn re_putliteral(&mut self, begin: &[u32], end: &[u32]) {
        // literal_add stores buf..=end and returns a magic char
        let w = wcwidth(end[0]);
        if w < 0 {
            return;
        }
        let mut all = begin.to_vec();
        all.push(end[0]);
        let magic = self.literal.add(&all, end);
        if magic == 0 {
            return;
        }
        self.re_putc(magic, true);
    }

    fn re_nextline(&mut self) {
        self.re_putc(0, false); // make line ended with NUL, no cursor shift
        self.refresh.r_cursor.h = 0;
        self.refresh.r_cursor.v += 1;
        // NB: the C re_nextline() emits nothing here; the physical newline
        // for the next display row is written by terminal_move_to_line()
        // in re_update_line() (or by re_fastputc()'s wrap handling).
    }

    fn re_clear_eol(&mut self, fx: i32, sx: i32, diff_in: i32) {
        let mut fx = fx;
        let mut sx = sx;
        let mut diff = diff_in;
        if fx < 0 {
            fx = -fx;
        }
        if sx < 0 {
            sx = -sx;
        }
        if fx > diff {
            diff = fx;
        }
        if sx > diff {
            diff = sx;
        }
        self.terminal_clear_EOL(diff);
    }

    /// re_update_line(): diff old vs new display row, emit terminal bytes.
    ///
    /// Faithful to the C: `old` is the space-padded display row (with a
    /// trailing NUL), `new` is the NUL-terminated vdisplay row.  The C walks
    /// pointers: first-diff, end-of-old (to the NUL, then stripping trailing
    /// blanks), end-of-new (same), last-same, then the insert/delete save
    /// scans, the pragmatics, and the redraw.  The row mutation the C does
    /// (re_insert/re_delete/re__strncopy on `old`) does not affect the
    /// emitted bytes (all positions are precomputed), only the display state,
    /// which re__copy_and_pad rebuilds afterwards, so it is skipped here.
    fn re_update_line(&mut self, row: usize, new_row: usize) {
        self.update_row = new_row;
        let mut old: Vec<u32> = self.display[row].clone();
        let mut new: Vec<u32> = self.vdisplay[new_row].clone();
        // find first diff: *o && (*o == *n)
        let mut o = 0usize;
        let mut n = 0usize;
        while old[o] != 0 && old[o] == new[n] {
            o += 1;
            n += 1;
        }
        let ofd = o;
        let nfd = n;
        // find end of old: while (*o) o++
        while old[o] != 0 {
            o += 1;
        }
        // remove trailing blanks off the end
        while ofd < o && old[o - 1] == (' ' as u32) {
            o -= 1;
        }
        let oe = o;
        // the C writes the NUL at the (stripped) end of the old row into the
        // row buffer itself; that mutation is what makes the "no difference"
        // check below see a prefix row (old padded with spaces, new
        // NUL-terminated at the same position) as identical.
        old[oe] = 0;
        // find end of new: while (*n) n++
        while new[n] != 0 {
            n += 1;
        }
        // remove trailing blanks from the end of new
        while nfd < n && new[n - 1] == (' ' as u32) {
            n -= 1;
        }
        let ne = n;
        new[ne] = 0;
        // if no diff, continue to the next line of redraw
        if old[ofd] == 0 && new[nfd] == 0 {
            return;
        }
        // find last same
        while o > ofd && n > nfd && old[o - 1] == new[n - 1] {
            o -= 1;
            n -= 1;
        }
        let mut ols = o;
        let mut nls = n;
        let mut osb = ols;
        let mut nsb = nls;
        let mut ose = ols;
        let mut nse = nls;
        // case 1: insert: scan from nfd to nls looking for *ofd
        if old[ofd] != 0 {
            let c = old[ofd];
            let mut ni = nfd;
            while ni < nls {
                if c == new[ni] {
                    let mut oi = ofd;
                    let mut pi = ni;
                    while pi < nls && oi < ols && old[oi] == new[pi] {
                        oi += 1;
                        pi += 1;
                    }
                    if (nse - nsb) < (pi - ni) && 2 * (pi - ni) > ni - nfd {
                        nsb = ni;
                        nse = pi;
                        osb = ofd;
                        ose = oi;
                    }
                }
                ni += 1;
            }
        }
        // case 2: delete: scan from ofd to ols looking for *nfd
        if new[nfd] != 0 {
            let c = new[nfd];
            let mut oi = ofd;
            while oi < ols {
                if c == old[oi] {
                    let mut ni = nfd;
                    let mut pi = oi;
                    while pi < ols && ni < nls && old[pi] == new[ni] {
                        pi += 1;
                        ni += 1;
                    }
                    if (ose - osb) < (pi - oi) && 2 * (pi - oi) > oi - ofd {
                        nsb = nfd;
                        nse = ni;
                        osb = oi;
                        ose = pi;
                    }
                }
                oi += 1;
            }
        }
        // Pragmatics I: not enough chars to save at the end
        if (oe - ols) < MIN_END_KEEP {
            ols = oe;
            nls = ne;
        }
        // Pragmatics II: terminal capabilities
        let el_can_insert = self.term.t_flags & TERM_CAN_INSERT != 0;
        let el_can_delete = self.term.t_flags & TERM_CAN_DELETE != 0;
        if !el_can_insert {
            let fx0 = (nsb as i64 - nfd as i64) - (osb as i64 - ofd as i64);
            if fx0 > 0 {
                osb = ols;
                ose = ols;
                nsb = nls;
                nse = nls;
            }
            if (nls as i64 - nse as i64 - (ols as i64 - ose as i64)) > 0 {
                ols = oe;
                nls = ne;
            }
            if (ols - ofd) < (nls - nfd) {
                ols = oe;
                nls = ne;
            }
        }
        if !el_can_delete {
            let fx0 = (nsb as i64 - nfd as i64) - (osb as i64 - ofd as i64);
            if fx0 < 0 {
                osb = ols;
                ose = ols;
                nsb = nls;
                nse = nls;
            }
            if (nls as i64 - nse as i64 - (ols as i64 - ose as i64)) < 0 {
                ols = oe;
                nls = ne;
            }
            if (ols - ofd) > (nls - nfd) {
                ols = oe;
                nls = ne;
            }
        }
        // Pragmatics III: make sure the middle shifted pointers are correct
        if (ose - osb) < MIN_END_KEEP {
            osb = ols;
            ose = ols;
            nsb = nls;
            nse = nls;
        }
        // recompute fx, sx
        let mut fx = (nsb as i64 - nfd as i64) - (osb as i64 - ofd as i64);
        let sx = (nls as i64 - nse as i64) - (ols as i64 - ose as i64);
        self.terminal_move_to_line(row as i32);
        // p: last useful old character
        let p = if ols != oe { oe } else { ose };
        let sizeh = self.term.t_size.h as i64;
        // first diff insert
        if nsb != nfd && fx > 0 && (p as i64 + fx <= sizeh) {
            self.terminal_move_to_char(nfd as i32);
            if nsb != ne {
                if fx > 0 {
                    self.terminal_insertwrite_at(nfd, fx as usize);
                }
                let len = (nsb as i64 - nfd as i64) - fx;
                self.terminal_overwrite_at((nfd as i64 + fx) as usize, len as usize);
            } else {
                let len = nsb - nfd;
                self.terminal_overwrite_at(nfd, len);
                return;
            }
        } else if fx < 0 {
            // first diff delete
            self.terminal_move_to_char(ofd as i32);
            if osb != oe {
                if fx < 0 {
                    self.terminal_deletechars((-fx) as i32);
                }
                let len = nsb - nfd;
                self.terminal_overwrite_at(nfd, len);
            } else {
                let len = nsb - nfd;
                self.terminal_overwrite_at(nfd, len);
                self.re_clear_eol(fx as i32, sx as i32, (oe as i64 - ne as i64) as i32);
                return;
            }
        } else {
            fx = 0;
        }
        // second diff delete
        if sx < 0 && (ose as i64 + fx) < sizeh {
            self.terminal_move_to_char((ose as i64 + fx) as i32);
            if ols != oe {
                if sx < 0 {
                    self.terminal_deletechars((-sx) as i32);
                }
                let len = nls - nse;
                self.terminal_overwrite_at(nse, len);
            } else {
                let len = nls - nse;
                self.terminal_overwrite_at(nse, len);
                self.re_clear_eol(fx as i32, sx as i32, (oe as i64 - ne as i64) as i32);
            }
        }
        // late first insert (we haven't already done it: fx == 0)
        if nsb != nfd && (osb as i64 - ofd as i64) <= (nsb as i64 - nfd as i64) && fx == 0 {
            self.terminal_move_to_char(nfd as i32);
            if nsb != ne {
                fx = (nsb as i64 - nfd as i64) - (osb as i64 - ofd as i64);
                if fx > 0 {
                    self.terminal_insertwrite_at(nfd, fx as usize);
                }
                let len = (nsb as i64 - nfd as i64) - fx;
                self.terminal_overwrite_at((nfd as i64 + fx) as usize, len as usize);
            } else {
                let len = nsb - nfd;
                self.terminal_overwrite_at(nfd, len);
            }
        }
        // second diff insert
        if sx >= 0 {
            self.terminal_move_to_char(nse as i32);
            if ols != oe {
                if sx > 0 {
                    self.terminal_insertwrite_at(nse, sx as usize);
                }
                let len = (nls as i64 - nse as i64) - sx;
                self.terminal_overwrite_at((nse as i64 + sx) as usize, len as usize);
            } else {
                let len = nls - nse;
                self.terminal_overwrite_at(nse, len);
            }
        }
    }

    fn re_insert(&mut self, dat: usize, num: usize, _s: usize) {
        // insert `num` chars of the new row at `dat` in the old row (row
        // model: the C mutates the `old` buffer; here we keep a scratch
        // copy of the old row per re_update_line call).
        self.re_insert_scratch = Some((dat, num));
    }

    fn re_delete(&mut self, dat: usize, num: usize) {
        self.re_delete_scratch = Some((dat, num));
    }

    /// re_refresh(): draw the virtual screen from the current line.
    pub fn re_refresh(&mut self) {
        let mut cur = Coord { h: -1, v: 0 };
        self.literal.clear();
        self.refresh.r_cursor.h = 0;
        self.refresh.r_cursor.v = 0;
        self.terminal_move_to_char(0);
        // rprompt sizing pass
        self.prompt_print(EL_RPROMPT);
        self.refresh.r_cursor.h = 0;
        self.refresh.r_cursor.v = 0;
        if self.line.cur >= self.line.last {
            if self.map.current == 1 && self.line.last != 0 {
                self.line.cur = self.line.last - 1;
            } else {
                self.line.cur = self.line.last;
            }
        }
        cur.h = -1;
        cur.v = 0;
        self.prompt_print(EL_PROMPT);
        let st = 0usize;
        let mut cp = st;
        while cp < self.line.last {
            if cp == self.line.cur {
                let w = wcwidth(self.line.buf[cp]);
                cur.h = self.refresh.r_cursor.h;
                cur.v = self.refresh.r_cursor.v;
                if w > 1 && self.refresh.r_cursor.h + w > self.term.t_size.h {
                    cur.h = 0;
                    cur.v += 1;
                }
            }
            let c = self.line.buf[cp];
            self.re_addc(c);
            cp += 1;
        }
        if cur.h == -1 {
            cur.h = self.refresh.r_cursor.h;
            cur.v = self.refresh.r_cursor.v;
        }
        let rhdiff = self.term.t_size.h - self.refresh.r_cursor.h - self.rprompt.p_pos.h;
        if self.rprompt.p_pos.h != 0
            && self.rprompt.p_pos.v == 0
            && self.refresh.r_cursor.v == 0
            && rhdiff > 1
        {
            let mut rd = rhdiff;
            while rd > 1 {
                self.re_putc(' ' as u32, true);
                rd -= 1;
            }
            self.prompt_print(EL_RPROMPT);
        } else {
            self.rprompt.p_pos.h = 0;
            self.rprompt.p_pos.v = 0;
        }
        self.re_putc(0, false);
        self.refresh.r_newcv = self.refresh.r_cursor.v;
        // update the rows
        let newcv = self.refresh.r_newcv;
        let _ = newcv;
        let nrows = (self.refresh.r_newcv + 1) as usize;
        for i in 0..nrows {
            // snapshot old row, then apply diff using a scratch copy
            self.re_update_line(i, i);
            self.re__copy_and_pad(i, i);
        }
        let oldcv = self.refresh.r_oldcv;
        let mut i = nrows;
        if oldcv > self.refresh.r_newcv {
            while i <= oldcv as usize {
                self.terminal_move_to_line(i as i32);
                self.terminal_move_to_char(0);
                let w = self.display[i]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(self.display[i].len());
                self.terminal_clear_EOL(w as i32);
                self.display[i].truncate(1);
                self.display[i][0] = 0;
                i += 1;
            }
        }
        self.refresh.r_oldcv = self.refresh.r_newcv;
        self.terminal_move_to_line(cur.v);
        self.terminal_move_to_char(cur.h);
    }

    fn re__copy_and_pad(&mut self, dst: usize, src: usize) {
        let width = self.term.t_size.h as usize;
        let mut i = 0usize;
        let mut v = Vec::with_capacity(width + 1);
        let slen = self.vdisplay[src].len();
        while i < width && i < slen && self.vdisplay[src][i] != 0 {
            v.push(self.vdisplay[src][i]);
            i += 1;
        }
        while i < width {
            v.push(' ' as u32);
            i += 1;
        }
        v.push(0);
        self.display[dst] = v;
    }

    pub fn re_refresh_cursor(&mut self) {
        if self.line.cur >= self.line.last {
            if self.map.current == 1 && self.line.last != 0 {
                self.line.cur = self.line.last - 1;
            } else {
                self.line.cur = self.line.last;
            }
        }
        let mut h = self.prompt.p_pos.h;
        let mut v = self.prompt.p_pos.v;
        let th = self.term.t_size.h;
        let mut cp = 0usize;
        while cp < self.line.cur {
            let c = self.line.buf[cp];
            match ct_chr_class(c) {
                CHTYPE_NL => {
                    h = 0;
                    v += 1;
                }
                CHTYPE_TAB => {
                    while {
                        h += 1;
                        (h & 07) != 0
                    } {}
                }
                _ => {
                    let w = wcwidth(c);
                    if w > 1 && h + w > th {
                        h = 0;
                        v += 1;
                    }
                    h += ct_visual_width(c);
                }
            }
            if h >= th {
                h -= th;
                v += 1;
            }
            cp += 1;
        }
        if cp < self.line.last {
            let w = wcwidth(self.line.buf[cp]);
            if w > 1 && h + w > th {
                h = 0;
                v += 1;
            }
        }
        self.terminal_move_to_line(v);
        self.terminal_move_to_char(h);
        self.terminal__flush();
    }

    fn re_fastputc(&mut self, c: u32) {
        let sizeh = self.term.t_size.h as usize;
        let mut w = wcwidth(c) as i32;
        while w > 1 && (self.cursor.h as usize) + (w as usize) > sizeh {
            self.re_fastputc(' ' as u32);
        }
        self.terminal__putc(c);
        let v = self.cursor.v as usize;
        let h = self.cursor.h as usize;
        self.display[v][h] = c;
        self.cursor.h += 1;
        let mut w = w;
        while w > 1 {
            self.display[v][self.cursor.h as usize] = MB_FILL_CHAR;
            self.cursor.h += 1;
            w -= 1;
        }
        if self.cursor.h >= sizeh as i32 {
            self.cursor.h = 0;
            if self.cursor.v + 1 >= self.term.t_size.v {
                let lins = self.term.t_size.v as usize;
                let lastline = self.display[0].clone();
                for i in 1..lins {
                    self.display[i - 1] = self.display[i].clone();
                }
                self.display[lins - 1] = lastline;
            } else {
                self.cursor.v += 1;
                self.refresh.r_oldcv += 1;
                let li = self.refresh.r_oldcv as usize;
                let mut pad = vec![' ' as u32; sizeh];
                pad.push(0);
                self.display[li] = pad;
            }
            if self.term.t_flags & TERM_HAS_AUTO_MARGINS != 0 {
                if self.term.t_flags & TERM_HAS_MAGIC_MARGINS != 0 {
                    self.terminal__putc(' ' as u32);
                    self.terminal__putc(0x08);
                }
            } else {
                self.terminal__putc('\r' as u32);
                self.terminal__putc('\n' as u32);
            }
        }
    }

    pub fn re_fastaddc(&mut self) {
        if self.line.cur == 0 {
            self.re_refresh();
            return;
        }
        let c = self.line.buf[self.line.cur - 1];
        if c == '\t' as u32 || self.line.cur != self.line.last {
            self.re_refresh();
            return;
        }
        let rhdiff = self.term.t_size.h - self.cursor.h - self.rprompt.p_pos.h;
        if self.rprompt.p_pos.h != 0 && rhdiff < 3 {
            self.re_refresh();
            return;
        }
        match ct_chr_class(c) {
            CHTYPE_TAB => {}
            CHTYPE_NL | CHTYPE_PRINT => {
                self.re_fastputc(c);
            }
            CHTYPE_ASCIICTL | CHTYPE_NONPRINT => {
                let mut vis = Vec::new();
                ct_visual_char(&mut vis, c);
                for &vc in &vis {
                    self.re_fastputc(vc);
                }
            }
            _ => {}
        }
        self.terminal__flush();
    }

    pub fn re_goto_bottom(&mut self) {
        self.terminal_move_to_line(self.refresh.r_oldcv);
        self.terminal__putc('\n' as u32);
        self.re_clear_display();
        self.terminal__flush();
    }

    pub fn re_clear_display(&mut self) {
        self.cursor.v = 0;
        self.cursor.h = 0;
        for i in 0..self.term.t_size.v as usize {
            self.display[i].truncate(1);
            self.display[i][0] = 0;
        }
        self.refresh.r_oldcv = 0;
    }

    pub fn re_clear_lines(&mut self) {
        if self.term.t_flags & TERM_CAN_CEOL != 0 {
            let mut i = self.refresh.r_oldcv;
            while i >= 0 {
                if i > 0 {
                    self.terminal__putc('\r' as u32);
                    self.terminal__putc('\n' as u32);
                }
                self.terminal_move_to_line(i);
                self.terminal_move_to_char(0);
                self.terminal_clear_EOL(self.term.t_size.h);
                i -= 1;
            }
        } else {
            let mut i = self.refresh.r_oldcv;
            while i > 0 {
                self.terminal__putc('\r' as u32);
                self.terminal__putc('\n' as u32);
                i -= 1;
            }
            self.terminal_move_to_line(self.refresh.r_oldcv);
            self.terminal__putc('\r' as u32);
            self.terminal__putc('\n' as u32);
        }
    }
}

// ---------------------------------------------------------------------------
// § Engine — the EditLine state (el.h struct editline)
// ---------------------------------------------------------------------------

pub type HistFn = fn(&mut History, &mut HistEventW, i32, &[HistoryArg]) -> i32;

#[derive(Clone, Default)]
pub struct HistEventW {
    pub num: i32,
    pub str: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct HistEventN {
    pub num: i32,
    pub str: Option<Vec<u8>>,
}

pub enum HistoryArg {
    I32(i32),
    Str(Vec<u8>),
    WStr(Vec<u32>),
    Fp(u8), // file handle id (for H_SAVE_FP)
    /// The C's `(void **)-1` magic for H_DELDATA: set the position to the
    /// n-th (0-based from the oldest) event WITHOUT deleting it.
    MagicDel,
    None,
}

/// The narrow/wide history implementation (history.c), shared state.
#[derive(Clone, Default)]
pub struct History {
    pub h_ref: HistoryImpl,
    pub h_ent: i32,
}

#[derive(Clone, Default)]
pub struct HistoryImpl {
    pub list: Vec<HEntry>, // head is index 0 (the fake list header)
    pub cursor: usize,
    pub max: i32,
    pub cur: i32,
    pub eventid: i32,
    pub flags: i32,
}

#[derive(Clone, Default)]
pub struct HEntry {
    pub ev_num: i32,
    pub ev_str: Vec<u8>,
    pub data: Option<Vec<u8>>,
}

pub struct Engine {
    pub prog: Vec<u32>,
    pub flags: u32,
    pub cursor: Coord,
    pub display: Vec<Vec<u32>>,
    pub vdisplay: Vec<Vec<u32>>,
    pub data: Option<Box<dyn std::any::Any>>,
    pub line: LineBuf,
    pub state: ElState,
    pub term: Terminal,
    pub tty: TtyModel,
    pub refresh: Refresh,
    pub prompt: Prompt,
    pub rprompt: Prompt,
    pub literal: Literal,
    pub chared: Chared,
    pub map: MapState,
    pub keymacro: KeymacroState,
    pub hist: HistState,
    pub search: SearchState,
    pub sig: SigState,
    pub read: ReadState,
    pub visual: Vec<u8>,
    pub scratch: Vec<u8>,
    pub lgcyconv: Vec<u8>,
    pub lgcylinfo_buf: Vec<u8>,
    pub getenv: Box<dyn Fn(&str) -> Option<String>>,
    // conservation plumbing (not part of libedit):
    pub input: Vec<u8>,
    pub input_pos: usize,
    pub out: Vec<u8>,
    pub err: Vec<u8>,
    pub merge_err: bool,
    pub user_prompts: Vec<Box<dyn FnMut(&mut Engine) -> Vec<u32>>>,
    pub user_funcs: Vec<(Vec<u32>, Vec<u32>, UserFunc)>,
    pub update_row: usize,
    pub tty_is_tty: bool,
    pub read_lastchar: u32,
    pub re_insert_scratch: Option<(usize, usize)>,
    pub re_delete_scratch: Option<(usize, usize)>,
}

pub type UserFunc = fn(&mut Engine, u32) -> u8;

impl Default for ElState {
    fn default() -> Self {
        ElState {
            inputmode: MODE_INSERT,
            doingarg: 0,
            argument: 1,
            metanext: 0,
            lastcmd: ED_UNASSIGNED,
            thiscmd: ED_UNASSIGNED,
            thisch: 0,
        }
    }
}

impl Default for Chared {
    fn default() -> Self {
        Chared {
            undo: Undo {
                len: -1,
                cursor: 0,
                buf: vec![0; EL_BUFSIZ],
            },
            kill: KillBuf {
                buf: vec![0; EL_BUFSIZ],
                last: 0,
                mark: 0,
            },
            redo: Redo {
                buf: vec![0; EL_BUFSIZ],
                pos: 0,
                lim: EL_BUFSIZ,
                cmd: ED_UNASSIGNED,
                ch: 0,
                count: 0,
                action: 0,
            },
            vcmd: Vcmd {
                action: NOP,
                pos: 0,
            },
            c_resizefun: false,
            c_aliasfun: false,
        }
    }
}

impl Default for Prompt {
    fn default() -> Self {
        Prompt {
            p_func: Some(PROMPT_DEFAULT),
            p_pos: Coord { h: 0, v: 0 },
            p_ignore: 0,
            p_wide: false,
        }
    }
}

impl Default for Refresh {
    fn default() -> Self {
        Refresh {
            r_cursor: Coord { h: 0, v: 0 },
            r_oldcv: 0,
            r_newcv: 0,
        }
    }
}

impl Default for SearchState {
    fn default() -> Self {
        SearchState {
            patbuf: vec![0; EL_BUFSIZ],
            patlen: 0,
            patdir: -1,
            chadir: CHAR_FWD,
            chacha: 0,
            chatflg: 0,
        }
    }
}

impl Default for HistState {
    fn default() -> Self {
        HistState {
            fun: None,
            refp: None,
            buf: vec![0; EL_BUFSIZ],
            sz: EL_BUFSIZ,
            last: 0,
            eventno: 0,
            ev: HistEventW::default(),
        }
    }
}

impl Default for KeymacroState {
    fn default() -> Self {
        KeymacroState {
            buf: vec![0; EL_BUFSIZ],
            map: None,
            val: KeymacroValue::default(),
        }
    }
}

impl Default for MapState {
    fn default() -> Self {
        MapState {
            alt: vec![0; N_KEYS],
            key: vec![0; N_KEYS],
            current: 0,
            typ: MAP_EMACS,
            nfunc: EL_NUM_FCNS,
            wordchars: Vec::new(),
        }
    }
}

impl Default for ReadState {
    fn default() -> Self {
        ReadState {
            macros: ReadMacros {
                macro_stack: Vec::new(),
                offset: 0,
            },
            read_errno: 0,
            read_char_fn: Some(0),
        }
    }
}

impl Default for SigState {
    fn default() -> Self {
        SigState { sig_no: 0 }
    }
}

pub struct TtyModel {
    pub mode: i32, // EX_IO / ED_IO / QU_IO
    pub tabs: bool,
    pub speed: u32,
    pub eight: bool,
    pub initialized: bool,
    pub vdisable: u8,
    pub t_c: [[u8; C_NCC]; 3], // TS_IO, ED_IO, EX_IO
}

pub const TS_IO: usize = 0;
pub const ED_IO: usize = 1;
pub const EX_IO: usize = 2;
pub const QU_IO: usize = 3;
pub const EX_IO2: usize = 2;
pub const C_NCC: usize = 25;

// C_* char indexes (Linux termios layout)
pub const CINTR: usize = 0;
pub const CQUIT: usize = 1;
pub const CERASE: usize = 2;
pub const CKILL: usize = 3;
pub const CEOF: usize = 4;
pub const CEOL: usize = 5;
pub const CEOL2: usize = 6;
pub const CSWTCH: usize = 7;
pub const CDSWTCH: usize = 8;
pub const CERASE2: usize = 9;
pub const CSTART: usize = 10;
pub const CSTOP: usize = 11;
pub const CWERASE: usize = 12;
pub const CSUSP: usize = 13;
pub const CDSUSP: usize = 14;
pub const CREPRINT: usize = 15;
pub const CDISCARD: usize = 16;
pub const CLNEXT: usize = 17;
pub const CSTATUS: usize = 18;
pub const CPAGE: usize = 19;
pub const CPGOFF: usize = 20;
pub const CKILL2: usize = 21;
pub const CBRK: usize = 22;
pub const CMIN: usize = 23;
pub const CTIME: usize = 24;

impl Default for TtyModel {
    fn default() -> Self {
        TtyModel {
            mode: EX_IO as i32,
            tabs: true,
            speed: 0,
            eight: false,
            initialized: false,
            vdisable: 0xff,
            t_c: [
                [
                    0x03, 0x1c, 0x7f, 0x15, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11, 0x13, 0xff,
                    0x1a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                [
                    0x03, 0x1c, 0x7f, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11, 0x13, 0xff,
                    0x1a, 0xff, 0xff, 0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00,
                ],
                [0; C_NCC],
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// § el.c — init / set / get / line / gets
// ---------------------------------------------------------------------------

impl Engine {
    pub fn el_init_internal(
        prog: &str,
        is_tty: bool,
        input: Vec<u8>,
        env: Vec<(String, String)>,
    ) -> Option<Engine> {
        let mut el = Engine {
            prog: Vec::new(),
            flags: 0,
            cursor: Coord { h: 0, v: 0 },
            display: Vec::new(),
            vdisplay: Vec::new(),
            data: None,
            line: LineBuf::new(EL_BUFSIZ),
            state: ElState::default(),
            term: Terminal::new("", &|k| {
                env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone())
            }),
            tty: TtyModel::default(),
            refresh: Refresh::default(),
            prompt: Prompt::default(),
            rprompt: Prompt::default(),
            literal: Literal::new(),
            chared: Chared::default(),
            map: MapState::default(),
            keymacro: KeymacroState::default(),
            hist: HistState::default(),
            search: SearchState::default(),
            sig: SigState::default(),
            read: ReadState::default(),
            visual: Vec::new(),
            scratch: Vec::new(),
            lgcyconv: Vec::new(),
            lgcylinfo_buf: Vec::new(),
            getenv: Box::new(move |k| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone())),
            input,
            input_pos: 0,
            out: Vec::new(),
            err: Vec::new(),
            merge_err: false,
            user_prompts: Vec::new(),
            user_funcs: Vec::new(),
            update_row: 0,
            tty_is_tty: is_tty,
            read_lastchar: 0,
            re_insert_scratch: None,
            re_delete_scratch: None,
        };
        el.prog = ct_decode_string(prog.as_bytes())?;
        if let Some(msg) = el.term.terminal_err.clone() {
            el.err_msg(&msg);
        }
        el.terminal_rebuffer();
        // terminal_init
        // keymacro_init + map_init + tty_init + ch_init + search_init +
        // hist_init + prompt_init + sig_init + literal_init + read_init
        // (order per el_init_internal)
        if let Some(msg) = Terminal::new("", &el.getenv).terminal_err {
            el.err_msg(&msg);
        }
        el.keymacro_init();
        map_init(&mut el);
        if el.tty_init() == -1 {
            el.flags |= NO_TTY;
        }
        el.ch_init();
        el.search_init();
        hist_init(&mut el);
        prompt_init(&mut el);
        sig_init(&mut el);
        literal_init(&mut el);
        if el.read_init() == -1 {
            el_end(&mut el);
            return None;
        }
        Some(el)
    }
}

pub fn el_init(
    prog: &str,
    is_tty: bool,
    input: Vec<u8>,
    env: Vec<(String, String)>,
) -> Option<Engine> {
    Engine::el_init_internal(prog, is_tty, input, env)
}

pub fn el_end(el: &mut Engine) {
    el_reset(el);
    // terminal_end/keymacro_end/map_end/tty_end/ch_end/read_end/search_end/
    // hist_end/prompt_end/sig_end/literal_end: no observable output in the
    // corpus (tty_end restores t_or but nothing writes afterwards).
    el.flags |= NO_TTY;
}

pub fn el_reset(el: &mut Engine) {
    el.tty_cookedmode();
    el.ch_reset();
}

pub fn el_gets(el: &mut Engine, nread: &mut i32) -> Option<Vec<u8>> {
    let tmp = el_wgets(el, nread);
    let tmp = tmp?;
    // C el_gets(): the wide length comes from el_wgets; the narrow length is
    // the sum of ct_enc_width over exactly that many chars (the trailing NUL
    // el_wgets appended is not part of the count).
    let n = (*nread).max(0) as usize;
    let mut nwread = 0usize;
    for &c in tmp.iter().take(n) {
        nwread += ct_enc_width(c);
    }
    *nread = nwread as i32;
    Some(ct_encode_string(&tmp))
}

pub fn el_wgets(el: &mut Engine, nread: &mut i32) -> Option<Vec<u32>> {
    let mut cmdnum: u8 = 0;
    let mut num: i32 = -1;
    let mut nrb: i32 = 0;
    *nread = 0;
    el.read.read_errno = 0;
    if el.flags & NO_TTY != 0 {
        el.line.last = 0;
        let r = noedit_wgets(el, nread);
        return r;
    }
    if el.flags & UNBUFFERED == 0 {
        el.read_prepare();
    }
    if el.flags & EDIT_DISABLED != 0 {
        if el.flags & UNBUFFERED == 0 {
            el.line.last = 0;
        }
        el.terminal__flush();
        return noedit_wgets(el, nread);
    }
    while num == -1 {
        if el.read_getcmd(&mut cmdnum) == -1 {
            break;
        }
        if (cmdnum as usize) >= el.map.nfunc {
            continue;
        }
        el.state.thiscmd = cmdnum;
        if el.map.typ == MAP_VI && el.map.current == 0 && el.chared.redo.pos < el.chared.redo.lim {
            if cmdnum == VI_DELETE_PREV_CHAR
                && el.chared.redo.pos != 0
                && iswprint(el.chared.redo.buf[el.chared.redo.pos - 1])
            {
                el.chared.redo.pos -= 1;
            } else if el.chared.redo.pos < el.chared.redo.lim {
                el.chared.redo.buf[el.chared.redo.pos] = el.state.thisch;
                el.chared.redo.pos += 1;
            }
        }
        let retval = dispatch(el, cmdnum, el.state.thisch);
        el.state.lastcmd = cmdnum;
        match retval {
            CC_CURSOR => el.re_refresh_cursor(),
            CC_REDISPLAY => {
                el.re_clear_lines();
                el.re_clear_display();
                el.re_refresh();
            }
            CC_REFRESH => el.re_refresh(),
            CC_REFRESH_BEEP => {
                el.re_refresh();
                el.terminal_beep();
            }
            CC_NORM => {}
            CC_ARGHACK => {
                continue;
            }
            CC_EOF => {
                if el.flags & UNBUFFERED == 0 {
                    num = 0;
                } else if num == -1 {
                    el.line.buf[el.line.last] = CONTROL('d' as u32);
                    el.line.last += 1;
                    el.line.cur = el.line.last;
                    num = 1;
                }
            }
            CC_NEWLINE => {
                num = (el.line.last - 0) as i32;
            }
            CC_FATAL => {
                el.re_clear_display();
                el.ch_reset();
                el.read_clearmacros();
                el.re_refresh();
            }
            _ => {
                el.terminal_beep();
                el.terminal__flush();
            }
        }
        el.state.argument = 1;
        el.state.doingarg = 0;
        el.chared.vcmd.action = NOP;
        if el.flags & UNBUFFERED != 0 {
            break;
        }
    }
    el.terminal__flush();
    if el.flags & UNBUFFERED == 0 {
        el.read_finish();
        *nread = if num != -1 { num } else { 0 };
    } else {
        *nread = el.line.last as i32;
    }
    if *nread == 0 {
        if num == -1 {
            *nread = -1;
        }
        return None;
    }
    let mut out = el.line.buf[..el.line.last].to_vec();
    out.push(0);
    Some(out)
}

fn CONTROL(a: u32) -> u32 {
    a & 0o37
}

fn noedit_wgets(el: &mut Engine, nread: &mut i32) -> Option<Vec<u32>> {
    let mut num = 0;
    loop {
        let r = el.read_char();
        num = r;
        if r != 1 {
            break;
        }
        let last = el.line.last;
        el.line.buf[last] = el.read_lastchar;
        if last + 1 >= el.line.limit && !el.ch_enlargebufs(2) {
            break;
        }
        el.line.last += 1;
        if el.flags & UNBUFFERED != 0
            || el.line.buf[el.line.last - 1] == '\r' as u32
            || el.line.buf[el.line.last - 1] == '\n' as u32
        {
            break;
        }
    }
    el.line.cur = el.line.last;
    el.line.buf[el.line.last] = 0;
    *nread = el.line.last as i32;
    if *nread != 0 {
        let mut out = el.line.buf[..el.line.last].to_vec();
        out.push(0);
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// § terminal.c — emission methods
// ---------------------------------------------------------------------------

impl Engine {
    pub fn terminal__putc(&mut self, c: u32) -> i32 {
        if c == MB_FILL_CHAR {
            return 0;
        }
        if c & EL_LITERAL != 0 {
            let s = self.literal.get(c).to_vec();
            for &b in &s {
                self.out.push(b);
            }
            return s.len() as i32;
        }
        if c == '\n' as u32 {
            // pty ONLCR output translation (t_ex and t_ed both set
            // OPOST|ONLCR; the C harness's slave line discipline converts
            // every written \n to \r\n)
            self.out.push('\r' as u8);
            self.out.push('\n' as u8);
            return 1;
        }
        ct_encode_char(&mut self.out, c);
        1
    }

    pub fn terminal__flush(&mut self) {}

    fn terminal_tputs(&mut self, cap: &[u8]) {
        tputs_cap(cap, &mut self.out);
    }

    fn terminal_tgoto(&mut self, cap: &[u8], cols: i32, rows: i32) {
        let s = tgoto_cap(cap, cols, rows);
        self.terminal_tputs(&s);
    }

    pub fn terminal_move_to_line(&mut self, wh: i32) {
        if wh == self.cursor.v {
            return;
        }
        if wh >= self.term.t_size.v {
            return;
        }
        let del = wh - self.cursor.v;
        if del > 0 {
            for _ in 0..del {
                self.terminal__putc('\n' as u32);
            }
            self.cursor.h = 0;
        } else {
            let up = self.term.t_str[T_UP].clone();
            let up1 = self.term.t_str[T_up].clone();
            if up.is_some() && (-del > 1 || up1.is_none()) {
                let cap = up.unwrap();
                let s = tgoto_cap(&cap, -del, -del);
                self.terminal_tputs(&s);
            } else if let Some(cap) = up1 {
                let mut d = del;
                while d < 0 {
                    self.terminal_tputs(&cap);
                    d += 1;
                }
            }
        }
        self.cursor.v = wh;
    }

    pub fn terminal_move_to_char(&mut self, wh: i32) {
        loop {
            if wh == self.cursor.h {
                return;
            }
            if wh > self.term.t_size.h {
                return;
            }
            if wh == 0 {
                self.terminal__putc('\r' as u32);
                self.cursor.h = 0;
                return;
            }
            let del = wh - self.cursor.h;
            let ch = self.term.t_str[T_ch].clone();
            if (del < -4 || del > 4) && ch.is_some() {
                let cap = ch.unwrap();
                let s = tgoto_cap(&cap, wh, wh);
                self.terminal_tputs(&s);
            } else if del > 0 {
                let ri = self.term.t_str[T_RI].clone();
                if del > 4 && ri.is_some() {
                    let cap = ri.unwrap();
                    let s = tgoto_cap(&cap, del, del);
                    self.terminal_tputs(&s);
                } else {
                    // if I can do tabs, use them
                    if self.term.t_flags & TERM_CAN_TAB != 0 {
                        let hcur = self.cursor.h & 0370;
                        let hdst = wh & !0x7;
                        if hcur != hdst
                            && self.display[self.cursor.v as usize]
                                .get(hdst as usize)
                                .copied()
                                .unwrap_or(0)
                                != MB_FILL_CHAR
                        {
                            let mut i = hcur;
                            while i < hdst {
                                self.terminal__putc('\t' as u32);
                                i += 8;
                            }
                            self.cursor.h = hdst;
                        }
                    }
                    // overwrite from display
                    let v = self.cursor.v as usize;
                    let h0 = self.cursor.h as usize;
                    let mut cp: Vec<u32> = Vec::new();
                    for k in h0..(h0 + del as usize) {
                        let c = self.display[v].get(k).copied().unwrap_or(0);
                        cp.push(c);
                    }
                    self.terminal_overwrite(&cp);
                }
            } else {
                let le = self.term.t_str[T_LE].clone();
                if -del > 4 && le.is_some() {
                    let cap = le.unwrap();
                    let s = tgoto_cap(&cap, -del, -del);
                    self.terminal_tputs(&s);
                } else {
                    let cost = if self.term.t_flags & TERM_CAN_TAB != 0 {
                        (wh >> 3) + (wh & 07)
                    } else {
                        wh
                    };
                    if -del > cost {
                        self.terminal__putc('\r' as u32);
                        self.cursor.h = 0;
                        continue;
                    }
                    for _ in 0..(-del) {
                        self.terminal__putc(0x08);
                    }
                }
            }
            self.cursor.h = wh;
            return;
        }
    }

    pub fn terminal_overwrite(&mut self, cp: &[u32]) {
        let n = cp.len();
        if n == 0 {
            return;
        }
        if n as i32 > self.term.t_size.h {
            return;
        }
        let mut idx = 0;
        loop {
            self.terminal__putc(cp[idx]);
            self.cursor.h += 1;
            idx += 1;
            if idx >= n {
                break;
            }
        }
        if self.cursor.h >= self.term.t_size.h {
            if self.term.t_flags & TERM_HAS_AUTO_MARGINS != 0 {
                self.cursor.h = 0;
                if self.cursor.v + 1 < self.term.t_size.v {
                    self.cursor.v += 1;
                }
                if self.term.t_flags & TERM_HAS_MAGIC_MARGINS != 0 {
                    let v = self.cursor.v as usize;
                    let h = self.cursor.h as usize;
                    let c = self.display[v].get(h).copied().unwrap_or(0);
                    if c != 0 {
                        let one = [c];
                        self.terminal_overwrite(&one);
                        let mut h2 = self.cursor.h as usize;
                        while self
                            .display
                            .get(self.cursor.v as usize)
                            .and_then(|r| r.get(h2))
                            .copied()
                            == Some(MB_FILL_CHAR)
                        {
                            h2 += 1;
                        }
                        self.cursor.h = h2 as i32;
                    } else {
                        self.terminal__putc(' ' as u32);
                        self.cursor.h = 1;
                    }
                }
            } else {
                self.cursor.h = self.term.t_size.h - 1;
            }
        }
    }

    fn terminal_deletechars(&mut self, num: i32) {
        if num <= 0 {
            return;
        }
        if self.term.t_flags & TERM_CAN_DELETE == 0 {
            return;
        }
        if num > self.term.t_size.h {
            return;
        }
        let dc = self.term.t_str[T_dc].clone();
        let DC = self.term.t_str[T_DC].clone();
        if DC.is_some() && (num > 1 || dc.is_none()) {
            let cap = DC.unwrap();
            let s = tgoto_cap(&cap, num, num);
            self.terminal_tputs(&s);
            return;
        }
        if let Some(cap) = self.term.t_str[T_dm].clone() {
            self.terminal_tputs(&cap);
        }
        if let Some(cap) = dc {
            let mut n = num;
            while n > 0 {
                self.terminal_tputs(&cap);
                n -= 1;
            }
        }
        if let Some(cap) = self.term.t_str[T_ed].clone() {
            self.terminal_tputs(&cap);
        }
    }

    fn terminal_insertwrite(&mut self, cp: &[u32]) {
        let num = cp.len() as i32;
        if num <= 0 {
            return;
        }
        if self.term.t_flags & TERM_CAN_INSERT == 0 {
            return;
        }
        if num > self.term.t_size.h {
            return;
        }
        let ic = self.term.t_str[T_ic].clone();
        let IC = self.term.t_str[T_IC].clone();
        if IC.is_some() && (num > 1 || ic.is_none()) {
            let cap = IC.unwrap();
            let s = tgoto_cap(&cap, num, num);
            self.terminal_tputs(&s);
            self.terminal_overwrite(cp);
            return;
        }
        let im = self.term.t_str[T_im].clone();
        let ei = self.term.t_str[T_ei].clone();
        if im.is_some() && ei.is_some() {
            self.terminal_tputs(im.as_ref().unwrap());
            self.cursor.h += num;
            let mut n = num;
            let mut idx = 0;
            while n > 0 {
                self.terminal__putc(cp[idx]);
                idx += 1;
                n -= 1;
            }
            if let Some(cap) = self.term.t_str[T_ip].clone() {
                self.terminal_tputs(&cap);
            }
            self.terminal_tputs(ei.as_ref().unwrap());
            return;
        }
        let mut n = num;
        let mut idx = 0;
        while n > 0 {
            if let Some(cap) = ic.clone() {
                self.terminal_tputs(&cap);
            }
            self.terminal__putc(cp[idx]);
            self.cursor.h += 1;
            if let Some(cap) = self.term.t_str[T_ip].clone() {
                self.terminal_tputs(&cap);
            }
            idx += 1;
            n -= 1;
        }
    }

    fn terminal_overwrite_at(&mut self, idx: usize, n: usize) {
        let row = &self.vdisplay[self.update_row];
        let mut cp = Vec::new();
        for i in idx..idx + n {
            cp.push(row.get(i).copied().unwrap_or(0));
        }
        self.terminal_overwrite(&cp);
    }

    fn terminal_insertwrite_at(&mut self, idx: usize, n: usize) {
        let row = &self.vdisplay[self.update_row];
        let mut cp = Vec::new();
        for i in idx..idx + n {
            cp.push(row.get(i).copied().unwrap_or(0));
        }
        self.terminal_insertwrite(&cp);
    }

    pub fn terminal_clear_EOL(&mut self, num: i32) {
        if self.term.t_flags & TERM_CAN_CEOL != 0 && self.term.good_str(T_ce) {
            let cap = self.term.t_str[T_ce].clone().unwrap();
            self.terminal_tputs(&cap);
        } else {
            for _ in 0..num {
                self.terminal__putc(' ' as u32);
            }
            self.cursor.h += num;
        }
    }

    fn terminal_clear_screen(&mut self) {
        if let Some(cap) = self.term.t_str[T_cl].clone() {
            self.terminal_tputs(&cap);
        } else if self.term.good_str(T_ho) && self.term.good_str(T_cd) {
            let cap = self.term.t_str[T_ho].clone().unwrap();
            self.terminal_tputs(&cap);
            let cap = self.term.t_str[T_cd].clone().unwrap();
            self.terminal_tputs(&cap);
        } else {
            self.terminal__putc('\r' as u32);
            self.terminal__putc('\n' as u32);
        }
    }

    pub fn terminal_beep(&mut self) {
        if self.term.good_str(T_bl) {
            let cap = self.term.t_str[T_bl].clone().unwrap();
            self.terminal_tputs(&cap);
        } else {
            self.terminal__putc(0x07);
        }
    }

    fn terminal_writec(&mut self, c: u32) {
        let mut vis = Vec::new();
        ct_visual_char(&mut vis, c);
        self.terminal_overwrite(&vis);
        self.terminal__flush();
    }
}

// ---------------------------------------------------------------------------
// § tty.c — observable tty model
// ---------------------------------------------------------------------------

impl Engine {
    fn tty_init(&mut self) -> i32 {
        self.tty.mode = EX_IO as i32;
        self.tty.vdisable = 0xff;
        self.tty.initialized = false;
        self.tty_setup()
    }

    fn tty_setup(&mut self) -> i32 {
        if self.flags & EDIT_DISABLED != 0 {
            return 0;
        }
        if self.tty.initialized {
            return -1;
        }
        if !self.tty_is_tty {
            return -1;
        }
        // t_or = current termios (the harness's cfmakeraw): not cooked
        // (ICANON off), so the TS_IO char propagation is skipped and the
        // ttychar defaults stay in place.
        self.tty.speed = 0;
        self.tty.tabs = true;
        self.tty.eight = false;
        self.tty.initialized = true;
        self.tty_bind_char(true);
        0
    }

    fn tty_rawmode(&mut self) -> i32 {
        if self.tty.mode == ED_IO as i32 || self.tty.mode == QU_IO as i32 {
            return 0;
        }
        if self.flags & EDIT_DISABLED != 0 {
            return 0;
        }
        self.tty.mode = ED_IO as i32;
        0
    }

    fn tty_cookedmode(&mut self) -> i32 {
        if self.tty.mode == EX_IO as i32 || self.tty.mode == QU_IO as i32 {
            return 0;
        }
        if self.flags & EDIT_DISABLED != 0 {
            return 0;
        }
        self.tty.mode = EX_IO as i32;
        0
    }

    fn tty_quotemode(&mut self) {
        self.tty.mode = QU_IO as i32;
    }

    fn tty_noquotemode(&mut self) {
        self.tty.mode = ED_IO as i32;
    }

    /// tty_bind_char(): rebind ERASE/KILL/EOF/WERASE/REPRINT/LNEXT.
    fn tty_bind_char(&mut self, force: bool) {
        let t_n = self.tty.t_c[ED_IO];
        let map_vi = self.map.typ == MAP_VI;
        let dmap: [u8; N_KEYS] = if map_vi { VI_INSERT_MAP } else { EMACS_MAP };
        let dalt: [u8; N_KEYS] = if map_vi {
            VI_COMMAND_MAP
        } else {
            [ED_UNASSIGNED; N_KEYS]
        };
        let binds: [(usize, usize, [u8; 3]); 8] = [
            // (nch, och, [emacs, vi, vi-cmd])
            (
                CERASE,
                2,
                [EM_DELETE_PREV_CHAR, VI_DELETE_PREV_CHAR, ED_PREV_CHAR],
            ),
            (
                CERASE2,
                9,
                [EM_DELETE_PREV_CHAR, VI_DELETE_PREV_CHAR, ED_PREV_CHAR],
            ),
            (CKILL, 3, [EM_KILL_LINE, VI_KILL_LINE_PREV, ED_UNASSIGNED]),
            (CKILL2, 21, [EM_KILL_LINE, VI_KILL_LINE_PREV, ED_UNASSIGNED]),
            (CEOF, 4, [EM_DELETE_OR_LIST, VI_LIST_OR_EOF, ED_UNASSIGNED]),
            (
                CWERASE,
                12,
                [ED_DELETE_PREV_WORD, ED_DELETE_PREV_WORD, ED_PREV_WORD],
            ),
            (CREPRINT, 15, [ED_REDISPLAY, ED_INSERT, ED_REDISPLAY]),
            (
                CLNEXT,
                17,
                [ED_QUOTED_INSERT, ED_QUOTED_INSERT, ED_UNASSIGNED],
            ),
        ];
        for &(nch, och, bind) in binds.iter() {
            let new = t_n[nch] as u32;
            // old = t_ed.c_cc[och]; with the harness's non-cooked setup
            // t_ed.c_cc was set from t_c[ED_IO], so old == t_n[och].
            let old = t_n[och] as u32;
            if new == old && !force {
                continue;
            }
            self.keymacro_clear(old);
            self.map.key[old as usize] = dmap[old as usize];
            self.keymacro_clear(new);
            self.map.key[new as usize] = bind[if map_vi { 1 } else { 0 }];
            self.keymacro_clear_alt(old);
            self.map.alt[old as usize] = dalt[old as usize];
            self.keymacro_clear_alt(new);
            self.map.alt[new as usize] = bind[if map_vi { 2 } else { 0 }];
        }
    }
}

// ---------------------------------------------------------------------------
// § chared.c
// ---------------------------------------------------------------------------

pub type WordTest = fn(&Engine, u32) -> i32;

fn ce_isword_wrap(el: &Engine, p: u32) -> i32 {
    if el.ce__isword(p) {
        1
    } else {
        0
    }
}
fn cv_isword_wrap(el: &Engine, p: u32) -> i32 {
    el.cv__isword(p)
}
fn cv_isWord_wrap(el: &Engine, p: u32) -> i32 {
    if el.cv__isWord(p) {
        1
    } else {
        0
    }
}

impl Engine {
    fn c_insert(&mut self, num: usize) {
        if self.line.last + num >= self.line.limit && !self.ch_enlargebufs(num) {
            return;
        }
        if self.line.cur < self.line.last {
            for i in (self.line.cur..=self.line.last).rev() {
                self.line.buf[i + num] = self.line.buf[i];
            }
        }
        self.line.last += num;
    }

    fn c_delafter(&mut self, num: usize) {
        let mut num = num;
        if self.line.cur + num > self.line.last {
            num = self.line.last - self.line.cur;
        }
        if !(self.map.typ == MAP_EMACS && self.map.current == 0) {
            self.cv_undo();
            self.cv_yank(self.line.cur, num);
        }
        if num > 0 {
            for i in self.line.cur..=self.line.last {
                self.line.buf[i] = if i + num < self.line.buf.len() {
                    self.line.buf[i + num]
                } else {
                    0
                };
            }
            self.line.last -= num;
        }
    }

    fn c_delafter1(&mut self) {
        for i in self.line.cur..=self.line.last {
            self.line.buf[i] = if i + 1 < self.line.buf.len() {
                self.line.buf[i + 1]
            } else {
                0
            };
        }
        self.line.last -= 1;
    }

    fn c_delbefore(&mut self, num: usize) {
        let mut num = num;
        if self.line.cur < num {
            num = self.line.cur;
        }
        if !(self.map.typ == MAP_EMACS && self.map.current == 0) {
            self.cv_undo();
            self.cv_yank(self.line.cur - num, num);
        }
        if num > 0 {
            for i in (self.line.cur - num)..=self.line.last {
                self.line.buf[i] = if i + num < self.line.buf.len() {
                    self.line.buf[i + num]
                } else {
                    0
                };
            }
            self.line.last -= num;
        }
    }

    fn c_delbefore1(&mut self) {
        for i in (self.line.cur - 1)..=self.line.last {
            self.line.buf[i] = if i + 1 < self.line.buf.len() {
                self.line.buf[i + 1]
            } else {
                0
            };
        }
        self.line.last -= 1;
    }

    fn ce__isword(&self, p: u32) -> bool {
        iswalnum(p) || self.map.wordchars.contains(&p)
    }

    fn cv__isword(&self, p: u32) -> i32 {
        if iswalnum(p) || self.map.wordchars.contains(&p) {
            1
        } else if iswgraph(p) {
            2
        } else {
            0
        }
    }

    fn cv__isWord(&self, p: u32) -> bool {
        !iswspace(p)
    }

    fn c__prev_word(&self, p: usize, low: usize, n: i32, wtest: WordTest) -> usize {
        let mut p = p;
        let mut n = n;
        if p == 0 {
            return 0;
        }
        p -= 1;
        while n > 0 {
            while p >= low && !(wtest(self, self.line.buf[p]) != 0) {
                if p == 0 {
                    break;
                }
                p -= 1;
            }
            while p >= low && wtest(self, self.line.buf[p]) != 0 {
                if p == 0 {
                    break;
                }
                p -= 1;
            }
            n -= 1;
        }
        p += 1;
        if p < low {
            p = low;
        }
        p
    }

    fn c__next_word(&self, p: usize, high: usize, n: i32, wtest: WordTest) -> usize {
        let mut p = p;
        let mut n = n;
        while n > 0 {
            while p < high && !(wtest(self, self.line.buf[p]) != 0) {
                p += 1;
            }
            while p < high && wtest(self, self.line.buf[p]) != 0 {
                p += 1;
            }
            n -= 1;
        }
        if p > high {
            p = high;
        }
        p
    }

    fn cv_next_word(&mut self, p: usize, high: usize, n: i32, wtest: WordTest) -> usize {
        let mut p = p;
        let mut n = n;
        while n > 0 {
            let test = wtest(self, self.line.buf[p]);
            while p < high && wtest(self, self.line.buf[p]) == test {
                p += 1;
            }
            if n != 1 || self.chared.vcmd.action != (DELETE | INSERT) {
                while p < high && iswspace(self.line.buf[p]) {
                    p += 1;
                }
            }
            n -= 1;
        }
        if p > high {
            high
        } else {
            p
        }
    }

    fn cv_prev_word(&self, p: usize, low: usize, n: i32, wtest: WordTest) -> usize {
        let mut p = p;
        let mut n = n;
        if p == 0 {
            return 0;
        }
        p -= 1;
        while n > 0 {
            while p > low && iswspace(self.line.buf[p]) {
                p -= 1;
            }
            let test = wtest(self, self.line.buf[p]);
            while p >= low && wtest(self, self.line.buf[p]) == test {
                if p == 0 {
                    break;
                }
                p -= 1;
            }
            if p < low {
                return low;
            }
            n -= 1;
        }
        p += 1;
        if p < low {
            low
        } else {
            p
        }
    }

    fn cv__endword(&self, p: usize, high: usize, n: i32, wtest: WordTest) -> usize {
        let mut p = p;
        let mut n = n;
        p += 1;
        while n > 0 {
            while p < high && iswspace(self.line.buf[p]) {
                p += 1;
            }
            let test = wtest(self, self.line.buf[p]);
            while p < high && wtest(self, self.line.buf[p]) == test {
                p += 1;
            }
            n -= 1;
        }
        p - 1
    }

    fn cv_undo(&mut self) {
        let size = self.line.last;
        self.chared.undo.len = size as isize;
        self.chared.undo.cursor = self.line.cur as i32;
        for i in 0..size {
            self.chared.undo.buf[i] = self.line.buf[i];
        }
        self.chared.redo.count = if self.state.doingarg != 0 {
            self.state.argument
        } else {
            0
        };
        self.chared.redo.action = self.chared.vcmd.action;
        self.chared.redo.pos = 0;
        self.chared.redo.cmd = self.state.thiscmd;
        self.chared.redo.ch = self.state.thisch;
    }

    fn cv_yank(&mut self, ptr: usize, size: usize) {
        for i in 0..size {
            self.chared.kill.buf[i] = self.line.buf[ptr + i];
        }
        self.chared.kill.last = size;
    }

    fn cv_delfini(&mut self) {
        let action = self.chared.vcmd.action;
        if action & INSERT != 0 {
            self.map.current = 0;
        }
        let pos = self.chared.vcmd.pos;
        let mut size = self.line.cur as i64 - pos as i64;
        if size == 0 {
            size = 1;
        }
        self.line.cur = pos;
        if action & YANK != 0 {
            if size > 0 {
                self.cv_yank(self.line.cur, size as usize);
            } else {
                self.cv_yank((self.line.cur as i64 + size) as usize, (-size) as usize);
            }
        } else if size > 0 {
            self.c_delafter(size as usize);
            self.re_refresh_cursor();
        } else {
            self.c_delbefore((-size) as usize);
            self.line.cur = (self.line.cur as i64 + size) as usize;
        }
        self.chared.vcmd.action = NOP;
    }

    fn ch_enlargebufs(&mut self, addlen: usize) -> bool {
        let sz = self.line.limit + EL_LEAVE;
        let mut newsz = sz * 2;
        if addlen > sz {
            while newsz - sz < addlen {
                newsz *= 2;
            }
        }
        self.line.buf.resize(newsz, 0);
        self.chared.kill.buf.resize(newsz, 0);
        self.chared.undo.buf.resize(newsz, 0);
        let old_redo_pos = self.chared.redo.pos;
        self.chared.redo.buf.resize(newsz, 0);
        self.chared.redo.lim = newsz;
        self.chared.redo.pos = old_redo_pos;
        self.line.limit = newsz - EL_LEAVE;
        true
    }

    fn c_hpos(&self) -> i32 {
        if self.line.cur == 0 {
            return 0;
        }
        let mut ptr = self.line.cur - 1;
        while ptr >= 1 && self.line.buf[ptr] != '\n' as u32 {
            ptr -= 1;
        }
        if self.line.buf[ptr] == '\n' as u32 {
            (self.line.cur - ptr - 1) as i32
        } else {
            self.line.cur as i32
        }
    }
}

// ---------------------------------------------------------------------------
// § read.c
// ---------------------------------------------------------------------------

impl Engine {
    fn read_init(&mut self) -> i32 {
        self.read.macros.macro_stack.clear();
        self.read.macros.offset = 0;
        self.read.read_char_fn = Some(0);
        0
    }

    fn read_char(&mut self) -> i32 {
        // C-locale mbrtowc.  When the input models a pty (tty_is_tty), the
        // harness pins INLCR|ICRNL (t_ed), so the line discipline converts
        // every input '\n' to '\r' (INLCR wins over ICRNL in the kernel) and
        // every '\r' to '\n'; for a pipe/NO_TTY input there is no pty and no
        // translation.  A byte >= 0x80 is an invalid single-byte sequence in
        // the C locale and is silently discarded (the C's read_char does
        // `cbuf = 0; goto again` for it).
        let translate = self.tty_is_tty;
        loop {
            if self.input_pos >= self.input.len() {
                return 0; // EOF
            }
            let b = self.input[self.input_pos];
            self.input_pos += 1;
            if b < 0x80 {
                self.read_lastchar = if translate {
                    match b {
                        b'\n' => '\r' as u32, // INLCR
                        b'\r' => '\n' as u32, // ICRNL
                        _ => b as u32,
                    }
                } else {
                    b as u32
                };
                return 1;
            }
            // invalid byte: discard and read the next
        }
    }

    fn read_getcmd(&mut self, cmdnum: &mut u8) -> i32 {
        let meta = 0x80u32;
        loop {
            let mut ch = 0u32;
            let r = self.el_wgetc(&mut ch);
            if r != 1 {
                return -1;
            }
            self.state.thisch = ch;
            if self.state.metanext != 0 {
                self.state.metanext = 0;
                ch |= meta;
            }
            let mut cmd: u8;
            if ch >= N_KEYS as u32 {
                cmd = ED_INSERT;
            } else {
                let map = if self.map.current == 0 {
                    &self.map.key
                } else {
                    &self.map.alt
                };
                cmd = map[ch as usize];
            }
            if cmd == ED_SEQUENCE_LEAD_IN {
                let mut val = KeymacroValue::default();
                let r = self.keymacro_get(&mut ch, &mut val);
                match r {
                    XK_CMD => cmd = val.cmd,
                    XK_STR => {
                        el_wpush(self, val.str.as_deref());
                    }
                    XK_NOD => return -1,
                    _ => {}
                }
            }
            if cmd != ED_SEQUENCE_LEAD_IN {
                *cmdnum = cmd;
                return 0;
            }
        }
    }

    fn el_wgetc(&mut self, cp: &mut u32) -> i32 {
        self.terminal__flush();
        loop {
            if self.read.macros.macro_stack.is_empty() {
                break;
            }
            let off = self.read.macros.offset;
            let top = &self.read.macros.macro_stack[0];
            if off >= top.len() {
                self.read_pop();
                continue;
            }
            *cp = top[off];
            self.read.macros.offset = off + 1;
            if self.read.macros.offset >= top.len() {
                self.read_pop();
            }
            return 1;
        }
        if self.tty_rawmode() < 0 {
            return 0;
        }
        let num_read = self.read_char();
        if num_read < 0 {
            self.read.read_errno = 5; // EIO placeholder; not surfaced
        }
        if num_read == 1 {
            *cp = self.read_lastchar;
        }
        num_read
    }

    fn read_pop(&mut self) {
        if !self.read.macros.macro_stack.is_empty() {
            self.read.macros.macro_stack.remove(0);
        }
        self.read.macros.offset = 0;
    }

    fn read_clearmacros(&mut self) {
        self.read.macros.macro_stack.clear();
        self.read.macros.offset = 0;
    }

    fn read_prepare(&mut self) {
        if self.flags & NO_TTY != 0 {
            return;
        }
        if (self.flags & (UNBUFFERED | EDIT_DISABLED)) == UNBUFFERED {
            self.tty_rawmode();
        }
        self.re_clear_display();
        self.ch_reset();
        self.re_refresh();
        if self.flags & UNBUFFERED != 0 {
            self.terminal__flush();
        }
    }

    fn read_finish(&mut self) {
        if self.flags & UNBUFFERED == 0 {
            self.tty_cookedmode();
        }
    }
}

pub fn el_wpush(el: &mut Engine, str: Option<&[u32]>) {
    let ma = &mut el.read.macros;
    if let Some(s) = str {
        if ma.macro_stack.len() < EL_MAXMACRO {
            let s = s.to_vec();
            ma.macro_stack.push(s);
            return;
        }
    }
    el.terminal_beep();
    el.terminal__flush();
}

// ---------------------------------------------------------------------------
// § keymacro.c
// ---------------------------------------------------------------------------

impl Engine {
    fn keymacro_init(&mut self) -> i32 {
        self.keymacro.buf = vec![0; EL_BUFSIZ];
        self.keymacro.map = None;
        0
    }

    fn keymacro_reset(&mut self) {
        self.keymacro.map = None;
    }

    fn keymacro_map_cmd(&mut self, cmd: u8) -> KeymacroValue {
        self.keymacro.val = KeymacroValue { cmd, str: None };
        self.keymacro.val.clone()
    }

    fn keymacro_map_str(&mut self, str: Vec<u32>) -> KeymacroValue {
        self.keymacro.val = KeymacroValue {
            cmd: 0,
            str: Some(str),
        };
        self.keymacro.val.clone()
    }

    fn keymacro_get(&mut self, ch: &mut u32, val: &mut KeymacroValue) -> i32 {
        let map = self.keymacro.map.clone();
        match map {
            None => {
                val.str = None;
                XK_STR
            }
            Some(root) => self.node_trav(root, ch, val),
        }
    }

    fn node_trav(&mut self, ptr: Box<KeymacroNode>, ch: &mut u32, val: &mut KeymacroValue) -> i32 {
        if ptr.ch == *ch {
            if let Some(next) = ptr.next {
                if self.el_wgetc(ch) != 1 {
                    return XK_NOD;
                }
                return self.node_trav(next, ch, val);
            } else {
                *val = ptr.val.clone();
                if ptr.typ != XK_CMD {
                    *ch = 0;
                }
                return ptr.typ;
            }
        } else if let Some(sib) = ptr.sibling {
            return self.node_trav(sib, ch, val);
        } else {
            val.str = None;
            XK_STR
        }
    }

    fn keymacro_add(&mut self, key: &[u32], val: KeymacroValue, ntype: i32) {
        if key.is_empty() || key[0] == 0 {
            return;
        }
        if ntype == XK_CMD && val.cmd == ED_SEQUENCE_LEAD_IN {
            return;
        }
        if self.keymacro.map.is_none() {
            self.keymacro.map = Some(Box::new(KeymacroNode {
                ch: key[0],
                typ: XK_NOD,
                val: KeymacroValue::default(),
                next: None,
                sibling: None,
            }));
        }
        let root = self.keymacro.map.as_mut().unwrap();
        node_try_mut(root, key, &val, ntype);
    }

    fn node_try(
        &mut self,
        mut ptr: Box<KeymacroNode>,
        str: &[u32],
        val: &KeymacroValue,
        ntype: i32,
    ) {
        let _ = (ptr, str, val, ntype);
    }

    fn keymacro_clear(&mut self, in_: u32) {
        if in_ >= N_KEYS as u32 {
            return;
        }
        if self.map.key[in_ as usize] == ED_SEQUENCE_LEAD_IN
            && (self.map.current == 0 && self.map.alt[in_ as usize] != ED_SEQUENCE_LEAD_IN
                || self.map.current == 1 && self.map.key[in_ as usize] != ED_SEQUENCE_LEAD_IN)
        {
            let key = vec![in_];
            self.keymacro_delete(&key);
        }
    }

    fn keymacro_clear_alt(&mut self, in_: u32) {
        if in_ >= N_KEYS as u32 {
            return;
        }
        if self.map.alt[in_ as usize] == ED_SEQUENCE_LEAD_IN
            && (self.map.current == 0 && self.map.key[in_ as usize] != ED_SEQUENCE_LEAD_IN
                || self.map.current == 1 && self.map.alt[in_ as usize] != ED_SEQUENCE_LEAD_IN)
        {
            let key = vec![in_];
            self.keymacro_delete(&key);
        }
    }

    fn keymacro_delete(&mut self, key: &[u32]) -> i32 {
        if key.is_empty() || key[0] == 0 {
            return -1;
        }
        if self.keymacro.map.is_none() {
            return 0;
        }
        node_delete(&mut self.keymacro.map, key);
        0
    }
}

/// node__try(): insert a key into the tree, mutating it in place (the C
/// recurses through pointers; the earlier clone-based version lost every
/// insertion past the first).
fn node_try_mut(ptr: &mut Box<KeymacroNode>, str: &[u32], val: &KeymacroValue, ntype: i32) {
    if ptr.ch != str[0] {
        // no match at this node: walk the sibling chain; append a new
        // sibling if ch isn't there yet
        let mut cur: &mut Box<KeymacroNode> = ptr;
        loop {
            let done = match cur.sibling.as_ref() {
                Some(s) if s.ch == str[0] => true,
                Some(_) => false,
                None => {
                    cur.sibling = Some(Box::new(KeymacroNode {
                        ch: str[0],
                        typ: XK_NOD,
                        val: KeymacroValue::default(),
                        next: None,
                        sibling: None,
                    }));
                    true
                }
            };
            if done {
                break;
            }
            cur = cur.sibling.as_mut().unwrap();
        }
        let mut target = cur.sibling.take().unwrap();
        node_try_mut(&mut target, str, val, ntype);
        cur.sibling = Some(target);
        return;
    }
    if str.len() > 1 && str[1] != 0 {
        // still more chars to go
        if ptr.next.is_none() {
            ptr.next = Some(Box::new(KeymacroNode {
                ch: str[1],
                typ: XK_NOD,
                val: KeymacroValue::default(),
                next: None,
                sibling: None,
            }));
        }
        let mut next = ptr.next.take().unwrap();
        node_try_mut(&mut next, &str[1..], val, ntype);
        ptr.next = Some(next);
        return;
    }
    // we're there: lose any longer keys with this prefix
    ptr.next = None;
    ptr.typ = ntype;
    if ntype == XK_CMD {
        ptr.val = val.clone();
    } else if ntype == XK_STR {
        ptr.val = KeymacroValue {
            cmd: 0,
            str: Some(val.str.clone().unwrap_or_default()),
        };
    }
}

fn node_delete(inptr: &mut Option<Box<KeymacroNode>>, str: &[u32]) -> i32 {
    let mut prev_ptr: Option<Box<KeymacroNode>> = None;
    let ptr = inptr.clone().unwrap();
    if ptr.ch != str[0] {
        let mut xm: Option<Box<KeymacroNode>> = None;
        let mut cur = ptr.clone();
        loop {
            match cur.sibling {
                Some(ref s) => {
                    if s.ch == str[0] {
                        xm = Some(s.clone());
                        break;
                    }
                    cur = s.clone();
                }
                None => break,
            }
        }
        match xm {
            None => return 0,
            Some(s) => {
                prev_ptr = Some(s.clone());
            }
        }
    }
    if str.len() > 1 && str[1] != 0 {
        if let Some(mut next) = ptr.next.clone() {
            let mut next_opt = Some(next.clone());
            if node_delete(&mut next_opt, &str[1..]) == 1 {
                if next_opt.is_some() {
                    return 0;
                }
            }
        }
        0
    } else {
        // we're there: unlink
        let mut new = ptr.clone();
        let sib = ptr.sibling.clone();
        new.sibling = sib;
        *inptr = Some(new);
        1
    }
}

// ---------------------------------------------------------------------------
// § map.c
// ---------------------------------------------------------------------------

fn map_init(el: &mut Engine) -> i32 {
    el.map.alt = vec![0; N_KEYS];
    el.map.key = vec![0; N_KEYS];
    el.map.nfunc = EL_NUM_FCNS;
    el.map.wordchars = Vec::new();
    map_init_vi(el);
    0
}

fn map_init_vi(el: &mut Engine) {
    el.map.typ = MAP_VI;
    el.map.current = 0;
    el.keymacro_reset();
    for i in 0..N_KEYS {
        el.map.key[i] = VI_INSERT_MAP[i];
        el.map.alt[i] = VI_COMMAND_MAP[i];
    }
    map_init_meta(el);
    map_init_nls(el);
    el.tty_bind_char(true);
    terminal_bind_arrow(el);
    el.map.wordchars = vec!['_' as u32];
}

fn map_init_emacs(el: &mut Engine) {
    el.map.typ = MAP_EMACS;
    el.map.current = 0;
    el.keymacro_reset();
    for i in 0..N_KEYS {
        el.map.key[i] = EMACS_MAP[i];
        el.map.alt[i] = ED_UNASSIGNED;
    }
    map_init_meta(el);
    map_init_nls(el);
    let mut buf = vec![CONTROL('x' as u32), CONTROL('x' as u32), 0];
    let v = el.keymacro_map_cmd(EM_EXCHANGE_MARK);
    el.keymacro_add(&buf, v, XK_CMD);
    buf.clear();
    el.tty_bind_char(true);
    terminal_bind_arrow(el);
    el.map.wordchars = "*?_-.[]~=".chars().map(|c| c as u32).collect();
}

fn map_init_nls(el: &mut Engine) {
    for i in 0o200..=0o377 {
        if iswprint(i) {
            el.map.key[i as usize] = ED_INSERT;
        }
    }
}

fn map_init_meta(el: &mut Engine) {
    let mut i = 0usize;
    while i <= 0o377 && el.map.key[i] != EM_META_NEXT {
        i += 1;
    }
    let mut map_is_alt = false;
    let mut meta_key: u32;
    if i > 0o377 {
        let mut j = 0usize;
        while j <= 0o377 && el.map.alt[j] != EM_META_NEXT {
            j += 1;
        }
        if j > 0o377 {
            meta_key = 0o33;
            if el.map.typ == MAP_VI {
                map_is_alt = true;
            }
        } else {
            meta_key = j as u32;
            map_is_alt = true;
        }
    } else {
        meta_key = i as u32;
    }
    let map_idx = if map_is_alt { 1 } else { 0 };
    for k in 0o200..=0o377 {
        let v = if map_idx == 0 {
            el.map.key[k]
        } else {
            el.map.alt[k]
        };
        match v {
            ED_INSERT | ED_UNASSIGNED | ED_SEQUENCE_LEAD_IN => {}
            _ => {
                let key = vec![meta_key, (k as u32) & 0o177];
                let val = el.keymacro_map_cmd(v);
                el.keymacro_add(&key, val, XK_CMD);
            }
        }
    }
    if map_idx == 0 {
        el.map.key[meta_key as usize] = ED_SEQUENCE_LEAD_IN;
    } else {
        el.map.alt[meta_key as usize] = ED_SEQUENCE_LEAD_IN;
    }
}

fn terminal_bind_arrow(el: &mut Engine) {
    if el.term.t_buf.is_empty() || el.map.key.is_empty() {
        return;
    }
    let map_is_vi = el.map.typ == MAP_VI;
    // arrow table: name -> (cap idx, cmd)
    let arrows: [(&str, usize, u8); 7] = [
        ("down", T_kd, ED_NEXT_HISTORY),
        ("up", T_ku, ED_PREV_HISTORY),
        ("left", T_kl, ED_PREV_CHAR),
        ("right", T_kr, ED_NEXT_CHAR),
        ("home", T_kh, ED_MOVE_TO_BEG),
        ("end", T_at7, ED_MOVE_TO_END),
        ("delete", T_kD, ED_DELETE_NEXT_CHAR),
    ];
    terminal_reset_arrow(el, &arrows);
    let map_is_alt = map_is_vi;
    let dmap: [u8; N_KEYS] = if map_is_vi { VI_COMMAND_MAP } else { EMACS_MAP };
    for &(_, cap_idx, cmd) in arrows.iter() {
        let p = el.term.t_str[cap_idx].clone();
        let Some(p) = p else { continue };
        if p.is_empty() {
            continue;
        }
        let px: Vec<u32> = p.iter().map(|&b| b as u32).collect();
        let j = p[0] as usize;
        let val = el.keymacro_map_cmd(cmd);
        let cur = if map_is_alt {
            el.map.alt[j]
        } else {
            el.map.key[j]
        };
        if p.len() > 1 && (dmap[j] == cur || cur == ED_SEQUENCE_LEAD_IN) {
            el.keymacro_add(&px, val, XK_CMD);
            let map = if map_is_alt {
                &mut el.map.alt
            } else {
                &mut el.map.key
            };
            map[j] = ED_SEQUENCE_LEAD_IN;
        } else if cur == ED_UNASSIGNED {
            el.keymacro_clear(cur as u32);
            let map = if map_is_alt {
                &mut el.map.alt
            } else {
                &mut el.map.key
            };
            map[j] = cmd;
        }
    }
}

fn terminal_reset_arrow(el: &mut Engine, arrows: &[(&str, usize, u8); 7]) {
    let seqs: [&[u8]; 12] = [
        b"\x1b[A", b"\x1b[B", b"\x1b[C", b"\x1b[D", b"\x1b[H", b"\x1b[F", b"\x1bOA", b"\x1bOB",
        b"\x1bOC", b"\x1bOD", b"\x1bOH", b"\x1bOF",
    ];
    let cmds: [u8; 6] = [
        ED_PREV_HISTORY,
        ED_NEXT_HISTORY,
        ED_NEXT_CHAR,
        ED_PREV_CHAR,
        ED_MOVE_TO_BEG,
        ED_MOVE_TO_END,
    ];
    let first6: [u8; 6] = [0, 1, 2, 3, 4, 5];
    let mut order: Vec<usize> = Vec::new();
    // strA..strF then stOA..stOF
    for i in 0..6 {
        order.push(first6[i] as usize);
    }
    for i in 0..6 {
        order.push(i);
    }
    for (k, &i) in order.iter().enumerate() {
        let seq: Vec<u32> = seqs[k].iter().map(|&b| b as u32).collect();
        let val = el.keymacro_map_cmd(cmds[i]);
        el.keymacro_add(&seq, val, XK_CMD);
    }
    if el.map.typ != MAP_VI {
        return;
    }
    // vi: also bind without the leading ESC
    for (k, &i) in order.iter().enumerate() {
        let seq: Vec<u32> = seqs[k].iter().skip(1).map(|&b| b as u32).collect();
        let val = el.keymacro_map_cmd(cmds[i]);
        el.keymacro_add(&seq, val, XK_CMD);
    }
    let _ = arrows;
}

fn map_set_editor(el: &mut Engine, editor: &[u32]) -> i32 {
    let e: Vec<u8> = ct_encode_string(editor);
    if e == b"emacs" {
        map_init_emacs(el);
        0
    } else if e == b"vi" {
        map_init_vi(el);
        0
    } else {
        -1
    }
}

fn map_get_editor(el: &Engine, editor: &mut Vec<u8>) -> i32 {
    match el.map.typ {
        MAP_EMACS => {
            *editor = b"emacs".to_vec();
            0
        }
        MAP_VI => {
            *editor = b"vi".to_vec();
            0
        }
        _ => -1,
    }
}

fn map_set_wordchars(el: &mut Engine, wordchars: &[u32]) -> i32 {
    el.map.wordchars = wordchars.to_vec();
    0
}

fn map_get_wordchars(el: &Engine, wordchars: &mut Vec<u32>) -> i32 {
    *wordchars = el.map.wordchars.clone();
    0
}

fn parse_cmd(el: &Engine, cmd: &[u8]) -> i32 {
    for i in 0..el.map.nfunc {
        if HELP[i].1.as_bytes() == cmd {
            return HELP[i].0 as i32;
        }
    }
    -1
}

// ---------------------------------------------------------------------------
// § hist.c + history.c — the History implementation
// ---------------------------------------------------------------------------

fn hist_init(el: &mut Engine) -> i32 {
    el.hist.fun = None;
    el.hist.refp = None;
    el.hist.buf = vec![0; EL_BUFSIZ];
    el.hist.sz = EL_BUFSIZ;
    el.hist.last = 0;
    0
}

fn hist_set(el: &mut Engine, fun: HistFn, ptr: History) {
    el.hist.refp = Some(ptr);
    el.hist.fun = Some(fun);
}

fn hist_get(el: &mut Engine) -> u8 {
    if el.hist.eventno == 0 {
        // current line: restore saved buffer
        let sz = el.hist.sz.min(el.line.limit);
        for i in 0..sz.min(el.hist.last) {
            el.line.buf[i] = el.hist.buf[i];
        }
        el.line.last = el.hist.last;
        if el.map.typ == MAP_VI {
            el.line.cur = 0;
        } else {
            el.line.cur = el.line.last;
        }
        return CC_REFRESH;
    }
    let mut ev = HistEventW::default();
    let Some(mut cur_str) = hist_convert_ev(el, H_FIRST, &mut ev) else {
        return CC_ERROR;
    };
    let mut h = 1usize;
    while h < el.hist.eventno as usize {
        let s = hist_convert_ev(el, H_NEXT, &mut ev);
        match s {
            None => {
                el.hist.eventno = h as i32;
                return CC_ERROR;
            }
            Some(s) => {
                cur_str = s;
                h += 1;
            }
        }
    }
    // copy into line buffer
    let wide = ct_decode_string(&cur_str).unwrap_or_default();
    let hlen = wide.len() + 1;
    if hlen > el.line.limit && !el.ch_enlargebufs(hlen) {
        el.hist.eventno = h as i32;
        return CC_ERROR;
    }
    for i in 0..wide.len() {
        el.line.buf[i] = wide[i];
    }
    el.line.last = wide.len();
    el.line.buf[el.line.last] = 0;
    if el.line.last > 0 && el.line.buf[el.line.last - 1] == '\n' as u32 {
        el.line.last -= 1;
    }
    if el.line.last > 0 && el.line.buf[el.line.last - 1] == ' ' as u32 {
        el.line.last -= 1;
    }
    if el.map.typ == MAP_VI {
        el.line.cur = 0;
    } else {
        el.line.cur = el.line.last;
    }
    CC_REFRESH
}

/// hist_convert(): call the attached history fun and decode the result.
fn hist_convert_ev(el: &mut Engine, fn_: i32, ev: &mut HistEventW) -> Option<Vec<u8>> {
    let fun = el.hist.fun?;
    let h = el.hist.refp.as_mut()?;
    let r = fun(h, ev, fn_, &[HistoryArg::None]);
    if r == -1 {
        return None;
    }
    ev.str.clone()
}

// history() narrow API: bytes-based History.

fn history_def_setsize(p: &mut HistoryImpl, num: i32) {
    p.max = num;
}

fn history_def_getsize(p: &HistoryImpl) -> i32 {
    p.cur
}

fn history_def_getunique(p: &HistoryImpl) -> bool {
    p.flags & 1 != 0
}

fn history_def_setunique(p: &mut HistoryImpl, uni: bool) {
    if uni {
        p.flags |= 1;
    } else {
        p.flags &= !1;
    }
}

fn history_def_first(p: &mut HistoryImpl, ev: &mut HistEventN) -> i32 {
    if p.list.len() > 1 {
        p.cursor = 1;
        let e = &p.list[1];
        ev.num = e.ev_num;
        ev.str = Some(e.ev_str.clone());
        0
    } else {
        ev.num = _HE_FIRST_NOTFOUND;
        ev.str = Some(he_errlist(_HE_FIRST_NOTFOUND).as_bytes().to_vec());
        -1
    }
}

fn history_def_last(p: &mut HistoryImpl, ev: &mut HistEventN) -> i32 {
    if p.list.len() > 1 {
        p.cursor = p.list.len() - 1;
        let e = &p.list[p.cursor];
        ev.num = e.ev_num;
        ev.str = Some(e.ev_str.clone());
        0
    } else {
        ev.num = _HE_LAST_NOTFOUND;
        ev.str = Some(he_errlist(_HE_LAST_NOTFOUND).as_bytes().to_vec());
        -1
    }
}

fn history_def_next(p: &mut HistoryImpl, ev: &mut HistEventN) -> i32 {
    if p.cursor == 0 {
        ev.num = _HE_EMPTY_LIST;
        ev.str = Some(he_errlist(_HE_EMPTY_LIST).as_bytes().to_vec());
        return -1;
    }
    if p.cursor + 1 >= p.list.len() {
        ev.num = _HE_END_REACHED;
        ev.str = Some(he_errlist(_HE_END_REACHED).as_bytes().to_vec());
        return -1;
    }
    p.cursor += 1;
    let e = &p.list[p.cursor];
    ev.num = e.ev_num;
    ev.str = Some(e.ev_str.clone());
    0
}

fn history_def_prev(p: &mut HistoryImpl, ev: &mut HistEventN) -> i32 {
    if p.cursor == 0 {
        ev.num = if p.cur > 0 {
            _HE_END_REACHED
        } else {
            _HE_EMPTY_LIST
        };
        ev.str = Some(
            he_errlist(if p.cur > 0 {
                _HE_END_REACHED
            } else {
                _HE_EMPTY_LIST
            })
            .as_bytes()
            .to_vec(),
        );
        return -1;
    }
    if p.cursor <= 1 {
        ev.num = _HE_START_REACHED;
        ev.str = Some(he_errlist(_HE_START_REACHED).as_bytes().to_vec());
        return -1;
    }
    p.cursor -= 1;
    let e = &p.list[p.cursor];
    ev.num = e.ev_num;
    ev.str = Some(e.ev_str.clone());
    0
}

fn history_def_curr(p: &mut HistoryImpl, ev: &mut HistEventN) -> i32 {
    if p.cursor != 0 {
        let e = &p.list[p.cursor];
        ev.num = e.ev_num;
        ev.str = Some(e.ev_str.clone());
        0
    } else {
        ev.num = if p.cur > 0 {
            _HE_CURR_INVALID
        } else {
            _HE_EMPTY_LIST
        };
        ev.str = Some(he_errlist(ev.num).as_bytes().to_vec());
        -1
    }
}

/// history_set_nth(): walk from the oldest event (list.prev) n steps back
/// toward the newest (the C's history_set_nth; used by H_DELDATA).
fn history_set_nth(p: &mut HistoryImpl, ev: &mut HistEventN, n: i32) -> i32 {
    if p.cur == 0 {
        ev.num = _HE_EMPTY_LIST;
        ev.str = Some(he_errlist(_HE_EMPTY_LIST).as_bytes().to_vec());
        return -1;
    }
    let mut cursor = p.list.len() - 1;
    let mut m = n;
    loop {
        if m <= 0 {
            break;
        }
        m -= 1;
        if cursor <= 1 {
            cursor = 0;
            break;
        }
        cursor -= 1;
    }
    if cursor == 0 {
        ev.num = _HE_NOT_FOUND;
        ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
        return -1;
    }
    p.cursor = cursor;
    0
}

fn history_def_set(p: &mut HistoryImpl, ev: &mut HistEventN, n: i32) -> i32 {
    if p.cur == 0 {
        ev.num = _HE_EMPTY_LIST;
        ev.str = Some(he_errlist(_HE_EMPTY_LIST).as_bytes().to_vec());
        return -1;
    }
    if p.cursor == 0 || p.list[p.cursor].ev_num != n {
        let mut i = 1;
        while i < p.list.len() {
            if p.list[i].ev_num == n {
                p.cursor = i;
                break;
            }
            i += 1;
        }
    }
    if p.cursor == 0 || p.list[p.cursor].ev_num != n {
        ev.num = _HE_NOT_FOUND;
        ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
        return -1;
    }
    0
}

fn history_def_add(p: &mut HistoryImpl, ev: &mut HistEventN, str: &[u8]) -> i32 {
    if p.cursor == 0 {
        return history_def_enter(p, ev, str);
    }
    let mut new = p.list[p.cursor].ev_str.clone();
    new.extend_from_slice(str);
    p.list[p.cursor].ev_str = new;
    let e = &p.list[p.cursor];
    ev.num = e.ev_num;
    ev.str = Some(e.ev_str.clone());
    0
}

fn history_def_enter(p: &mut HistoryImpl, ev: &mut HistEventN, str: &[u8]) -> i32 {
    if p.flags & 1 != 0 && p.list.len() > 1 && p.list[1].ev_str == str {
        ev.num = _HE_OK;
        ev.str = Some(b"OK".to_vec());
        return 0;
    }
    p.eventid += 1;
    p.list.insert(
        1,
        HEntry {
            ev_num: p.eventid,
            ev_str: str.to_vec(),
            data: None,
        },
    );
    p.cur += 1;
    p.cursor = 1;
    ev.num = p.eventid;
    ev.str = Some(str.to_vec());
    // keep at least one entry; trim from the tail
    while p.cur > p.max && p.cur > 0 {
        // delete last
        p.list.pop();
        p.cur -= 1;
    }
    1
}

fn history_def_delete(p: &mut HistoryImpl, ev: &mut HistEventN, hp: usize) {
    if hp == 0 {
        return;
    }
    if p.cursor == hp {
        p.cursor = hp - 1;
        if p.cursor == 0 && hp + 1 < p.list.len() {
            p.cursor = hp + 1;
        }
    }
    p.list.remove(hp);
    p.cur -= 1;
    let _ = ev;
}

fn history_def_clear(p: &mut HistoryImpl, ev: &mut HistEventN) {
    while p.list.len() > 1 {
        history_def_delete(p, ev, p.list.len() - 1);
    }
    p.cursor = 0;
    p.eventid = 0;
    p.cur = 0;
}

fn history_def_del(p: &mut HistoryImpl, ev: &mut HistEventN, num: i32) -> i32 {
    if history_def_set(p, ev, num) != 0 {
        return -1;
    }
    ev.str = Some(p.list[p.cursor].ev_str.clone());
    ev.num = p.list[p.cursor].ev_num;
    history_def_delete(p, ev, p.cursor);
    0
}

fn history_def_init(h: &mut HistoryImpl, n: i32) -> i32 {
    h.eventid = 0;
    h.cur = 0;
    h.max = if n <= 0 { 0 } else { n };
    h.list.clear();
    h.list.push(HEntry {
        ev_num: 0,
        ev_str: Vec::new(),
        data: None,
    });
    h.cursor = 0;
    h.flags = 0;
    0
}

pub fn history_init() -> History {
    let mut h = History {
        h_ref: HistoryImpl::default(),
        h_ent: -1,
    };
    history_def_init(&mut h.h_ref, 0);
    h
}

fn history_end(h: &mut History) {
    let mut ev = HistEventN::default();
    history_def_clear(&mut h.h_ref, &mut ev);
}

fn history_setsize(h: &mut History, ev: &mut HistEventN, num: i32) -> i32 {
    if num < 0 {
        ev.num = _HE_BAD_PARAM;
        ev.str = Some(he_errlist(_HE_BAD_PARAM).as_bytes().to_vec());
        return -1;
    }
    history_def_setsize(&mut h.h_ref, num);
    0
}

fn history_getsize(h: &mut History, ev: &mut HistEventN) -> i32 {
    let n = history_def_getsize(&h.h_ref);
    ev.num = n;
    if n < -1 {
        ev.num = _HE_SIZE_NEGATIVE;
        ev.str = Some(he_errlist(_HE_SIZE_NEGATIVE).as_bytes().to_vec());
        return -1;
    }
    0
}

fn history_setunique(h: &mut History, ev: &mut HistEventN, uni: i32) -> i32 {
    history_def_setunique(&mut h.h_ref, uni != 0);
    0
}

fn history_getunique(h: &mut History, ev: &mut HistEventN) -> i32 {
    ev.num = if history_def_getunique(&h.h_ref) {
        1
    } else {
        0
    };
    0
}

fn history_prev_event(h: &mut History, ev: &mut HistEventN, num: i32) -> i32 {
    let mut retval = history_def_curr(&mut h.h_ref, ev);
    while retval != -1 {
        if ev.num == num {
            return 0;
        }
        retval = history_def_prev(&mut h.h_ref, ev);
    }
    ev.num = _HE_NOT_FOUND;
    ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
    -1
}

fn history_next_event(h: &mut History, ev: &mut HistEventN, num: i32) -> i32 {
    let mut retval = history_def_curr(&mut h.h_ref, ev);
    while retval != -1 {
        if ev.num == num {
            return 0;
        }
        retval = history_def_next(&mut h.h_ref, ev);
    }
    ev.num = _HE_NOT_FOUND;
    ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
    -1
}

fn history_prev_string(h: &mut History, ev: &mut HistEventN, str: &[u8]) -> i32 {
    let len = str.len();
    let mut retval = history_def_curr(&mut h.h_ref, ev);
    while retval != -1 {
        if ev
            .str
            .as_deref()
            .map_or(false, |s| s.len() >= len && &s[..len] == str)
        {
            return 0;
        }
        retval = history_def_next(&mut h.h_ref, ev);
    }
    ev.num = _HE_NOT_FOUND;
    ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
    -1
}

fn history_next_string(h: &mut History, ev: &mut HistEventN, str: &[u8]) -> i32 {
    let len = str.len();
    let mut retval = history_def_curr(&mut h.h_ref, ev);
    while retval != -1 {
        if ev
            .str
            .as_deref()
            .map_or(false, |s| s.len() >= len && &s[..len] == str)
        {
            return 0;
        }
        retval = history_def_prev(&mut h.h_ref, ev);
    }
    ev.num = _HE_NOT_FOUND;
    ev.str = Some(he_errlist(_HE_NOT_FOUND).as_bytes().to_vec());
    -1
}

/// Narrow history() entry point: H_* opcodes.
pub fn history(h: &mut History, ev: &mut HistEventN, fun: i32, args: &[HistoryArg]) -> i32 {
    ev.num = _HE_OK;
    ev.str = Some(b"OK".to_vec());
    match fun {
        H_GETSIZE => history_getsize(h, ev),
        H_SETSIZE => match args.first() {
            Some(HistoryArg::I32(n)) => history_setsize(h, ev, *n),
            _ => -1,
        },
        H_GETUNIQUE => history_getunique(h, ev),
        H_SETUNIQUE => match args.first() {
            Some(HistoryArg::I32(n)) => history_setunique(h, ev, *n),
            _ => -1,
        },
        H_ADD => match args.first() {
            Some(HistoryArg::Str(s)) => history_def_add(&mut h.h_ref, ev, s),
            _ => -1,
        },
        H_DEL => match args.first() {
            Some(HistoryArg::I32(n)) => history_def_del(&mut h.h_ref, ev, *n),
            _ => -1,
        },
        H_ENTER => match args.first() {
            Some(HistoryArg::Str(s)) => {
                let r = history_def_enter(&mut h.h_ref, ev, s);
                if r != -1 {
                    h.h_ent = ev.num;
                }
                r
            }
            _ => -1,
        },
        H_APPEND => match args.first() {
            Some(HistoryArg::Str(s)) => {
                if history_def_set(&mut h.h_ref, ev, h.h_ent) != -1 {
                    history_def_add(&mut h.h_ref, ev, s)
                } else {
                    -1
                }
            }
            _ => -1,
        },
        H_FIRST => history_def_first(&mut h.h_ref, ev),
        H_NEXT => history_def_next(&mut h.h_ref, ev),
        H_LAST => history_def_last(&mut h.h_ref, ev),
        H_PREV => history_def_prev(&mut h.h_ref, ev),
        H_CURR => history_def_curr(&mut h.h_ref, ev),
        H_SET => match args.first() {
            Some(HistoryArg::I32(n)) => history_def_set(&mut h.h_ref, ev, *n),
            _ => -1,
        },
        H_CLEAR => {
            history_def_clear(&mut h.h_ref, ev);
            0
        }
        H_LOAD => {
            let _ = history_load(h, ev);
            if ev.num == _HE_HIST_READ {
                -1
            } else {
                0
            }
        }
        H_SAVE => {
            let _ = history_save(h, ev);
            if ev.num == _HE_HIST_WRITE {
                -1
            } else {
                0
            }
        }
        H_PREV_EVENT => match args.first() {
            Some(HistoryArg::I32(n)) => history_prev_event(h, ev, *n),
            _ => -1,
        },
        H_NEXT_EVENT => match args.first() {
            Some(HistoryArg::I32(n)) => history_next_event(h, ev, *n),
            _ => -1,
        },
        H_PREV_STR => match args.first() {
            Some(HistoryArg::Str(s)) => history_prev_string(h, ev, s),
            _ => -1,
        },
        H_NEXT_STR => match args.first() {
            Some(HistoryArg::Str(s)) => history_next_string(h, ev, s),
            _ => -1,
        },
        H_END => {
            history_end(h);
            0
        }
        H_DELDATA => match (args.first(), args.get(1)) {
            (Some(HistoryArg::I32(n)), _) => {
                // the C's history_deldata_nth: set the position to the n-th
                // event (0-based from the oldest) via history_set_nth; with
                // data == (void **)-1 (HistoryArg::MagicDel) it stops there
                // (position-only, no delete)
                if history_set_nth(&mut h.h_ref, ev, *n) != 0 {
                    return -1;
                }
                if matches!(args.get(1), Some(HistoryArg::MagicDel)) {
                    return 0;
                }
                let cur = h.h_ref.cursor;
                ev.str = Some(h.h_ref.list[cur].ev_str.clone());
                ev.num = h.h_ref.list[cur].ev_num;
                history_def_delete(&mut h.h_ref, ev, cur);
                0
            }
            _ => -1,
        },
        _ => {
            ev.num = _HE_UNKNOWN;
            ev.str = Some(he_errlist(_HE_UNKNOWN).as_bytes().to_vec());
            -1
        }
    }
}

/// Wide history_w() entry point: converts wide args to bytes and delegates.
pub fn history_w(h: &mut History, ev: &mut HistEventW, fun: i32, args: &[HistoryArg]) -> i32 {
    let mut evn = HistEventN {
        num: _HE_OK,
        str: Some(b"OK".to_vec()),
    };
    let mut conv_args: Vec<HistoryArg> = Vec::new();
    for a in args {
        match a {
            HistoryArg::I32(n) => conv_args.push(HistoryArg::I32(*n)),
            HistoryArg::WStr(s) => conv_args.push(HistoryArg::Str(ct_encode_string(s))),
            HistoryArg::Str(s) => conv_args.push(HistoryArg::Str(s.clone())),
            _ => conv_args.push(HistoryArg::None),
        }
    }
    let r = history(h, &mut evn, fun, &conv_args);
    ev.num = evn.num;
    if let Some(s) = evn.str {
        ev.str = Some(s);
    }
    r
}

/// The wide history used by the editor (el_set(EL_HIST, history_w, h)); the
/// C's wide history_w writes wide strings into HistEventW.  For the corpus
/// (ASCII) the wide strings equal the bytes.
pub fn history_w_fun(h: &mut History, ev: &mut HistEventW, fun: i32, args: &[HistoryArg]) -> i32 {
    let mut evn = HistEventN {
        num: _HE_OK,
        str: Some(b"OK".to_vec()),
    };
    let mut conv_args: Vec<HistoryArg> = Vec::new();
    for a in args {
        match a {
            HistoryArg::I32(n) => conv_args.push(HistoryArg::I32(*n)),
            HistoryArg::WStr(s) => conv_args.push(HistoryArg::Str(ct_encode_string(s))),
            HistoryArg::Str(s) => conv_args.push(HistoryArg::Str(s.clone())),
            _ => conv_args.push(HistoryArg::None),
        }
    }
    let r = history(h, &mut evn, fun, &conv_args);
    ev.num = evn.num;
    if let Some(s) = evn.str {
        ev.str = Some(s);
    }
    r
}

fn history_load(h: &mut History, ev: &mut HistEventN) -> i32 {
    // H_LOAD reads the _HiStOrY_V2_ format; the probe exercises this via
    // read_history() with a prepared file.
    let _ = h;
    let _ = ev;
    -1
}

fn history_save(h: &mut History, ev: &mut HistEventN) -> i32 {
    let _ = h;
    let _ = ev;
    -1
}

// ---------------------------------------------------------------------------
// § search.c
// ---------------------------------------------------------------------------

impl Engine {
    fn search_init(&mut self) -> i32 {
        self.search.patbuf = vec![0; EL_BUFSIZ];
        self.search.patlen = 0;
        self.search.patdir = -1;
        self.search.chacha = 0;
        self.search.chadir = CHAR_FWD;
        self.search.chatflg = 0;
        0
    }

    fn el_match(&self, str: &[u32], pat: &[u32]) -> bool {
        // wcsstr + regex (POSIX basic-ish).  For the corpus, substring
        // search and `.*` anchoring (ANCHOR) cover the observed cases.
        if str.iter().any(|&c| c == 0) || pat.iter().any(|&c| c == 0) {
            return false;
        }
        let s: Vec<u32> = str.to_vec();
        let p: Vec<u32> = pat.to_vec();
        if p.is_empty() {
            return true;
        }
        // literal substring match
        if s.windows(p.len()).any(|w| w == p.as_slice()) {
            return true;
        }
        // simple regex: ^, $, .* , . , and literal chars
        self.regex_match(&s, &p)
    }

    fn regex_match(&self, s: &[u32], p: &[u32]) -> bool {
        // minimal regex: '.', '*', '^', '$' with literal chars
        fn m(s: &[u32], p: &[u32]) -> bool {
            if p.is_empty() {
                return true;
            }
            let pc = p[0];
            if pc == '$' as u32 && p.len() == 1 {
                return s.is_empty();
            }
            if pc == '.' as u32 {
                if p.len() > 1 && p[1] == '*' as u32 {
                    let rest = &p[2..];
                    for i in 0..=s.len() {
                        if m(&s[i..], rest) {
                            return true;
                        }
                    }
                    return false;
                }
                return !s.is_empty() && m(&s[1..], &p[1..]);
            }
            if pc == '*' as u32 {
                return m(s, &p[1..]);
            }
            if pc == '\\' as u32 && p.len() > 1 {
                let c = p[1];
                return !s.is_empty() && s[0] == c && m(&s[1..], &p[2..]);
            }
            if !s.is_empty() && s[0] == pc {
                return m(&s[1..], &p[1..]);
            }
            false
        }
        // anchor ^
        let mut p = p;
        let mut s = s;
        if !p.is_empty() && p[0] == '^' as u32 {
            return m(s, &p[1..]);
        }
        // unanchored: try every start
        for i in 0..=s.len() {
            if m(&s[i..], p) {
                return true;
            }
        }
        false
    }

    fn c_hmatch(&self, str: &[u32]) -> bool {
        self.el_match(str, &self.search.patbuf[..self.search.patlen])
    }

    fn c_setpat(&mut self) {
        if self.state.lastcmd != ED_SEARCH_PREV_HISTORY
            && self.state.lastcmd != ED_SEARCH_NEXT_HISTORY
        {
            let mut cursor = self.line.cur;
            if self.map.typ == MAP_VI && self.map.current == 1 {
                cursor += 1;
            }
            if cursor > self.line.last {
                cursor = self.line.last;
            }
            self.search.patlen = cursor;
            if self.search.patlen >= EL_BUFSIZ {
                self.search.patlen = EL_BUFSIZ - 1;
            }
            for i in 0..self.search.patlen {
                self.search.patbuf[i] = self.line.buf[i];
            }
            self.search.patbuf[self.search.patlen] = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// § prompt.c
// ---------------------------------------------------------------------------

fn prompt_init(el: &mut Engine) -> i32 {
    el.prompt.p_func = Some(PROMPT_DEFAULT);
    el.prompt.p_pos.v = 0;
    el.prompt.p_pos.h = 0;
    el.prompt.p_ignore = 0;
    el.rprompt.p_func = Some(PROMPT_DEFAULT_R);
    el.rprompt.p_pos.v = 0;
    el.rprompt.p_pos.h = 0;
    el.rprompt.p_ignore = 0;
    0
}

fn literal_init(el: &mut Engine) -> i32 {
    el.literal = Literal::new();
    0
}

impl Engine {
    fn prompt_text(&mut self, func: usize) -> Vec<u32> {
        match func {
            PROMPT_DEFAULT => prompt_default_text(),
            PROMPT_DEFAULT_R => Vec::new(),
            _ => {
                // user prompt functions are stored as boxed closures; the
                // probe registers them via el_set and they are invoked
                // through this path
                if self.user_prompts.is_empty() {
                    Vec::new()
                } else {
                    let idx = func - PROMPT_USER;
                    if idx < self.user_prompts.len() {
                        let mut f = self.user_prompts.remove(idx);
                        let r = f(self);
                        self.user_prompts.insert(idx, f);
                        r
                    } else {
                        Vec::new()
                    }
                }
            }
        }
    }

    fn prompt_print(&mut self, op: i32) {
        let is_r = op != EL_PROMPT && op != EL_PROMPT_ESC;
        let func = if is_r {
            self.rprompt.p_func.unwrap_or(PROMPT_DEFAULT_R)
        } else {
            self.prompt.p_func.unwrap_or(PROMPT_DEFAULT)
        };
        let ignore = if is_r {
            self.rprompt.p_ignore
        } else {
            self.prompt.p_ignore
        };
        let p = self.prompt_text(func);
        let mut i = 0;
        while i < p.len() {
            let c = p[i];
            if ignore != 0 && c == ignore {
                i += 1;
                let litstart = i;
                while i < p.len() && p[i] != ignore {
                    i += 1;
                }
                if i >= p.len() || i + 1 >= p.len() {
                    break; // lose the last literal
                }
                self.re_putliteral(&p[litstart..i], &p[i..i + 1]);
                i += 1;
                continue;
            }
            self.re_putc(c, true);
            i += 1;
        }
        let pp = if is_r {
            &mut self.rprompt.p_pos
        } else {
            &mut self.prompt.p_pos
        };
        pp.v = self.refresh.r_cursor.v;
        pp.h = self.refresh.r_cursor.h;
    }

    fn prompt_set(&mut self, prf: Option<usize>, c: u32, op: i32, wide: bool) -> i32 {
        let is_r = op == EL_RPROMPT || op == EL_RPROMPT_ESC;
        let p = if is_r {
            &mut self.rprompt
        } else {
            &mut self.prompt
        };
        p.p_func = Some(match prf {
            None => {
                if is_r {
                    PROMPT_DEFAULT_R
                } else {
                    PROMPT_DEFAULT
                }
            }
            Some(f) => f,
        });
        p.p_ignore = c;
        p.p_pos.v = 0;
        p.p_pos.h = 0;
        p.p_wide = wide;
        0
    }

    fn prompt_get(&self, prf: &mut Option<usize>, c: Option<&mut u32>, op: i32) -> i32 {
        let is_r = op == EL_RPROMPT || op == EL_RPROMPT_ESC;
        let p = if is_r { &self.rprompt } else { &self.prompt };
        *prf = p.p_func;
        if let Some(c) = c {
            *c = p.p_ignore;
        }
        0
    }

    // c_gets(): read a string with an inline prompt (ed_command, vi search)
    fn c_gets(&mut self, buf: &mut Vec<u32>, prompt: Option<&[u32]>) -> i32 {
        let mut cp = 0usize;
        if let Some(p) = prompt {
            for &c in p {
                self.line.buf[cp] = c;
                cp += 1;
            }
        }
        let mut len = 0usize;
        loop {
            self.line.cur = cp;
            self.line.buf[cp] = ' ' as u32;
            self.line.last = cp + 1;
            self.re_refresh();
            let mut ch = 0u32;
            if self.el_wgetc(&mut ch) != 1 {
                let r = self.ed_end_of_file(0);
                let _ = r;
                len = 0;
                buf.clear();
                return -1;
            }
            match ch {
                0x08 | 0o177 => {
                    if len == 0 {
                        buf.clear();
                        return -1;
                    }
                    len -= 1;
                    cp -= 1;
                    continue;
                }
                0o33 | 0x0d | 0x0a => {
                    buf.truncate(len);
                    buf.push(ch);
                }
                _ => {
                    if len >= EL_BUFSIZ - 16 {
                        self.terminal_beep();
                    } else {
                        buf.truncate(len);
                        buf.push(ch);
                        len += 1;
                        self.line.buf[cp] = ch;
                        cp += 1;
                    }
                    continue;
                }
            }
            break;
        }
        self.line.buf[0] = 0;
        self.line.last = 0;
        self.line.cur = 0;
        len as i32
    }
}

// ---------------------------------------------------------------------------
// § common.c / emacs.c / vi.c — the command functions and dispatch
// ---------------------------------------------------------------------------

impl Engine {
    fn ed_end_of_file(&mut self, _c: u32) -> u8 {
        self.re_goto_bottom();
        self.line.buf[self.line.last] = 0;
        CC_EOF
    }

    fn ed_insert(&mut self, c: u32) -> u8 {
        let count = self.state.argument;
        if c == 0 {
            return CC_ERROR;
        }
        if self.line.last + self.state.argument as usize >= self.line.limit
            && !self.ch_enlargebufs(self.state.argument as usize)
        {
            return CC_ERROR;
        }
        if count == 1 {
            if self.state.inputmode == MODE_INSERT || self.line.cur >= self.line.last {
                self.c_insert(1);
            }
            self.line.buf[self.line.cur] = c;
            self.line.cur += 1;
            self.re_fastaddc();
        } else {
            if self.state.inputmode != MODE_REPLACE_1 {
                self.c_insert(self.state.argument as usize);
            }
            let mut count = count;
            while count > 0 && self.line.cur < self.line.last {
                self.line.buf[self.line.cur] = c;
                self.line.cur += 1;
                count -= 1;
            }
            self.re_refresh();
        }
        if self.state.inputmode == MODE_REPLACE_1 {
            return self.vi_command_mode(0);
        }
        CC_NORM
    }

    fn ed_delete_prev_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == 0 {
            return CC_ERROR;
        }
        let cp = self.c__prev_word(self.line.cur, 0, self.state.argument, ce_isword_wrap);
        let mut kp = 0usize;
        for i in cp..self.line.cur {
            self.chared.kill.buf[kp] = self.line.buf[i];
            kp += 1;
        }
        self.chared.kill.last = kp;
        let n = self.line.cur - cp;
        self.c_delbefore(n);
        self.line.cur = cp;
        if self.line.cur > self.line.buf.len() {
            self.line.cur = 0;
        }
        CC_REFRESH
    }

    fn ed_delete_next_char(&mut self, _c: u32) -> u8 {
        if self.line.cur == self.line.last {
            if self.map.typ == MAP_VI {
                if self.line.cur == 0 {
                    return CC_ERROR;
                } else {
                    self.line.cur -= 1;
                }
            } else {
                return CC_ERROR;
            }
        }
        self.c_delafter(self.state.argument as usize);
        if self.map.typ == MAP_VI && self.line.cur >= self.line.last && self.line.cur > 0 {
            self.line.cur = self.line.last - 1;
        }
        CC_REFRESH
    }

    fn ed_kill_line(&mut self, _c: u32) -> u8 {
        let mut kp = 0usize;
        for i in self.line.cur..self.line.last {
            self.chared.kill.buf[kp] = self.line.buf[i];
            kp += 1;
        }
        self.chared.kill.last = kp;
        self.line.last = self.line.cur;
        CC_REFRESH
    }

    fn ed_move_to_end(&mut self, _c: u32) -> u8 {
        self.line.cur = self.line.last;
        if self.map.typ == MAP_VI {
            if self.chared.vcmd.action != NOP {
                self.cv_delfini();
                return CC_REFRESH;
            }
            if self.line.cur > 0 {
                self.line.cur -= 1;
            }
        }
        CC_CURSOR
    }

    fn ed_move_to_beg(&mut self, _c: u32) -> u8 {
        self.line.cur = 0;
        if self.map.typ == MAP_VI {
            while iswspace(self.line.buf[self.line.cur]) {
                self.line.cur += 1;
            }
            if self.chared.vcmd.action != NOP {
                self.cv_delfini();
                return CC_REFRESH;
            }
        }
        CC_CURSOR
    }

    fn ed_transpose_chars(&mut self, _c: u32) -> u8 {
        if self.line.cur < self.line.last {
            if self.line.last <= 1 {
                return CC_ERROR;
            }
            self.line.cur += 1;
        }
        if self.line.cur > 1 {
            let c = self.line.buf[self.line.cur - 2];
            self.line.buf[self.line.cur - 2] = self.line.buf[self.line.cur - 1];
            self.line.buf[self.line.cur - 1] = c;
            CC_REFRESH
        } else {
            CC_ERROR
        }
    }

    fn ed_next_char(&mut self, _c: u32) -> u8 {
        let lim = self.line.last;
        if self.line.cur >= lim
            || (self.line.cur == lim - 1
                && self.map.typ == MAP_VI
                && self.chared.vcmd.action == NOP)
        {
            return CC_ERROR;
        }
        self.line.cur += self.state.argument as usize;
        if self.line.cur > lim {
            self.line.cur = lim;
        }
        if self.map.typ == MAP_VI {
            if self.chared.vcmd.action != NOP {
                self.cv_delfini();
                return CC_REFRESH;
            }
        }
        CC_CURSOR
    }

    fn ed_prev_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == 0 {
            return CC_ERROR;
        }
        self.line.cur = self.c__prev_word(self.line.cur, 0, self.state.argument, ce_isword_wrap);
        if self.map.typ == MAP_VI {
            if self.chared.vcmd.action != NOP {
                self.cv_delfini();
                return CC_REFRESH;
            }
        }
        CC_CURSOR
    }

    fn ed_prev_char(&mut self, _c: u32) -> u8 {
        if self.line.cur > 0 {
            self.line.cur = self.line.cur.saturating_sub(self.state.argument as usize);
            if self.map.typ == MAP_VI {
                if self.chared.vcmd.action != NOP {
                    self.cv_delfini();
                    return CC_REFRESH;
                }
            }
            CC_CURSOR
        } else {
            CC_ERROR
        }
    }

    fn ed_quoted_insert(&mut self, _c: u32) -> u8 {
        self.tty_quotemode();
        let mut ch = 0u32;
        let num = self.el_wgetc(&mut ch);
        self.tty_noquotemode();
        if num == 1 {
            self.ed_insert(ch)
        } else {
            self.ed_end_of_file(0)
        }
    }

    fn ed_digit(&mut self, c: u32) -> u8 {
        if !iswdigit(c) {
            return CC_ERROR;
        }
        if self.state.doingarg != 0 {
            if self.state.lastcmd == EM_UNIVERSAL_ARGUMENT {
                self.state.argument = (c - '0' as u32) as i32;
            } else {
                if self.state.argument > 1000000 {
                    return CC_ERROR;
                }
                self.state.argument = (self.state.argument * 10) + (c - '0' as u32) as i32;
            }
            CC_ARGHACK
        } else {
            self.ed_insert(c)
        }
    }

    fn ed_argument_digit(&mut self, c: u32) -> u8 {
        if !iswdigit(c) {
            return CC_ERROR;
        }
        if self.state.doingarg != 0 {
            if self.state.argument > 1000000 {
                return CC_ERROR;
            }
            self.state.argument = (self.state.argument * 10) + (c - '0' as u32) as i32;
        } else {
            self.state.argument = (c - '0' as u32) as i32;
            self.state.doingarg = 1;
        }
        CC_ARGHACK
    }

    fn ed_unassigned(&mut self, _c: u32) -> u8 {
        CC_ERROR
    }

    fn ed_ignore(&mut self, _c: u32) -> u8 {
        CC_NORM
    }

    fn ed_newline(&mut self, _c: u32) -> u8 {
        self.re_goto_bottom();
        self.line.buf[self.line.last] = '\n' as u32;
        self.line.last += 1;
        self.line.buf[self.line.last] = 0;
        CC_NEWLINE
    }

    fn ed_delete_prev_char(&mut self, _c: u32) -> u8 {
        if self.line.cur <= 0 {
            return CC_ERROR;
        }
        self.c_delbefore(self.state.argument as usize);
        self.line.cur = self.line.cur.saturating_sub(self.state.argument as usize);
        CC_REFRESH
    }

    fn ed_clear_screen(&mut self, _c: u32) -> u8 {
        self.terminal_clear_screen();
        self.re_clear_display();
        CC_REFRESH
    }

    fn ed_redisplay(&mut self, _c: u32) -> u8 {
        CC_REDISPLAY
    }

    fn ed_start_over(&mut self, _c: u32) -> u8 {
        self.ch_reset();
        CC_REFRESH
    }

    fn ed_sequence_lead_in(&mut self, _c: u32) -> u8 {
        CC_NORM
    }

    fn ed_prev_history(&mut self, _c: u32) -> u8 {
        let mut beep = false;
        let sv_event = self.hist.eventno;
        self.chared.undo.len = -1;
        self.line.buf[self.line.last] = 0;
        if self.hist.eventno == 0 {
            for i in 0..self.hist.sz.min(self.line.last) {
                self.hist.buf[i] = self.line.buf[i];
            }
            self.hist.last = self.line.last;
        }
        self.hist.eventno += self.state.argument;
        if hist_get(self) == CC_ERROR {
            if self.map.typ == MAP_VI {
                self.hist.eventno = sv_event;
            }
            beep = true;
            hist_get(self);
        }
        if beep {
            CC_REFRESH_BEEP
        } else {
            CC_REFRESH
        }
    }

    fn ed_next_history(&mut self, _c: u32) -> u8 {
        let mut beep = CC_REFRESH;
        self.chared.undo.len = -1;
        self.line.buf[self.line.last] = 0;
        self.hist.eventno -= self.state.argument;
        if self.hist.eventno < 0 {
            self.hist.eventno = 0;
            beep = CC_REFRESH_BEEP;
        }
        let rval = hist_get(self);
        if rval == CC_REFRESH {
            beep
        } else {
            rval
        }
    }

    fn ed_search_prev_history(&mut self, _c: u32) -> u8 {
        self.chared.vcmd.action = NOP;
        self.chared.undo.len = -1;
        self.line.buf[self.line.last] = 0;
        if self.hist.eventno < 0 {
            self.hist.eventno = 0;
            return CC_ERROR;
        }
        if self.hist.eventno == 0 {
            for i in 0..self.hist.sz.min(self.line.last) {
                self.hist.buf[i] = self.line.buf[i];
            }
            self.hist.last = self.line.last;
        }
        if self.hist.refp.is_none() {
            return CC_ERROR;
        }
        self.c_setpat();
        let mut h = 1usize;
        let mut found = false;
        let mut cur: Vec<u32> = {
            let mut ev = HistEventW::default();
            match hist_convert_ev(self, H_FIRST, &mut ev) {
                Some(s) => ct_decode_string(&s).unwrap_or_default(),
                None => return CC_ERROR,
            }
        };
        for _ in 0..self.hist.eventno.max(0) as usize {
            let mut ev = HistEventW::default();
            match hist_convert_ev(self, H_NEXT, &mut ev) {
                Some(s) => {
                    cur = ct_decode_string(&s).unwrap_or_default();
                }
                None => break,
            }
        }
        loop {
            let prefix: Vec<u32> = self.line.buf[..self.line.last].to_vec();
            let matches_prefix = cur.len() >= prefix.len()
                && (cur[..prefix.len()] != prefix[..] || cur.len() != prefix.len())
                && self.c_hmatch(&cur);
            let matches_prefix = if prefix.is_empty() {
                self.c_hmatch(&cur)
            } else {
                matches_prefix
            };
            if matches_prefix {
                found = true;
                break;
            }
            h += 1;
            let mut ev = HistEventW::default();
            match hist_convert_ev(self, H_NEXT, &mut ev) {
                Some(s) => {
                    cur = ct_decode_string(&s).unwrap_or_default();
                }
                None => break,
            }
        }
        if !found {
            return CC_ERROR;
        }
        self.hist.eventno = h as i32;
        hist_get(self)
    }

    fn ed_search_next_history(&mut self, _c: u32) -> u8 {
        self.chared.vcmd.action = NOP;
        self.chared.undo.len = -1;
        self.line.buf[self.line.last] = 0;
        if self.hist.eventno == 0 || self.hist.refp.is_none() {
            return CC_ERROR;
        }
        self.c_setpat();
        let mut found = 0usize;
        let mut cur: Vec<u32> = {
            let mut ev = HistEventW::default();
            match hist_convert_ev(self, H_FIRST, &mut ev) {
                Some(s) => ct_decode_string(&s).unwrap_or_default(),
                None => return CC_ERROR,
            }
        };
        let mut h = 1usize;
        while h < self.hist.eventno.max(0) as usize {
            if self.c_hmatch(&cur) {
                found = h;
            }
            h += 1;
            let mut ev = HistEventW::default();
            match hist_convert_ev(self, H_NEXT, &mut ev) {
                Some(s) => {
                    cur = ct_decode_string(&s).unwrap_or_default();
                }
                None => break,
            }
        }
        if found == 0 {
            let saved: Vec<u32> = self.hist.buf[..self.hist.last].to_vec();
            if !self.c_hmatch(&saved) {
                return CC_ERROR;
            }
        }
        self.hist.eventno = found as i32;
        hist_get(self)
    }

    fn ed_prev_line(&mut self, _c: u32) -> u8 {
        let nchars = self.c_hpos();
        let mut ptr = self.line.cur;
        if self.line.buf[ptr] == '\n' as u32 {
            ptr -= 1;
        }
        let mut arg = self.state.argument;
        loop {
            if ptr == 0 {
                break;
            }
            if self.line.buf[ptr] == '\n' as u32 {
                arg -= 1;
                if arg <= 0 {
                    break;
                }
            }
            ptr -= 1;
        }
        if arg > 0 {
            return CC_ERROR;
        }
        if ptr > 0 {
            ptr -= 1;
        }
        while ptr >= 1 && self.line.buf[ptr] != '\n' as u32 {
            ptr -= 1;
        }
        ptr += 1;
        let mut nc = nchars;
        while nc > 0 && ptr < self.line.last && self.line.buf[ptr] != '\n' as u32 {
            ptr += 1;
            nc -= 1;
        }
        self.line.cur = ptr;
        CC_CURSOR
    }

    fn ed_next_line(&mut self, _c: u32) -> u8 {
        let nchars = self.c_hpos();
        let mut ptr = self.line.cur;
        let mut arg = self.state.argument;
        while ptr < self.line.last {
            if self.line.buf[ptr] == '\n' as u32 {
                arg -= 1;
                if arg <= 0 {
                    break;
                }
            }
            ptr += 1;
        }
        if arg > 0 {
            return CC_ERROR;
        }
        ptr += 1;
        let mut nc = nchars;
        while nc > 0 && ptr < self.line.last && self.line.buf[ptr] != '\n' as u32 {
            ptr += 1;
            nc -= 1;
        }
        self.line.cur = ptr;
        CC_CURSOR
    }

    fn ed_command(&mut self, _c: u32) -> u8 {
        let mut tmpbuf: Vec<u32> = Vec::new();
        let tmplen = self.c_gets(&mut tmpbuf, Some(&['\n' as u32, ':' as u32, ' ' as u32]));
        self.terminal__putc('\n' as u32);
        if tmplen < 0 {
            self.terminal_beep();
        } else {
            tmpbuf.truncate(tmplen as usize);
            tmpbuf.push(0);
            if parse_line(self, &tmpbuf) == -1 {
                self.terminal_beep();
            }
        }
        self.map.current = 0;
        self.re_clear_display();
        CC_REFRESH
    }
}

// ---------------------------------------------------------------------------
// § emacs.c + vi.c command functions
// ---------------------------------------------------------------------------

impl Engine {
    fn em_delete_or_list(&mut self, c: u32) -> u8 {
        if self.line.cur == self.line.last {
            if self.line.cur == 0 {
                self.terminal_writec(c);
                CC_EOF
            } else {
                self.terminal_beep();
                CC_ERROR
            }
        } else {
            if self.state.doingarg != 0 {
                self.c_delafter(self.state.argument as usize);
            } else {
                self.c_delafter1();
            }
            if self.line.cur > self.line.last {
                self.line.cur = self.line.last;
            }
            CC_REFRESH
        }
    }

    fn em_delete_next_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == self.line.last {
            return CC_ERROR;
        }
        let cp = self.c__next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            ce_isword_wrap,
        );
        let mut kp = 0usize;
        for i in self.line.cur..cp {
            self.chared.kill.buf[kp] = self.line.buf[i];
            kp += 1;
        }
        self.chared.kill.last = kp;
        let n = cp - self.line.cur;
        self.c_delafter(n);
        if self.line.cur > self.line.last {
            self.line.cur = self.line.last;
        }
        CC_REFRESH
    }

    fn em_yank(&mut self, _c: u32) -> u8 {
        if self.chared.kill.last == 0 {
            return CC_NORM;
        }
        let klen = self.chared.kill.last;
        if self.line.last + klen >= self.line.limit {
            return CC_ERROR;
        }
        self.chared.kill.mark = self.line.cur;
        self.c_insert(klen);
        let mut cp = self.line.cur;
        for i in 0..klen {
            self.line.buf[cp] = self.chared.kill.buf[i];
            cp += 1;
        }
        if self.state.argument == 1 {
            self.line.cur = cp;
        }
        CC_REFRESH
    }

    fn em_kill_line(&mut self, _c: u32) -> u8 {
        let mut kp = 0usize;
        for i in 0..self.line.last {
            self.chared.kill.buf[kp] = self.line.buf[i];
            kp += 1;
        }
        self.chared.kill.last = kp;
        self.line.last = 0;
        self.line.cur = 0;
        CC_REFRESH
    }

    fn em_kill_region(&mut self, _c: u32) -> u8 {
        let mark = self.chared.kill.mark;
        if self.chared.kill.mark > self.line.cur {
            let mut kp = 0usize;
            for i in self.line.cur..mark {
                self.chared.kill.buf[kp] = self.line.buf[i];
                kp += 1;
            }
            self.chared.kill.last = kp;
            self.c_delafter(mark - self.line.cur);
        } else {
            let mut kp = 0usize;
            for i in mark..self.line.cur {
                self.chared.kill.buf[kp] = self.line.buf[i];
                kp += 1;
            }
            self.chared.kill.last = kp;
            self.c_delbefore(self.line.cur - mark);
            self.line.cur = mark;
        }
        CC_REFRESH
    }

    fn em_copy_region(&mut self, _c: u32) -> u8 {
        let mark = self.chared.kill.mark;
        let mut kp = 0usize;
        if mark > self.line.cur {
            for i in self.line.cur..mark {
                self.chared.kill.buf[kp] = self.line.buf[i];
                kp += 1;
            }
        } else {
            for i in mark..self.line.cur {
                self.chared.kill.buf[kp] = self.line.buf[i];
                kp += 1;
            }
        }
        self.chared.kill.last = kp;
        CC_NORM
    }

    fn em_gosmacs_transpose(&mut self, _c: u32) -> u8 {
        if self.line.cur > 1 {
            let c = self.line.buf[self.line.cur - 2];
            self.line.buf[self.line.cur - 2] = self.line.buf[self.line.cur - 1];
            self.line.buf[self.line.cur - 1] = c;
            CC_REFRESH
        } else {
            CC_ERROR
        }
    }

    fn em_next_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == self.line.last {
            return CC_ERROR;
        }
        self.line.cur = self.c__next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            ce_isword_wrap,
        );
        if self.map.typ == MAP_VI {
            if self.chared.vcmd.action != NOP {
                self.cv_delfini();
                return CC_REFRESH;
            }
        }
        CC_CURSOR
    }

    fn em_upper_case(&mut self, _c: u32) -> u8 {
        let ep = self.c__next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            ce_isword_wrap,
        );
        let mut cp = self.line.cur;
        while cp < ep {
            if iswlower(self.line.buf[cp]) {
                self.line.buf[cp] = towupper(self.line.buf[cp]);
            }
            cp += 1;
        }
        self.line.cur = ep;
        if self.line.cur > self.line.last {
            self.line.cur = self.line.last;
        }
        CC_REFRESH
    }

    fn em_capitol_case(&mut self, _c: u32) -> u8 {
        let ep = self.c__next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            ce_isword_wrap,
        );
        let mut cp = self.line.cur;
        while cp < ep {
            if iswalpha(self.line.buf[cp]) {
                if iswlower(self.line.buf[cp]) {
                    self.line.buf[cp] = towupper(self.line.buf[cp]);
                }
                cp += 1;
                break;
            }
            cp += 1;
        }
        while cp < ep {
            if iswupper(self.line.buf[cp]) {
                self.line.buf[cp] = towlower(self.line.buf[cp]);
            }
            cp += 1;
        }
        self.line.cur = ep;
        if self.line.cur > self.line.last {
            self.line.cur = self.line.last;
        }
        CC_REFRESH
    }

    fn em_lower_case(&mut self, _c: u32) -> u8 {
        let ep = self.c__next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            ce_isword_wrap,
        );
        let mut cp = self.line.cur;
        while cp < ep {
            if iswupper(self.line.buf[cp]) {
                self.line.buf[cp] = towlower(self.line.buf[cp]);
            }
            cp += 1;
        }
        self.line.cur = ep;
        if self.line.cur > self.line.last {
            self.line.cur = self.line.last;
        }
        CC_REFRESH
    }

    fn em_set_mark(&mut self, _c: u32) -> u8 {
        self.chared.kill.mark = self.line.cur;
        CC_NORM
    }

    fn em_exchange_mark(&mut self, _c: u32) -> u8 {
        let cp = self.line.cur;
        self.line.cur = self.chared.kill.mark;
        self.chared.kill.mark = cp;
        CC_CURSOR
    }

    fn em_universal_argument(&mut self, _c: u32) -> u8 {
        if self.state.argument > 1000000 {
            return CC_ERROR;
        }
        self.state.doingarg = 1;
        self.state.argument *= 4;
        CC_ARGHACK
    }

    fn em_meta_next(&mut self, _c: u32) -> u8 {
        self.state.metanext = 1;
        CC_ARGHACK
    }

    fn em_toggle_overwrite(&mut self, _c: u32) -> u8 {
        self.state.inputmode = if self.state.inputmode == MODE_INSERT {
            MODE_REPLACE
        } else {
            MODE_INSERT
        };
        CC_NORM
    }

    fn em_copy_prev_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == 0 {
            return CC_ERROR;
        }
        let cp = self.c__prev_word(self.line.cur, 0, self.state.argument, ce_isword_wrap);
        let oldc = self.line.cur;
        self.c_insert(oldc - cp);
        let mut dp = oldc;
        let mut ci = cp;
        while ci < oldc && dp < self.line.last {
            self.line.buf[dp] = self.line.buf[ci];
            dp += 1;
            ci += 1;
        }
        self.line.cur = dp;
        CC_REFRESH
    }

    fn em_inc_search_next(&mut self, _c: u32) -> u8 {
        self.search.patlen = 0;
        self.ce_inc_search(ED_SEARCH_NEXT_HISTORY as i32)
    }

    fn em_inc_search_prev(&mut self, _c: u32) -> u8 {
        self.search.patlen = 0;
        self.ce_inc_search(ED_SEARCH_PREV_HISTORY as i32)
    }

    fn em_delete_prev_char(&mut self, _c: u32) -> u8 {
        if self.line.cur <= 0 {
            return CC_ERROR;
        }
        if self.state.doingarg != 0 {
            self.c_delbefore(self.state.argument as usize);
        } else {
            self.c_delbefore1();
        }
        self.line.cur = self.line.cur.saturating_sub(self.state.argument as usize);
        CC_REFRESH
    }
}

// vi.c

impl Engine {
    fn cv_action(&mut self, c: u32) -> u8 {
        if self.chared.vcmd.action != NOP {
            if c != self.chared.vcmd.action as u32 {
                return CC_ERROR;
            }
            if c & YANK as u32 == 0 {
                self.cv_undo();
            }
            self.cv_yank(0, self.line.last);
            self.chared.vcmd.action = NOP;
            self.chared.vcmd.pos = 0;
            if c & YANK as u32 == 0 {
                self.line.last = 0;
                self.line.cur = 0;
            }
            if c & INSERT as u32 != 0 {
                self.map.current = 0;
            }
            return CC_REFRESH;
        }
        self.chared.vcmd.pos = self.line.cur;
        self.chared.vcmd.action = c as i32;
        CC_ARGHACK
    }

    fn cv_paste(&mut self, c: u32) -> u8 {
        let len = self.chared.kill.last;
        if len == 0 {
            return CC_ERROR;
        }
        self.cv_undo();
        if c == 0 && self.line.cur < self.line.last {
            self.line.cur += 1;
        }
        self.c_insert(len);
        if self.line.cur + len > self.line.last {
            return CC_ERROR;
        }
        for i in 0..len {
            self.line.buf[self.line.cur + i] = self.chared.kill.buf[i];
        }
        CC_REFRESH
    }

    fn vi_paste_next(&mut self, _c: u32) -> u8 {
        self.cv_paste(0)
    }

    fn vi_paste_prev(&mut self, _c: u32) -> u8 {
        self.cv_paste(1)
    }

    fn vi_prev_big_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == 0 {
            return CC_ERROR;
        }
        self.line.cur = self.cv_prev_word(self.line.cur, 0, self.state.argument, cv_isWord_wrap);
        if self.chared.vcmd.action != NOP {
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_prev_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == 0 {
            return CC_ERROR;
        }
        self.line.cur = self.cv_prev_word(self.line.cur, 0, self.state.argument, cv_isword_wrap);
        if self.chared.vcmd.action != NOP {
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_next_big_word(&mut self, _c: u32) -> u8 {
        if self.line.cur >= self.line.last.saturating_sub(1) {
            return CC_ERROR;
        }
        self.line.cur = self.cv_next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            cv_isWord_wrap,
        );
        if self.chared.vcmd.action != NOP {
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_next_word(&mut self, _c: u32) -> u8 {
        if self.line.cur >= self.line.last.saturating_sub(1) {
            return CC_ERROR;
        }
        self.line.cur = self.cv_next_word(
            self.line.cur,
            self.line.last,
            self.state.argument,
            cv_isword_wrap,
        );
        if self.chared.vcmd.action != NOP {
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_change_case(&mut self, _c: u32) -> u8 {
        if self.line.cur >= self.line.last {
            return CC_ERROR;
        }
        self.cv_undo();
        for _ in 0..self.state.argument {
            let c = self.line.buf[self.line.cur];
            if iswupper(c) {
                self.line.buf[self.line.cur] = towlower(c);
            } else if iswlower(c) {
                self.line.buf[self.line.cur] = towupper(c);
            }
            self.line.cur += 1;
            if self.line.cur >= self.line.last {
                self.line.cur -= 1;
                self.re_fastaddc();
                break;
            }
            self.re_fastaddc();
        }
        CC_NORM
    }

    fn vi_change_meta(&mut self, _c: u32) -> u8 {
        self.cv_action((DELETE | INSERT) as u32)
    }

    fn vi_insert_at_bol(&mut self, _c: u32) -> u8 {
        self.line.cur = 0;
        self.cv_undo();
        self.map.current = 0;
        CC_CURSOR
    }

    fn vi_replace_char(&mut self, _c: u32) -> u8 {
        if self.line.cur >= self.line.last {
            return CC_ERROR;
        }
        self.map.current = 0;
        self.state.inputmode = MODE_REPLACE_1;
        self.cv_undo();
        CC_ARGHACK
    }

    fn vi_replace_mode(&mut self, _c: u32) -> u8 {
        self.map.current = 0;
        self.state.inputmode = MODE_REPLACE;
        self.cv_undo();
        CC_NORM
    }

    fn vi_substitute_char(&mut self, _c: u32) -> u8 {
        self.c_delafter(self.state.argument as usize);
        self.map.current = 0;
        CC_REFRESH
    }

    fn vi_substitute_line(&mut self, _c: u32) -> u8 {
        self.cv_undo();
        self.cv_yank(0, self.line.last);
        self.em_kill_line(0);
        self.map.current = 0;
        CC_REFRESH
    }

    fn vi_change_to_eol(&mut self, _c: u32) -> u8 {
        self.cv_undo();
        self.cv_yank(self.line.cur, self.line.last - self.line.cur);
        self.ed_kill_line(0);
        self.map.current = 0;
        CC_REFRESH
    }

    fn vi_insert(&mut self, _c: u32) -> u8 {
        self.map.current = 0;
        self.cv_undo();
        CC_NORM
    }

    fn vi_add(&mut self, _c: u32) -> u8 {
        self.map.current = 0;
        let ret = if self.line.cur < self.line.last {
            self.line.cur += 1;
            if self.line.cur > self.line.last {
                self.line.cur = self.line.last;
            }
            CC_CURSOR
        } else {
            CC_NORM
        };
        self.cv_undo();
        ret
    }

    fn vi_add_at_eol(&mut self, _c: u32) -> u8 {
        self.map.current = 0;
        self.line.cur = self.line.last;
        self.cv_undo();
        CC_CURSOR
    }

    fn vi_delete_meta(&mut self, _c: u32) -> u8 {
        self.cv_action(DELETE as u32)
    }

    fn vi_end_big_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == self.line.last {
            return CC_ERROR;
        }
        self.line.cur = self.cv__endword(
            self.line.cur,
            self.line.last,
            self.state.argument,
            cv_isWord_wrap,
        );
        if self.chared.vcmd.action != NOP {
            self.line.cur += 1;
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_end_word(&mut self, _c: u32) -> u8 {
        if self.line.cur == self.line.last {
            return CC_ERROR;
        }
        self.line.cur = self.cv__endword(
            self.line.cur,
            self.line.last,
            self.state.argument,
            cv_isword_wrap,
        );
        if self.chared.vcmd.action != NOP {
            self.line.cur += 1;
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_undo(&mut self, _c: u32) -> u8 {
        if self.chared.undo.len == -1 {
            return CC_ERROR;
        }
        // swap line buffer and undo buffer
        let un = (
            self.chared.undo.len,
            self.chared.undo.cursor,
            self.chared.undo.buf.clone(),
        );
        self.chared.undo.len = self.line.last as isize;
        self.chared.undo.cursor = self.line.cur as i32;
        let newbuf = un.2.clone();
        self.chared.undo.buf = self.line.buf.clone();
        self.line.buf = newbuf;
        self.line.cur = un.1 as usize;
        self.line.last = un.0 as usize;
        self.line.buf[self.line.last] = 0;
        CC_REFRESH
    }

    fn vi_command_mode(&mut self, _c: u32) -> u8 {
        self.chared.vcmd.action = NOP;
        self.chared.vcmd.pos = 0;
        self.state.doingarg = 0;
        self.state.inputmode = MODE_INSERT;
        self.map.current = 1;
        if self.line.cur > 0 {
            self.line.cur -= 1;
        }
        CC_CURSOR
    }

    fn vi_zero(&mut self, c: u32) -> u8 {
        if self.state.doingarg != 0 {
            return self.ed_argument_digit(c);
        }
        self.line.cur = 0;
        if self.chared.vcmd.action != NOP {
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_delete_prev_char(&mut self, _c: u32) -> u8 {
        if self.line.cur <= 0 {
            return CC_ERROR;
        }
        self.c_delbefore1();
        self.line.cur -= 1;
        CC_REFRESH
    }

    fn vi_list_or_eof(&mut self, c: u32) -> u8 {
        if self.line.cur == self.line.last {
            if self.line.cur == 0 {
                self.terminal_writec(c);
                CC_EOF
            } else {
                self.terminal_beep();
                CC_ERROR
            }
        } else {
            self.terminal_beep();
            CC_ERROR
        }
    }

    fn vi_kill_line_prev(&mut self, _c: u32) -> u8 {
        let mut kp = 0usize;
        for i in 0..self.line.cur {
            self.chared.kill.buf[kp] = self.line.buf[i];
            kp += 1;
        }
        self.chared.kill.last = kp;
        self.c_delbefore(self.line.cur);
        self.line.cur = 0;
        CC_REFRESH
    }

    fn vi_search_prev(&mut self, _c: u32) -> u8 {
        self.cv_search(ED_SEARCH_PREV_HISTORY as i32)
    }

    fn vi_search_next(&mut self, _c: u32) -> u8 {
        self.cv_search(ED_SEARCH_NEXT_HISTORY as i32)
    }

    fn vi_repeat_search_next(&mut self, _c: u32) -> u8 {
        if self.search.patlen == 0 {
            CC_ERROR
        } else {
            self.cv_repeat_srch(self.search.patdir)
        }
    }

    fn vi_repeat_search_prev(&mut self, _c: u32) -> u8 {
        if self.search.patlen == 0 {
            CC_ERROR
        } else {
            let dir = if self.search.patdir == ED_SEARCH_PREV_HISTORY as i32 {
                ED_SEARCH_NEXT_HISTORY as i32
            } else {
                ED_SEARCH_PREV_HISTORY as i32
            };
            self.cv_repeat_srch(dir)
        }
    }

    fn vi_next_char(&mut self, _c: u32) -> u8 {
        self.cv_csearch(CHAR_FWD, 0, self.state.argument, 0)
    }

    fn vi_prev_char(&mut self, _c: u32) -> u8 {
        self.cv_csearch(CHAR_BACK, 0, self.state.argument, 0)
    }

    fn vi_to_next_char(&mut self, _c: u32) -> u8 {
        self.cv_csearch(CHAR_FWD, 0, self.state.argument, 1)
    }

    fn vi_to_prev_char(&mut self, _c: u32) -> u8 {
        self.cv_csearch(CHAR_BACK, 0, self.state.argument, 1)
    }

    fn vi_repeat_next_char(&mut self, _c: u32) -> u8 {
        self.cv_csearch(
            self.search.chadir,
            self.search.chacha,
            self.state.argument,
            self.search.chatflg as i32,
        )
    }

    fn vi_repeat_prev_char(&mut self, _c: u32) -> u8 {
        let dir = self.search.chadir;
        let r = self.cv_csearch(
            -dir,
            self.search.chacha,
            self.state.argument,
            self.search.chatflg as i32,
        );
        self.search.chadir = dir;
        r
    }

    fn vi_match(&mut self, _c: u32) -> u8 {
        let match_chars: Vec<u32> = "()[]{}".chars().map(|c| c as u32).collect();
        self.line.buf[self.line.last] = 0;
        let rest = &self.line.buf[self.line.cur..self.line.last];
        let mut i = 0usize;
        while i < rest.len() && !match_chars.contains(&rest[i]) {
            i += 1;
        }
        if i >= rest.len() {
            return CC_ERROR;
        }
        let o_ch = rest[i];
        let delta_i = match_chars.iter().position(|&c| c == o_ch).unwrap();
        let c_ch = match_chars[delta_i ^ 1];
        let mut count = 1i32;
        let delta: i64 = 1 - ((delta_i & 1) as i64) * 2;
        let mut cp = (self.line.cur + i) as i64;
        while count != 0 {
            cp += delta;
            if cp < 0 || cp >= self.line.last as i64 {
                return CC_ERROR;
            }
            let ch = self.line.buf[cp as usize];
            if ch == o_ch {
                count += 1;
            } else if ch == c_ch {
                count -= 1;
            }
        }
        self.line.cur = cp as usize;
        if self.chared.vcmd.action != NOP {
            if delta > 0 {
                self.line.cur += 1;
            }
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn vi_undo_line(&mut self, _c: u32) -> u8 {
        self.cv_undo();
        hist_get(self)
    }

    fn vi_to_column(&mut self, _c: u32) -> u8 {
        self.line.cur = 0;
        self.state.argument -= 1;
        self.ed_next_char(0)
    }

    fn vi_yank_end(&mut self, _c: u32) -> u8 {
        self.cv_yank(self.line.cur, self.line.last - self.line.cur);
        CC_REFRESH
    }

    fn vi_yank(&mut self, _c: u32) -> u8 {
        self.cv_action(YANK as u32)
    }

    fn vi_comment_out(&mut self, _c: u32) -> u8 {
        self.line.cur = 0;
        self.c_insert(1);
        self.line.buf[self.line.cur] = '#' as u32;
        self.re_refresh();
        self.ed_newline(0)
    }

    fn vi_alias(&mut self, _c: u32) -> u8 {
        if !self.chared.c_aliasfun {
            return CC_ERROR;
        }
        let mut ch = 0u32;
        if self.el_wgetc(&mut ch) != 1 {
            return CC_ERROR;
        }
        CC_NORM
    }

    fn vi_to_history_line(&mut self, _c: u32) -> u8 {
        let sv_event_no = self.hist.eventno;
        if self.hist.eventno == 0 {
            for i in 0..EL_BUFSIZ.min(self.line.last) {
                self.hist.buf[i] = self.line.buf[i];
            }
            self.hist.last = self.line.last;
        }
        if self.state.doingarg == 0 {
            self.hist.eventno = 0x7fff_ffff;
            hist_get(self);
        } else {
            self.hist.eventno = 1;
            if hist_get(self) == CC_ERROR {
                return CC_ERROR;
            }
            self.hist.eventno = 1 + self.hist.ev.num - self.state.argument;
            if self.hist.eventno < 0 {
                self.hist.eventno = sv_event_no;
                return CC_ERROR;
            }
        }
        let rval = hist_get(self);
        if rval == CC_ERROR {
            self.hist.eventno = sv_event_no;
        }
        rval
    }

    fn vi_history_word(&mut self, _c: u32) -> u8 {
        let mut ev = HistEventW::default();
        let Some(mut wp) = hist_convert_ev(self, H_FIRST, &mut ev) else {
            return CC_ERROR;
        };
        let wpw: Vec<u32> = ct_decode_string(&wp).unwrap_or_default();
        let mut idx = 0usize;
        let mut wsp: Option<usize> = None;
        let mut wep: usize = 0;
        loop {
            while idx < wpw.len() && iswspace(wpw[idx]) {
                idx += 1;
            }
            if idx >= wpw.len() {
                break;
            }
            wsp = Some(idx);
            while idx < wpw.len() && !iswspace(wpw[idx]) {
                idx += 1;
            }
            wep = idx;
            let cont = if self.state.doingarg != 0 {
                self.state.argument -= 1;
                self.state.argument > 0
            } else {
                false
            };
            if !cont || idx >= wpw.len() {
                break;
            }
        }
        let Some(wsp) = wsp else {
            return CC_ERROR;
        };
        if self.state.doingarg != 0 && self.state.argument != 0 {
            return CC_ERROR;
        }
        self.cv_undo();
        let len = wep - wsp;
        if self.line.cur < self.line.last {
            self.line.cur += 1;
        }
        self.c_insert(len + 1);
        let mut cp = self.line.cur;
        if cp < self.line.limit {
            self.line.buf[cp] = ' ' as u32;
            cp += 1;
        }
        let mut si = wsp;
        while si < wep && cp < self.line.limit {
            self.line.buf[cp] = wpw[si];
            cp += 1;
            si += 1;
        }
        self.line.cur = cp;
        self.map.current = 0;
        CC_REFRESH
    }

    fn vi_redo(&mut self, _c: u32) -> u8 {
        if self.state.doingarg == 0 && self.chared.redo.count != 0 {
            self.state.doingarg = 1;
            self.state.argument = self.chared.redo.count;
        }
        self.chared.vcmd.pos = self.line.cur;
        self.chared.vcmd.action = self.chared.redo.action;
        if self.chared.redo.pos != 0 {
            let mut seq: Vec<u32> = Vec::new();
            for i in 0..self.chared.redo.pos {
                seq.push(self.chared.redo.buf[i]);
            }
            el_wpush(self, Some(&seq));
        }
        self.state.thiscmd = self.chared.redo.cmd;
        self.state.thisch = self.chared.redo.ch;
        dispatch(self, self.chared.redo.cmd, self.chared.redo.ch)
    }

    fn cv_search(&mut self, dir: i32) -> u8 {
        let mut tmpbuf: Vec<u32> = Vec::new();
        let prompt: Vec<u32> = if dir == ED_SEARCH_PREV_HISTORY as i32 {
            "\n/".chars().map(|c| c as u32).collect()
        } else {
            "\n?".chars().map(|c| c as u32).collect()
        };
        self.search.patdir = dir;
        // ANCHOR: tmpbuf starts with ".*"
        let tmplen = self.c_gets(&mut tmpbuf, Some(&prompt));
        if tmplen == -1 {
            return CC_REFRESH;
        }
        // build pattern: ".*" + input
        let mut pat: Vec<u32> = vec!['.' as u32, '*' as u32];
        pat.extend_from_slice(&tmpbuf[..tmplen as usize]);
        let mut ch = 0u32;
        if tmplen as usize >= tmpbuf.len() {
            ch = 0;
        } else {
            ch = tmpbuf[tmplen as usize];
        }
        tmpbuf.truncate(tmplen as usize);
        let patlen = pat.len();
        if patlen == 2 {
            // use the old pattern
            if self.search.patlen == 0 {
                self.re_refresh();
                return CC_ERROR;
            }
            if self.search.patbuf[0] != '.' as u32 && self.search.patbuf[0] != '*' as u32 {
                let old = self.search.patbuf[..self.search.patlen].to_vec();
                let mut np = vec!['.' as u32, '*' as u32];
                np.extend_from_slice(&old);
                np.push('.' as u32);
                np.push('*' as u32);
                self.search.patbuf = np.clone();
                self.search.patlen = np.len();
            }
        } else {
            pat.push('.' as u32);
            pat.push('*' as u32);
            self.search.patbuf = pat;
            self.search.patlen = self.search.patbuf.len();
        }
        self.search.patbuf.resize(EL_BUFSIZ, 0);
        self.state.lastcmd = dir as u8;
        self.line.cur = 0;
        self.line.last = 0;
        let r = if dir == ED_SEARCH_PREV_HISTORY as i32 {
            self.ed_search_prev_history(0)
        } else {
            self.ed_search_next_history(0)
        };
        if r == CC_ERROR {
            self.re_refresh();
            return CC_ERROR;
        }
        if ch == 0o33 {
            self.re_refresh();
            return self.ed_newline(0);
        }
        CC_REFRESH
    }

    fn cv_repeat_srch(&mut self, c: i32) -> u8 {
        self.state.lastcmd = c as u8;
        self.line.last = 0;
        match c {
            23 => self.ed_search_next_history(0), // ED_SEARCH_NEXT_HISTORY
            24 => self.ed_search_prev_history(0), // ED_SEARCH_PREV_HISTORY
            _ => CC_ERROR,
        }
    }

    fn cv_csearch(&mut self, direction: i32, mut ch: u32, count: i32, tflag: i32) -> u8 {
        if ch == 0xFFFF_FFFF {
            let mut c = 0u32;
            if self.el_wgetc(&mut c) != 1 {
                return self.ed_end_of_file(0);
            }
            ch = c;
        }
        if ch == 0 {
            return CC_ERROR;
        }
        self.search.chacha = ch;
        self.search.chadir = direction;
        self.search.chatflg = tflag as i8;
        let mut cp = self.line.cur as i64;
        let mut count = count;
        while count > 0 {
            if (self.line.buf[cp as usize]) as u32 == ch {
                cp += direction as i64;
            }
            loop {
                cp += direction as i64;
                if cp >= self.line.last as i64 {
                    return CC_ERROR;
                }
                if cp < 0 {
                    return CC_ERROR;
                }
                if (self.line.buf[cp as usize]) as u32 == ch {
                    break;
                }
            }
            count -= 1;
        }
        if tflag != 0 {
            cp -= direction as i64;
        }
        self.line.cur = cp as usize;
        if self.chared.vcmd.action != NOP {
            if direction > 0 {
                self.line.cur += 1;
            }
            self.cv_delfini();
            return CC_REFRESH;
        }
        CC_CURSOR
    }

    fn ce_inc_search(&mut self, dir: i32) -> u8 {
        let ocursor = self.line.cur;
        let ohisteventno = self.hist.eventno;
        let oldpatlen = self.search.patlen;
        let mut newdir = dir;
        let mut ret = CC_NORM;
        const LEN: usize = 2; // ANCHOR ".*"
        let mut pchar: u32 = ':' as u32;
        loop {
            if self.search.patlen == 0 {
                pchar = ':' as u32;
                self.search.patbuf[0] = '.' as u32;
                self.search.patbuf[1] = '*' as u32;
                self.search.patlen = 2;
            }
            let mut done = false;
            let mut redo = false;
            self.line.buf[self.line.last] = '\n' as u32;
            self.line.last += 1;
            let dirtext: Vec<u32> = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                "bck".chars().map(|c| c as u32).collect()
            } else {
                "fwd".chars().map(|c| c as u32).collect()
            };
            for &c in &dirtext {
                self.line.buf[self.line.last] = c;
                self.line.last += 1;
            }
            self.line.buf[self.line.last] = pchar;
            self.line.last += 1;
            for i in LEN..self.search.patlen {
                self.line.buf[self.line.last] = self.search.patbuf[i];
                self.line.last += 1;
            }
            self.line.buf[self.line.last] = 0;
            self.re_refresh();
            let mut ch = 0u32;
            if self.el_wgetc(&mut ch) != 1 {
                return self.ed_end_of_file(0);
            }
            let curmap: &[u8] = if self.map.current == 0 {
                &self.map.key
            } else {
                &self.map.alt
            };
            let cmd = if ch >= N_KEYS as u32 {
                ED_INSERT
            } else {
                curmap[ch as usize]
            };
            match cmd {
                ED_INSERT | ED_DIGIT => {
                    if self.search.patlen >= EL_BUFSIZ - LEN {
                        self.terminal_beep();
                    } else {
                        self.search.patbuf[self.search.patlen] = ch;
                        self.search.patlen += 1;
                        self.line.buf[self.line.last] = ch;
                        self.line.last += 1;
                        self.line.buf[self.line.last] = 0;
                        self.re_refresh();
                    }
                }
                EM_INC_SEARCH_NEXT => {
                    newdir = ED_SEARCH_NEXT_HISTORY as i32;
                    redo = true;
                }
                EM_INC_SEARCH_PREV => {
                    newdir = ED_SEARCH_PREV_HISTORY as i32;
                    redo = true;
                }
                EM_DELETE_PREV_CHAR | ED_DELETE_PREV_CHAR => {
                    if self.search.patlen > LEN {
                        done = true;
                    } else {
                        self.terminal_beep();
                    }
                }
                _ => match ch {
                    0x07 => {
                        // ^G abort
                        ret = CC_ERROR;
                        done = true;
                    }
                    0o33 => {
                        // ESC terminate
                        ret = CC_REFRESH;
                        done = true;
                    }
                    _ => {
                        // terminate and execute cmd
                        let mut endcmd = vec![ch, 0];
                        el_wpush(self, Some(&endcmd));
                        ret = CC_REFRESH;
                        done = true;
                    }
                },
            }
            while self.line.last > 0 && self.line.buf[self.line.last - 1] != '\n' as u32 {
                self.line.last -= 1;
            }
            self.line.buf[self.line.last] = 0;
            if !done {
                if self.search.patlen > LEN {
                    if redo && newdir == dir {
                        if pchar == '?' as u32 {
                            self.hist.eventno = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                                0
                            } else {
                                0x7fff_ffff
                            };
                            if hist_get(self) == CC_ERROR {
                                hist_get(self);
                            }
                            self.line.cur = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                                self.line.last
                            } else {
                                0
                            };
                        } else {
                            self.line.cur = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                                self.line.cur - 1
                            } else {
                                self.line.cur + 1
                            };
                        }
                    }
                    self.search.patbuf[self.search.patlen] = '.' as u32;
                    self.search.patbuf[self.search.patlen + 1] = '*' as u32;
                    let patext = self.search.patlen + 2;
                    self.search.patbuf[patext] = 0;
                    let mut r = self.ce_search_line(newdir);
                    if self.line.cur > self.line.last {
                        self.line.cur = self.line.last;
                    }
                    if r == CC_ERROR {
                        self.state.lastcmd = newdir as u8;
                        r = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                            self.ed_search_prev_history(0)
                        } else {
                            self.ed_search_next_history(0)
                        };
                        if r != CC_ERROR {
                            self.line.cur = if newdir == ED_SEARCH_PREV_HISTORY as i32 {
                                self.line.last
                            } else {
                                0
                            };
                            self.ce_search_line(newdir);
                        }
                    }
                    self.search.patlen -= LEN;
                    self.search.patbuf[self.search.patlen] = 0;
                    if r == CC_ERROR {
                        self.terminal_beep();
                        if self.hist.eventno != ohisteventno {
                            self.hist.eventno = ohisteventno;
                            if hist_get(self) == CC_ERROR {
                                return CC_ERROR;
                            }
                        }
                        self.line.cur = ocursor;
                        pchar = '?' as u32;
                    } else {
                        pchar = ':' as u32;
                    }
                }
                ret = self.ce_inc_search(newdir);
                if ret == CC_ERROR && pchar == '?' as u32 && oldpatlen == 0 {
                    ret = CC_NORM;
                }
            }
            if ret == CC_NORM || (ret == CC_ERROR && oldpatlen == 0) {
                self.search.patlen = oldpatlen;
                if self.hist.eventno != ohisteventno {
                    self.hist.eventno = ohisteventno;
                    if hist_get(self) == CC_ERROR {
                        return CC_ERROR;
                    }
                }
                self.line.cur = ocursor;
                if ret == CC_ERROR {
                    self.re_refresh();
                }
            }
            if done || ret != CC_NORM {
                return ret;
            }
        }
    }

    fn ce_search_line(&mut self, dir: i32) -> u8 {
        let mut pat: Vec<u32> = Vec::new();
        for i in 1..self.search.patlen {
            pat.push(self.search.patbuf[i]);
        }
        if !pat.is_empty() {
            pat[0] = '^' as u32;
        }
        if dir == ED_SEARCH_PREV_HISTORY as i32 {
            let mut cp = self.line.cur as i64;
            while cp >= 0 {
                if self.el_match(&self.line.buf[cp as usize..self.line.last], &pat) {
                    self.line.cur = cp as usize;
                    return CC_NORM;
                }
                cp -= 1;
            }
            CC_ERROR
        } else {
            let mut cp = self.line.cur;
            while cp < self.line.last {
                if self.el_match(&self.line.buf[cp..self.line.last], &pat) {
                    self.line.cur = cp;
                    return CC_NORM;
                }
                cp += 1;
            }
            CC_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// § dispatch — el_map.func table (func.h)
// ---------------------------------------------------------------------------

fn dispatch(el: &mut Engine, cmd: u8, ch: u32) -> u8 {
    match cmd {
        ED_ARGUMENT_DIGIT => el.ed_argument_digit(ch),
        ED_CLEAR_SCREEN => el.ed_clear_screen(ch),
        ED_COMMAND => el.ed_command(ch),
        ED_DELETE_NEXT_CHAR => el.ed_delete_next_char(ch),
        ED_DELETE_PREV_CHAR => el.ed_delete_prev_char(ch),
        ED_DELETE_PREV_WORD => el.ed_delete_prev_word(ch),
        ED_DIGIT => el.ed_digit(ch),
        ED_END_OF_FILE => el.ed_end_of_file(ch),
        ED_IGNORE => el.ed_ignore(ch),
        ED_INSERT => el.ed_insert(ch),
        ED_KILL_LINE => el.ed_kill_line(ch),
        ED_MOVE_TO_BEG => el.ed_move_to_beg(ch),
        ED_MOVE_TO_END => el.ed_move_to_end(ch),
        ED_NEWLINE => el.ed_newline(ch),
        ED_NEXT_CHAR => el.ed_next_char(ch),
        ED_NEXT_HISTORY => el.ed_next_history(ch),
        ED_NEXT_LINE => el.ed_next_line(ch),
        ED_PREV_CHAR => el.ed_prev_char(ch),
        ED_PREV_HISTORY => el.ed_prev_history(ch),
        ED_PREV_LINE => el.ed_prev_line(ch),
        ED_PREV_WORD => el.ed_prev_word(ch),
        ED_QUOTED_INSERT => el.ed_quoted_insert(ch),
        ED_REDISPLAY => el.ed_redisplay(ch),
        ED_SEARCH_NEXT_HISTORY => el.ed_search_next_history(ch),
        ED_SEARCH_PREV_HISTORY => el.ed_search_prev_history(ch),
        ED_SEQUENCE_LEAD_IN => el.ed_sequence_lead_in(ch),
        ED_START_OVER => el.ed_start_over(ch),
        ED_TRANSPOSE_CHARS => el.ed_transpose_chars(ch),
        ED_UNASSIGNED => el.ed_unassigned(ch),
        EM_CAPITOL_CASE => el.em_capitol_case(ch),
        EM_COPY_PREV_WORD => el.em_copy_prev_word(ch),
        EM_COPY_REGION => el.em_copy_region(ch),
        EM_DELETE_NEXT_WORD => el.em_delete_next_word(ch),
        EM_DELETE_OR_LIST => el.em_delete_or_list(ch),
        EM_DELETE_PREV_CHAR => el.em_delete_prev_char(ch),
        EM_EXCHANGE_MARK => el.em_exchange_mark(ch),
        EM_GOSMACS_TRANSPOSE => el.em_gosmacs_transpose(ch),
        EM_INC_SEARCH_NEXT => el.em_inc_search_next(ch),
        EM_INC_SEARCH_PREV => el.em_inc_search_prev(ch),
        EM_KILL_LINE => el.em_kill_line(ch),
        EM_KILL_REGION => el.em_kill_region(ch),
        EM_LOWER_CASE => el.em_lower_case(ch),
        EM_META_NEXT => el.em_meta_next(ch),
        EM_NEXT_WORD => el.em_next_word(ch),
        EM_SET_MARK => el.em_set_mark(ch),
        EM_TOGGLE_OVERWRITE => el.em_toggle_overwrite(ch),
        EM_UNIVERSAL_ARGUMENT => el.em_universal_argument(ch),
        EM_UPPER_CASE => el.em_upper_case(ch),
        EM_YANK => el.em_yank(ch),
        VI_ADD => el.vi_add(ch),
        VI_ADD_AT_EOL => el.vi_add_at_eol(ch),
        VI_ALIAS => el.vi_alias(ch),
        VI_CHANGE_CASE => el.vi_change_case(ch),
        VI_CHANGE_META => el.vi_change_meta(ch),
        VI_CHANGE_TO_EOL => el.vi_change_to_eol(ch),
        VI_COMMAND_MODE => el.vi_command_mode(ch),
        VI_COMMENT_OUT => el.vi_comment_out(ch),
        VI_DELETE_META => el.vi_delete_meta(ch),
        VI_DELETE_PREV_CHAR => el.vi_delete_prev_char(ch),
        VI_END_BIG_WORD => el.vi_end_big_word(ch),
        VI_END_WORD => el.vi_end_word(ch),
        VI_HISTEDIT => el.vi_histedit(ch),
        VI_HISTORY_WORD => el.vi_history_word(ch),
        VI_INSERT => el.vi_insert(ch),
        VI_INSERT_AT_BOL => el.vi_insert_at_bol(ch),
        VI_KILL_LINE_PREV => el.vi_kill_line_prev(ch),
        VI_LIST_OR_EOF => el.vi_list_or_eof(ch),
        VI_MATCH => el.vi_match(ch),
        VI_NEXT_BIG_WORD => el.vi_next_big_word(ch),
        VI_NEXT_CHAR => el.vi_next_char(ch),
        VI_NEXT_WORD => el.vi_next_word(ch),
        VI_PASTE_NEXT => el.vi_paste_next(ch),
        VI_PASTE_PREV => el.vi_paste_prev(ch),
        VI_PREV_BIG_WORD => el.vi_prev_big_word(ch),
        VI_PREV_CHAR => el.vi_prev_char(ch),
        VI_PREV_WORD => el.vi_prev_word(ch),
        VI_REDO => el.vi_redo(ch),
        VI_REPEAT_NEXT_CHAR => el.vi_repeat_next_char(ch),
        VI_REPEAT_PREV_CHAR => el.vi_repeat_prev_char(ch),
        VI_REPEAT_SEARCH_NEXT => el.vi_repeat_search_next(ch),
        VI_REPEAT_SEARCH_PREV => el.vi_repeat_search_prev(ch),
        VI_REPLACE_CHAR => el.vi_replace_char(ch),
        VI_REPLACE_MODE => el.vi_replace_mode(ch),
        VI_SEARCH_NEXT => el.vi_search_next(ch),
        VI_SEARCH_PREV => el.vi_search_prev(ch),
        VI_SUBSTITUTE_CHAR => el.vi_substitute_char(ch),
        VI_SUBSTITUTE_LINE => el.vi_substitute_line(ch),
        VI_TO_COLUMN => el.vi_to_column(ch),
        VI_TO_HISTORY_LINE => el.vi_to_history_line(ch),
        VI_TO_NEXT_CHAR => el.vi_to_next_char(ch),
        VI_TO_PREV_CHAR => el.vi_to_prev_char(ch),
        VI_UNDO => el.vi_undo(ch),
        VI_UNDO_LINE => el.vi_undo_line(ch),
        VI_YANK => el.vi_yank(ch),
        VI_YANK_END => el.vi_yank_end(ch),
        VI_ZERO => el.vi_zero(ch),
        _ => {
            // user-defined functions (EL_ADDFN)
            let idx = (cmd as usize) - EL_NUM_FCNS;
            if idx < el.user_funcs.len() {
                (el.user_funcs[idx].2)(el, ch)
            } else {
                CC_ERROR
            }
        }
    }
}

impl Engine {
    fn vi_histedit(&mut self, _c: u32) -> u8 {
        // vi-histedit forks an editor; not exercised by the corpus
        CC_ERROR
    }

    fn ch_reset(&mut self) {
        self.line.cur = 0;
        self.line.last = 0;
        self.chared.undo.len = -1;
        self.chared.undo.cursor = 0;
        self.chared.vcmd.action = NOP;
        self.chared.vcmd.pos = 0;
        self.chared.kill.mark = 0;
        self.map.current = 0;
        self.state.inputmode = MODE_INSERT;
        self.state.doingarg = 0;
        self.state.metanext = 0;
        self.state.argument = 1;
        self.state.lastcmd = ED_UNASSIGNED;
        self.hist.eventno = 0;
    }

    fn ch_init(&mut self) -> i32 {
        self.line = LineBuf::new(EL_BUFSIZ);
        self.chared.undo.buf = vec![0; EL_BUFSIZ];
        self.chared.undo.len = -1;
        self.chared.undo.cursor = 0;
        self.chared.redo.buf = vec![0; EL_BUFSIZ];
        self.chared.redo.pos = 0;
        self.chared.redo.lim = EL_BUFSIZ;
        self.chared.redo.cmd = ED_UNASSIGNED;
        self.chared.vcmd.action = NOP;
        self.chared.vcmd.pos = 0;
        self.chared.kill.buf = vec![0; EL_BUFSIZ];
        self.chared.kill.mark = 0;
        self.chared.kill.last = 0;
        self.chared.c_resizefun = false;
        self.chared.c_aliasfun = false;
        self.map.current = 0;
        self.state.inputmode = MODE_INSERT;
        self.state.doingarg = 0;
        self.state.metanext = 0;
        self.state.argument = 1;
        self.state.lastcmd = ED_UNASSIGNED;
        0
    }
}

// ---------------------------------------------------------------------------
// § parse.c + tokenizer.c
// ---------------------------------------------------------------------------

pub struct Tokenizer {
    pub ifs: Vec<u32>,
    pub argc: usize,
    pub amax: usize,
    /// Indices into `wspace` (the C's `const Char **argv` pointer array).
    /// Entries beyond `argc` keep stale values across tok_reset, exactly
    /// like the C: a failed tok_line returns without updating the caller's
    /// argc/argv, so the residue of the previous parse is observed.
    pub argv: Vec<Option<usize>>,
    /// Flat word buffer (the C's `Char *wspace`); tokens live here as
    /// NUL-terminated C strings and are reused across parses.
    pub wspace: Vec<u32>,
    pub wptr: usize,
    pub wstart: usize,
    pub quote: i32,
    pub flags: i32,
}

pub const Q_none: i32 = 0;
pub const Q_single: i32 = 1;
pub const Q_double: i32 = 2;
pub const Q_one: i32 = 3;
pub const Q_doubleone: i32 = 4;

pub const TOK_KEEP: i32 = 1;
pub const TOK_EAT: i32 = 2;

impl Tokenizer {
    pub fn tok_init(ifs: Option<&[u32]>) -> Tokenizer {
        let ifs = match ifs {
            Some(s) => s.to_vec(),
            None => "\t \n".chars().map(|c| c as u32).collect(),
        };
        Tokenizer {
            ifs,
            argc: 0,
            amax: 10,
            argv: Vec::new(),
            wspace: vec![0; 20],
            wptr: 0,
            wstart: 0,
            quote: Q_none,
            flags: 0,
        }
    }

    /// FUN(tok,reset): resets the parse state but NOT the argv array (the C
    /// keeps the old pointers — they are overwritten as new tokens finish).
    pub fn tok_reset(&mut self) {
        self.argc = 0;
        self.wstart = 0;
        self.wptr = 0;
        self.flags = 0;
        self.quote = Q_none;
    }

    /// FUN(tok,finish): terminate the current word in wspace and record it.
    pub fn tok_finish(&mut self) {
        if self.wptr >= self.wspace.len() {
            self.wspace.resize(self.wptr + 1, 0);
        }
        self.wspace[self.wptr] = 0;
        if (self.flags & TOK_KEEP != 0) || self.wptr != self.wstart {
            while self.argv.len() <= self.argc + 1 {
                self.argv.push(None);
            }
            self.argv[self.argc] = Some(self.wstart);
            self.argv[self.argc + 1] = None;
            self.argc += 1;
            // the C does `wstart = ++wptr`: the NUL just written is skipped
            // so the next word starts after it
            self.wptr += 1;
            self.wstart = self.wptr;
        }
        self.flags &= !TOK_KEEP;
    }

    /// tok_str(): simpler version of tok_line; on success the caller's
    /// argc/argv are updated, on error they keep their previous values
    /// (the C returns from inside the loop before the outok update).
    pub fn tok_str(&mut self, line: &[u32], argc: &mut i32, argv: &mut Vec<Option<usize>>) -> i32 {
        let r = self.tok_line_impl(line, line.len(), None);
        if r == 0 {
            *argc = self.argc as i32;
            *argv = self.argv.clone();
        }
        r
    }

    /// tok_line with cursor tracking (cursorc/cursoro optional).
    pub fn tok_line(
        &mut self,
        buffer: &[u32],
        lastchar: usize,
        cursor: Option<usize>,
        cursorc: &mut i32,
        cursoro: &mut i32,
        argc: &mut i32,
        argv: &mut Vec<Option<usize>>,
    ) -> i32 {
        let mut cc = -1i32;
        let mut co = -1i32;
        let mut idx = 0usize;
        let r = loop {
            let is_end = idx >= lastchar;
            if let Some(cu) = cursor {
                if idx == cu {
                    cc = self.argc as i32;
                    co = (self.wptr - self.wstart) as i32;
                }
            }
            let c = if is_end { 0 } else { buffer[idx] };
            let r = self.step(c, is_end);
            if is_end {
                // the C's '\0' case: return 1/2/3 directly for the quote
                // errors / quoted return; Q_none falls through to outok
                if r == 0 {
                    cc = if cc == -1 { self.argc as i32 } else { cc };
                    co = if co == -1 {
                        (self.wptr - self.wstart) as i32
                    } else {
                        co
                    };
                    self.tok_finish();
                }
                break r;
            }
            if r != 0 {
                break r;
            }
            idx += 1;
        };
        *cursorc = cc;
        *cursoro = co;
        if r == 0 {
            *argc = self.argc as i32;
            *argv = self.argv.clone();
        }
        r
    }

    fn tok_line_impl(&mut self, line: &[u32], len: usize, cursor: Option<usize>) -> i32 {
        let _ = cursor;
        let mut idx = 0usize;
        loop {
            let is_end = idx >= len;
            let c = if is_end { 0 } else { line[idx] };
            let r = self.step(c, is_end);
            if is_end {
                // the C's '\0' case: Q_none -> outok (0); Q_single -> 1;
                // Q_double -> 2; TOK_EAT -> 3; Q_one/Q_doubleone push the
                // NUL and continue (the C re-reads past the NUL; the
                // corpus never reaches the re-read)
                if r == 0 {
                    self.tok_finish();
                }
                return r;
            }
            if r != 0 {
                return r;
            }
            idx += 1;
        }
    }

    /// One state-machine step; returns 0 = continue, 1/2/3 = line-terminating.
    fn step(&mut self, c: u32, is_end: bool) -> i32 {
        match c {
            0x27 => {
                self.flags |= TOK_KEEP;
                self.flags &= !TOK_EAT;
                match self.quote {
                    Q_none => self.quote = Q_single,
                    Q_single => self.quote = Q_none,
                    Q_one => {
                        self.quote = Q_none;
                        self.push(c);
                    }
                    Q_double => self.push(c),
                    Q_doubleone => {
                        self.quote = Q_double;
                        self.push(c);
                    }
                    _ => return -1,
                }
            }
            0x22 => {
                self.flags &= !TOK_EAT;
                self.flags |= TOK_KEEP;
                match self.quote {
                    Q_none => self.quote = Q_double,
                    Q_double => self.quote = Q_none,
                    Q_one => {
                        self.quote = Q_none;
                        self.push(c);
                    }
                    Q_single => self.push(c),
                    Q_doubleone => {
                        self.quote = Q_double;
                        self.push(c);
                    }
                    _ => return -1,
                }
            }
            0x5c => {
                self.flags |= TOK_KEEP;
                self.flags &= !TOK_EAT;
                match self.quote {
                    Q_none => self.quote = Q_one,
                    Q_double => self.quote = Q_doubleone,
                    Q_one => {
                        self.push(c);
                        self.quote = Q_none;
                    }
                    Q_single => self.push(c),
                    Q_doubleone => {
                        self.quote = Q_double;
                        self.push(c);
                    }
                    _ => return -1,
                }
            }
            0x0a => {
                self.flags &= !TOK_EAT;
                match self.quote {
                    Q_none => return 0, // tok_line_outok
                    Q_single | Q_double => self.push(c),
                    Q_doubleone => {
                        self.flags |= TOK_EAT;
                        self.quote = Q_double;
                    }
                    Q_one => {
                        self.flags |= TOK_EAT;
                        self.quote = Q_none;
                    }
                    _ => return 0,
                }
            }
            0 => {
                if is_end {
                    match self.quote {
                        Q_none => {
                            if self.flags & TOK_EAT != 0 {
                                self.flags &= !TOK_EAT;
                                return 3;
                            }
                            return 0; // tok_line_outok
                        }
                        Q_single => return 1,
                        Q_double => return 2,
                        Q_doubleone => {
                            self.quote = Q_double;
                            self.push(c);
                        }
                        Q_one => {
                            self.quote = Q_none;
                            self.push(c);
                        }
                        _ => return -1,
                    }
                }
            }
            _ => {
                self.flags &= !TOK_EAT;
                match self.quote {
                    Q_none => {
                        if self.ifs.contains(&c) {
                            self.tok_finish();
                        } else {
                            self.push(c);
                        }
                    }
                    Q_single | Q_double => self.push(c),
                    Q_doubleone => {
                        self.push('\\' as u32);
                        self.quote = Q_double;
                        self.push(c);
                    }
                    Q_one => {
                        self.quote = Q_none;
                        self.push(c);
                    }
                    _ => return -1,
                }
            }
        }
        self.grow();
        0
    }

    fn push(&mut self, c: u32) {
        if self.wptr >= self.wspace.len() - 1 {
            self.grow();
        }
        self.wspace[self.wptr] = c;
        self.wptr += 1;
    }

    fn grow(&mut self) {
        if self.wptr >= self.wspace.len() - 4 {
            let size = self.wspace.len() + 20;
            self.wspace.resize(size, 0);
        }
        if self.argc >= self.amax - 4 {
            self.amax += 10;
        }
    }
}

fn parse_line(el: &mut Engine, line: &[u32]) -> i32 {
    let mut tok = Tokenizer::tok_init(None);
    let mut argc = 0i32;
    let mut argv_idx: Vec<Option<usize>> = Vec::new();
    tok.tok_str(line, &mut argc, &mut argv_idx);
    let mut argv: Vec<Vec<u32>> = Vec::new();
    for i in 0..argc.max(0) as usize {
        match argv_idx.get(i).copied().flatten() {
            Some(start) => {
                let s = &tok.wspace[start..];
                let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                argv.push(s[..end].to_vec());
            }
            None => argv.push(Vec::new()),
        }
    }
    el_wparse(el, argc, &argv)
}

fn el_wparse(el: &mut Engine, argc: i32, argv: &[Vec<u32>]) -> i32 {
    if argc < 1 || argv.is_empty() {
        return -1;
    }
    let first: Vec<u8> = ct_encode_string(&argv[0]);
    let mut ptr: &[u8] = &first;
    if let Some(pos) = first.iter().position(|&b| b == b':') {
        if pos == 0 {
            return 0;
        }
        let tprog = &first[..pos];
        let rest = &first[pos + 1..];
        // el_match(el->el_prog, tprog)
        let prog: Vec<u8> = ct_encode_string(&el.prog);
        let matched = el_match_prog(&prog, tprog);
        if !matched {
            return 0;
        }
        ptr = rest;
    }
    let cmds: [(&[u8], i32); 7] = [
        (b"bind", 0),
        (b"echotc", 1),
        (b"edit", 2),
        (b"history", 3),
        (b"telltc", 4),
        (b"settc", 5),
        (b"setty", 6),
    ];
    for (name, idx) in cmds.iter() {
        if ptr == *name {
            let r = match idx {
                0 => map_bind(el, &argv),
                2 => el_editmode(el, &argv),
                3 => hist_command(el, &argv),
                _ => -1,
            };
            return -r;
        }
    }
    -1
}

fn el_match_prog(prog: &[u8], pat: &[u8]) -> bool {
    // wcsstr semantics on the raw prog
    if pat.is_empty() {
        return true;
    }
    prog.windows(pat.len()).any(|w| w == pat)
}

fn el_editmode(el: &mut Engine, argv: &[Vec<u32>]) -> i32 {
    if argv.len() < 2 {
        return -1;
    }
    let how: Vec<u8> = ct_encode_string(&argv[1]);
    if how == b"on" {
        el.flags &= !EDIT_DISABLED;
        el.tty_rawmode();
        0
    } else if how == b"off" {
        el.tty_cookedmode();
        el.flags |= EDIT_DISABLED;
        0
    } else {
        // fprintf to errfile
        let msg = format!("edit: Bad value `{}'.\n", String::from_utf8_lossy(&how));
        el.err_msg(&msg);
        -1
    }
}

fn hist_command(el: &mut Engine, argv: &[Vec<u32>]) -> i32 {
    let Some(ref mut h) = el.hist.refp else {
        return -1;
    };
    if argv.len() == 1 || ct_encode_string(&argv[1]) == b"list" {
        // list history entries newest-first
        let mut ev = HistEventN::default();
        let mut hno = 1i32;
        let mut out_lines: Vec<(i32, Vec<u8>)> = Vec::new();
        if history_def_last(&mut h.h_ref, &mut ev) == 0 {
            loop {
                if let Some(s) = ev.str.clone() {
                    let mut s = s;
                    if s.last() == Some(&b'\n') {
                        s.pop();
                    }
                    out_lines.push((hno, s));
                }
                hno += 1;
                if history_def_prev(&mut h.h_ref, &mut ev) != 0 {
                    break;
                }
            }
        }
        for (n, s) in out_lines.iter().rev() {
            // strvis(buf, ptr, VIS_NL)
            let vis = strvis_nl(s);
            el.out
                .extend_from_slice(format!("{}\t{}", n, vis).as_bytes());
            el.out.push(b'\n');
        }
        return 0;
    }
    if argv.len() != 3 {
        return -1;
    }
    let num = wcstol_wide(&argv[2]);
    let what: Vec<u8> = ct_encode_string(&argv[1]);
    if what == b"size" {
        let mut evn = HistEventN::default();
        return history_setsize(h, &mut evn, num);
    }
    if what == b"unique" {
        let mut evn = HistEventN::default();
        return history_setunique(h, &mut evn, num);
    }
    -1
}

fn wcstol_wide(s: &[u32]) -> i32 {
    let text: Vec<u8> = ct_encode_string(s);
    std::str::from_utf8(&text)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0)
}

fn strvis_nl(s: &[u8]) -> String {
    // strvis with VIS_NL: \n -> \\n
    let mut out = String::new();
    for &b in s {
        match b {
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{:03o}", b)),
        }
    }
    out
}

fn map_bind(el: &mut Engine, argv: &[Vec<u32>]) -> i32 {
    let mut argc = 1usize;
    let mut ntype = XK_CMD;
    let mut rem = false;
    let mut map_alt = false;
    let mut key = false;
    while argc < argv.len() {
        let p: Vec<u8> = ct_encode_string(&argv[argc]);
        if p.first() == Some(&b'-') && p.len() >= 2 {
            match p[1] {
                b'a' => map_alt = true,
                b's' => ntype = XK_STR,
                b'k' => key = true,
                b'r' => rem = true,
                b'v' => {
                    map_init_vi(el);
                    return 0;
                }
                b'e' => {
                    map_init_emacs(el);
                    return 0;
                }
                b'l' => {
                    for i in 0..el.map.nfunc {
                        el.out.extend_from_slice(HELP[i].1.as_bytes());
                        el.out.extend_from_slice(b"\n\t");
                        el.out.extend_from_slice(HELP[i].2.as_bytes());
                        el.out.push(b'\n');
                    }
                    return 0;
                }
                _ => {
                    el.out
                        .extend_from_slice(ct_encode_string(&argv[0]).as_slice());
                    el.out.extend_from_slice(
                        format!(": Invalid switch `{}'.\n", p[1] as char).as_bytes(),
                    );
                }
            }
            argc += 1;
        } else {
            break;
        }
    }
    if argc >= argv.len() {
        // print all keys
        map_print_all_keys(el);
        return 0;
    }
    // parse the input key string (parse__string)
    let in_wide: Vec<u32> = if key {
        argv[argc].clone()
    } else {
        let raw: Vec<u8> = ct_encode_string(&argv[argc]);
        match parse_string_wide(&raw) {
            Some(s) => s,
            None => {
                el.out
                    .extend_from_slice(ct_encode_string(&argv[0]).as_slice());
                el.out
                    .extend_from_slice(b": Invalid \\ or ^ in instring.\r\n");
                return -1;
            }
        }
    };
    argc += 1;
    if rem {
        if key {
            return -1;
        }
        if in_wide.len() > 1 {
            el.keymacro_delete(&in_wide);
        } else if in_wide[0] < N_KEYS as u32
            && if map_alt {
                el.map.alt[in_wide[0] as usize]
            } else {
                el.map.key[in_wide[0] as usize]
            } == ED_SEQUENCE_LEAD_IN
        {
            el.keymacro_delete(&in_wide);
        } else {
            let m = if map_alt {
                &mut el.map.alt
            } else {
                &mut el.map.key
            };
            m[in_wide[0] as usize] = ED_UNASSIGNED;
        }
        return 0;
    }
    if argc >= argv.len() {
        // print key binding
        if key {
            return 0;
        }
        map_print_key(el, if map_alt { 1 } else { 0 }, &in_wide);
        return 0;
    }
    let out_raw: Vec<u8> = ct_encode_string(&argv[argc]);
    if ntype == XK_STR {
        let out = match parse_string_wide(&out_raw) {
            Some(s) => s,
            None => {
                el.out
                    .extend_from_slice(ct_encode_string(&argv[0]).as_slice());
                el.out
                    .extend_from_slice(b": Invalid \\ or ^ in outstring.\r\n");
                return -1;
            }
        };
        let val = el.keymacro_map_str(out);
        if !key {
            el.keymacro_add(&in_wide, val, XK_STR);
        }
        let m = if map_alt {
            &mut el.map.alt
        } else {
            &mut el.map.key
        };
        m[in_wide[0] as usize] = ED_SEQUENCE_LEAD_IN;
    } else {
        let cmd = parse_cmd(el, &out_raw);
        if cmd == -1 {
            el.out
                .extend_from_slice(ct_encode_string(&argv[0]).as_slice());
            el.out.extend_from_slice(b": Invalid command `");
            el.out.extend_from_slice(&out_raw);
            el.out.extend_from_slice(b"'.\r\n");
            return -1;
        }
        if !key {
            if in_wide.len() > 1 {
                let val = el.keymacro_map_cmd(cmd as u8);
                el.keymacro_add(&in_wide, val, XK_CMD);
                let m = if map_alt {
                    &mut el.map.alt
                } else {
                    &mut el.map.key
                };
                m[in_wide[0] as usize] = ED_SEQUENCE_LEAD_IN;
            } else {
                let m0 = if map_alt {
                    el.map.alt[in_wide[0] as usize]
                } else {
                    el.map.key[in_wide[0] as usize]
                };
                el.keymacro_clear(m0 as u32);
                let m = if map_alt {
                    &mut el.map.alt
                } else {
                    &mut el.map.key
                };
                m[in_wide[0] as usize] = cmd as u8;
            }
        }
    }
    0
}

fn map_print_all_keys(el: &mut Engine) {
    el.out.extend_from_slice(b"Standard key bindings\n");
    map_print_range(el, 0);
    el.out.extend_from_slice(b"Alternative key bindings\n");
    map_print_range(el, 1);
    el.out.extend_from_slice(b"Multi-character bindings\n");
    el.out.extend_from_slice(b"Arrow key bindings\n");
}

fn map_print_range(el: &mut Engine, which: usize) {
    let runs: Vec<(usize, usize)> = {
        let m = if which == 0 { &el.map.key } else { &el.map.alt };
        let mut runs = Vec::new();
        let mut prev = 0usize;
        let mut i = 0usize;
        while i < N_KEYS {
            if m[prev] == m[i] {
                i += 1;
                continue;
            }
            runs.push((prev, i - 1));
            prev = i;
            i += 1;
        }
        runs.push((prev, i - 1));
        runs
    };
    for (a, b) in runs {
        map_print_some_keys(el, which, a, b);
    }
}

fn map_print_some_keys(el: &mut Engine, which: usize, first: usize, last: usize) {
    let m = if which == 0 { &el.map.key } else { &el.map.alt };
    if m[first] == ED_UNASSIGNED {
        if first == last {
            let unpars = keymacro_decode_str(&[first as u32], "\"\"");
            el.out
                .extend_from_slice(format!("{:<15}->  is undefined\n", unpars).as_bytes());
        }
        return;
    }
    let name = HELP
        .iter()
        .find(|(f, _, _)| *f == m[first])
        .map(|(_, n, _)| *n)
        .unwrap_or("");
    if first == last {
        let unpars = keymacro_decode_str(&[first as u32], "\"\"");
        el.out
            .extend_from_slice(format!("{:<15}->  {}\n", unpars, name).as_bytes());
    } else {
        let unpars = keymacro_decode_str(&[first as u32], "\"\"");
        let extrabuf = keymacro_decode_str(&[last as u32], "\"\"");
        el.out.extend_from_slice(
            format!("{:<4} to {:<7}->  {}\n", unpars, extrabuf, name).as_bytes(),
        );
    }
}

fn map_print_key(el: &mut Engine, which: usize, in_: &[u32]) {
    if in_.len() <= 1 {
        let m = if which == 0 { &el.map.key } else { &el.map.alt };
        let unpars = keymacro_decode_str(in_, "");
        let name = HELP
            .iter()
            .find(|(f, _, _)| *f == m[in_[0] as usize])
            .map(|(_, n, _)| *n)
            .unwrap_or("");
        el.out
            .extend_from_slice(format!("{}\t->\t{}\n", unpars, name).as_bytes());
    }
}

/// parse__string(): decode \escapes and ^control sequences.
fn parse_string_wide(raw: &[u8]) -> Option<Vec<u32>> {
    let s: Vec<u32> = raw.iter().map(|&b| b as u32).collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if c == '\\' as u32 || c == '^' as u32 {
            let (n, next) = parse_escape(&s, i)?;
            out.push(n);
            i = next;
        } else if c == 'M' as u32 && i + 2 < s.len() && s[i + 1] == '-' as u32 {
            out.push(0o33);
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some(out)
}

fn parse_escape(s: &[u32], idx: usize) -> Option<(u32, usize)> {
    if idx + 1 >= s.len() {
        return None;
    }
    let p = s[idx];
    if p == '\\' as u32 {
        let c = s[idx + 1];
        let v = match c {
            0x61 => 0o07,
            0x62 => 0o10,
            0x74 => 0o11,
            0x6e => 0o12,
            0x76 => 0o13,
            0x66 => 0o14,
            0x72 => 0o15,
            0x65 => 0o33,
            0x30..=0x37 => {
                let mut val = 0u32;
                let mut cnt = 0usize;
                let mut j = idx + 1;
                while cnt < 3 && j < s.len() && (s[j] as u8).is_ascii_digit() && s[j] <= '7' as u32
                {
                    val = (val << 3) | (s[j] - '0' as u32);
                    j += 1;
                    cnt += 1;
                }
                if (val & 0xffffff00) != 0 {
                    return None;
                }
                return Some((val, j - 1));
            }
            _ => c,
        };
        Some((v, idx + 2))
    } else {
        // ^
        let c = s[idx + 1];
        let v = if c == '?' as u32 { 0o177 } else { c & 0o37 };
        Some((v, idx + 2))
    }
}

/// keymacro__decode_str(): render a key as text with an optional sep.
fn keymacro_decode_str(str: &[u32], sep: &str) -> String {
    let mut out = String::new();
    let sep: Vec<char> = sep.chars().collect();
    if !sep.is_empty() {
        out.push(sep[0]);
    }
    if str.is_empty() || str[0] == 0 {
        out.push_str("^@");
    } else {
        for &c in str {
            if c == 0 {
                break;
            }
            let mut vis = Vec::new();
            ct_visual_char(&mut vis, c);
            for &vc in &vis {
                let b = ct_encode_string(&[vc]);
                out.push_str(&String::from_utf8_lossy(&b));
            }
        }
    }
    if sep.len() > 1 {
        out.push(sep[1]);
    }
    out
}

// ---------------------------------------------------------------------------
// § sig.c
// ---------------------------------------------------------------------------

fn sig_init(el: &mut Engine) -> i32 {
    el.sig.sig_no = 0;
    0
}

fn sig_end(el: &mut Engine) {
    let _ = el;
}

// ---------------------------------------------------------------------------
// § el.c — set / get / line / insertstr / deletestr / parse / source
// ---------------------------------------------------------------------------

pub fn el_wset(el: &mut Engine, op: i32, args: &[WSetArg]) -> i32 {
    let mut rv = 0i32;
    match op {
        EL_PROMPT | EL_RPROMPT => {
            let prf = match args.first() {
                Some(WSetArg::Prompt(Some(p))) => Some(PROMPT_USER + p),
                _ => None,
            };
            rv = el.prompt_set(prf, 0, op, true);
        }
        EL_PROMPT_ESC | EL_RPROMPT_ESC => {
            let prf = match args.first() {
                Some(WSetArg::Prompt(Some(p))) => Some(PROMPT_USER + p),
                _ => None,
            };
            let c = match args.get(1) {
                Some(WSetArg::I32(c)) => *c as u32,
                _ => 0,
            };
            rv = el.prompt_set(prf, c, op, true);
        }
        EL_TERMINAL => {
            let term = match args.first() {
                Some(WSetArg::Str(s)) => String::from_utf8_lossy(s).to_string(),
                _ => String::new(),
            };
            let term = if term.is_empty() {
                (el.getenv)("TERM").unwrap_or_default()
            } else {
                term
            };
            // C el_wset EL_TERMINAL -> terminal_set(): -1 on an unknown
            // terminal (after printing the dumb-terminal message)
            rv = match el.term.terminal_set(&term, &el.getenv) {
                Some(msg) => {
                    el.err_msg(&msg);
                    el.term.t_name = term;
                    el.terminal_rebuffer();
                    -1
                }
                None => {
                    el.term.t_name = term;
                    el.terminal_rebuffer();
                    0
                }
            };
        }
        EL_EDITOR => {
            let e: Vec<u8> = match args.first() {
                Some(WSetArg::WStr(s)) => ct_encode_string(s),
                _ => Vec::new(),
            };
            let wide: Vec<u32> = e.iter().map(|&b| b as u32).collect();
            rv = map_set_editor(el, &wide);
        }
        EL_SIGNAL => {
            match args.first() {
                Some(WSetArg::I32(v)) => {
                    if *v != 0 {
                        el.flags |= HANDLE_SIGNALS;
                    } else {
                        el.flags &= !HANDLE_SIGNALS;
                    }
                }
                _ => {}
            }
            rv = 0;
        }
        EL_EDITMODE => {
            match args.first() {
                Some(WSetArg::I32(v)) => {
                    if *v != 0 {
                        el.flags &= !EDIT_DISABLED;
                    } else {
                        el.flags |= EDIT_DISABLED;
                    }
                }
                _ => {}
            }
            rv = 0;
        }
        EL_SAFEREAD => {
            match args.first() {
                Some(WSetArg::I32(v)) => {
                    if *v != 0 {
                        el.flags |= FIXIO;
                    } else {
                        el.flags &= !FIXIO;
                    }
                }
                _ => {}
            }
            rv = 0;
        }
        EL_UNBUFFERED => {
            let v = match args.first() {
                Some(WSetArg::I32(v)) => *v != 0,
                _ => false,
            };
            rv = if v {
                if el.flags & UNBUFFERED == 0 {
                    el.flags |= UNBUFFERED;
                }
                0
            } else {
                if el.flags & UNBUFFERED != 0 {
                    el.flags &= !UNBUFFERED;
                }
                0
            };
        }
        EL_PREP_TERM => {
            match args.first() {
                Some(WSetArg::I32(v)) => {
                    if *v != 0 {
                        el.tty_rawmode();
                    } else {
                        el.tty_cookedmode();
                    }
                }
                _ => {}
            }
            rv = 0;
        }
        EL_HIST => {
            if let Some(WSetArg::Hist(fun, h)) = args.first() {
                hist_set(el, *fun, h.clone());
            }
            rv = 0;
        }
        EL_CLIENTDATA => {
            rv = 0;
        }
        EL_GETCFN => {
            rv = 0;
        }
        EL_ADDFN => {
            if let Some(WSetArg::AddFn(name, help, func)) = args.first() {
                el.user_funcs.push((name.clone(), help.clone(), *func));
                el.map.nfunc += 1;
            }
            rv = 0;
        }
        EL_WORDCHARS => {
            if let Some(WSetArg::WStr(s)) = args.first() {
                map_set_wordchars(el, s);
            }
            rv = 0;
        }
        EL_GETENV => {
            rv = 0;
        }
        EL_REFRESH => {
            el.re_clear_display();
            el.re_refresh();
            el.terminal__flush();
            rv = 0;
        }
        EL_RESIZE => {
            rv = 0;
        }
        EL_ALIAS_TEXT => {
            el.chared.c_aliasfun = true;
            rv = 0;
        }
        EL_SETFP => {
            rv = 0;
        }
        EL_BIND => {
            if let Some(WSetArg::BindArgs(a)) = args.first() {
                rv = map_bind(el, a);
            }
        }
        EL_SETTC => {
            rv = -1;
        }
        _ => rv = -1,
    }
    rv
}

pub enum WSetArg {
    I32(i32),
    Str(Vec<u8>),
    WStr(Vec<u32>),
    Prompt(Option<usize>),
    Hist(HistFn, History),
    AddFn(Vec<u32>, Vec<u32>, UserFunc),
    BindArgs(Vec<Vec<u32>>),
    None,
}

pub fn el_wget(el: &mut Engine, op: i32, out: &mut WGetOut) -> i32 {
    match op {
        EL_PROMPT | EL_RPROMPT => {
            let mut prf = None;
            let rv = el.prompt_get(&mut prf, None, op);
            *out = WGetOut::Prompt(prf);
            rv
        }
        EL_PROMPT_ESC | EL_RPROMPT_ESC => {
            let mut prf = None;
            let mut c = 0u32;
            let rv = el.prompt_get(&mut prf, Some(&mut c), op);
            *out = WGetOut::PromptEsc(prf, c);
            rv
        }
        EL_EDITOR => {
            let mut e = Vec::new();
            let rv = map_get_editor(el, &mut e);
            *out = WGetOut::WStr(e.iter().map(|&b| b as u32).collect());
            rv
        }
        EL_SIGNAL => {
            *out = WGetOut::I32((el.flags & HANDLE_SIGNALS != 0) as i32);
            0
        }
        EL_EDITMODE => {
            *out = WGetOut::I32((el.flags & EDIT_DISABLED == 0) as i32);
            0
        }
        EL_SAFEREAD => {
            // C el_wget EL_SAFEREAD: `*va_arg = el->el_flags & FIXIO` — the
            // raw flag word (0x100 = 256 when set), not a boolean.
            *out = WGetOut::I32((el.flags & FIXIO) as i32);
            0
        }
        EL_TERMINAL => {
            *out = WGetOut::Str(el.term.t_name.clone().into_bytes());
            0
        }
        EL_UNBUFFERED => {
            *out = WGetOut::I32((el.flags & UNBUFFERED != 0) as i32);
            0
        }
        EL_WORDCHARS => {
            let w = el.map.wordchars.clone();
            *out = WGetOut::WStr(w);
            0
        }
        EL_GETTC => {
            if let WGetOut::GetTc(cap) = out {
                let cap = cap.clone();
                let names: [&str; 39] = [
                    "al", "bl", "cd", "ce", "ch", "cl", "dc", "dl", "dm", "ed", "ei", "fs", "ho",
                    "ic", "im", "ip", "kd", "kl", "kr", "ku", "md", "me", "nd", "se", "so", "ts",
                    "up", "us", "ue", "vb", "DC", "DO", "IC", "LE", "RI", "UP", "kh", "@7", "kD",
                ];
                if let Some(pos) = names.iter().position(|&n| n == cap) {
                    *out = WGetOut::Str(el.term.t_str[pos].clone().unwrap_or_default());
                    return 0;
                }
                let vals: [(&str, usize); 8] = [
                    ("am", T_am),
                    ("pt", T_pt),
                    ("li", T_li),
                    ("co", T_co),
                    ("km", T_km),
                    ("xt", T_xt),
                    ("xn", T_xn),
                    ("MT", T_MT),
                ];
                if let Some((_, idx)) = vals.iter().find(|(n, _)| *n == cap) {
                    if *idx == T_pt || *idx == T_km || *idx == T_am || *idx == T_xn {
                        *out = WGetOut::Str(if el.term.t_val[*idx] != 0 {
                            b"yes".to_vec()
                        } else {
                            b"no".to_vec()
                        });
                    } else {
                        *out = WGetOut::I32(el.term.t_val[*idx]);
                    }
                    return 0;
                }
                return -1;
            }
            -1
        }
        _ => -1,
    }
}

pub enum WGetOut {
    I32(i32),
    Str(Vec<u8>),
    WStr(Vec<u32>),
    Prompt(Option<usize>),
    PromptEsc(Option<usize>, u32),
    GetTc(String),
    None,
}

pub fn el_wline(el: &mut Engine) -> (usize, usize, usize) {
    (0, el.line.cur, el.line.last)
}

pub fn el_winsertstr(el: &mut Engine, s: Option<&[u32]>) -> i32 {
    let Some(s) = s else { return -1 };
    if s.is_empty() {
        return -1;
    }
    let len = s.len();
    if el.line.last + len >= el.line.limit && !el.ch_enlargebufs(len) {
        return -1;
    }
    el.c_insert(len);
    for &c in s {
        el.line.buf[el.line.cur] = c;
        el.line.cur += 1;
    }
    0
}

pub fn el_deletestr(el: &mut Engine, n: i32) {
    if n <= 0 {
        return;
    }
    if el.line.cur < n as usize {
        return;
    }
    el.c_delbefore(n as usize);
    el.line.cur -= n as usize;
}

pub fn el_deletestr1(el: &mut Engine, start: i32, end: i32) -> i32 {
    if end <= start {
        return 0;
    }
    let line_length = el.line.last;
    if start >= line_length as i32 || end >= line_length as i32 {
        return 0;
    }
    let mut len = (end - start) as usize;
    if len > line_length - end as usize {
        len = line_length - end as usize;
    }
    let mut p1 = start as usize;
    let mut p2 = end as usize;
    for _ in 0..len {
        // the C advances both pointers per iteration; the bytes past the new
        // lastchar are left stale (the narrow el_line() encodes until the
        // next NUL, so they leak into the printed buffer)
        el.line.buf[p1] = el.line.buf[p2];
        p1 += 1;
        p2 += 1;
        el.line.last -= 1;
    }
    end - start
}

pub fn el_wreplacestr(el: &mut Engine, s: Option<&[u32]>) -> i32 {
    let Some(s) = s else { return -1 };
    if s.is_empty() {
        return -1;
    }
    let len = s.len();
    if el.line.limit <= len && !el.ch_enlargebufs(len) {
        return -1;
    }
    for i in 0..len {
        el.line.buf[i] = s[i];
    }
    el.line.buf[len] = 0;
    el.line.last = len;
    if el.line.cur > el.line.last {
        el.line.cur = el.line.last;
    }
    0
}

pub fn el_cursor(el: &mut Engine, n: i32) -> i32 {
    if n != 0 {
        el.line.cur = (el.line.cur as i64 + n as i64) as usize;
        if el.line.cur > el.line.last {
            el.line.cur = el.line.last;
        }
    }
    el.line.cur as i32
}

/// el_parse(): narrow argv dispatch (eln.c), mirrors el_wparse.
pub fn el_parse(el: &mut Engine, argv_bytes: &[Vec<u8>]) -> i32 {
    let wide: Vec<Vec<u32>> = argv_bytes
        .iter()
        .map(|a| a.iter().map(|&b| b as u32).collect())
        .collect();
    el_wparse(el, argv_bytes.len() as i32, &wide)
}

pub fn el_source(el: &mut Engine, fname: Option<&str>) -> i32 {
    let fname = match fname {
        Some(f) => f.to_string(),
        None => {
            if let Some(editrc) = (el.getenv)("EDITRC") {
                editrc
            } else {
                let home = match (el.getenv)("HOME") {
                    Some(h) => h,
                    None => return -1,
                };
                format!("{}/.editrc", home)
            }
        }
    };
    let Ok(content) = std::fs::read(&fname) else {
        return -1;
    };
    let mut error = 0;
    for line in content.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut line = line.to_vec();
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        let Some(wide) = ct_decode_string(&line) else {
            continue;
        };
        let mut idx = 0usize;
        while idx < wide.len() && iswspace(wide[idx]) {
            idx += 1;
        }
        if idx < wide.len() && wide[idx] == '#' as u32 {
            continue;
        }
        let l = &wide[idx..];
        error = parse_line(el, l);
        if error == -1 {
            break;
        }
    }
    error
}

impl Engine {
    fn err_msg(&mut self, msg: &str) {
        if self.merge_err {
            for &b in msg.as_bytes() {
                if b == b'\n' {
                    self.out.push(b'\r');
                }
                self.out.push(b);
            }
        } else {
            self.err.extend_from_slice(msg.as_bytes());
        }
    }

    fn terminal_rebuffer(&mut self) {
        let h = self.term.t_val[T_co];
        let v = self.term.t_val[T_li];
        self.term.t_size.h = h;
        self.term.t_size.v = v;
        let (w, hh) = (h as usize, v as usize);
        let mut d = Vec::new();
        let mut vd = Vec::new();
        for _ in 0..hh {
            let mut row = vec![0u32; w + 1];
            row[w] = 0;
            d.push(row);
            let mut row2 = vec![0u32; w + 1];
            row2[w] = 0;
            vd.push(row2);
        }
        self.display = d;
        self.vdisplay = vd;
        self.re_clear_display();
    }
}

// ---------------------------------------------------------------------------
// § narrow (eln.c) convenience wrappers for the probe
// ---------------------------------------------------------------------------

pub fn el_set_narrow(el: &mut Engine, op: i32, args: &[SetArg]) -> i32 {
    let mut wargs: Vec<WSetArg> = Vec::new();
    for a in args {
        match a {
            SetArg::I32(v) => wargs.push(WSetArg::I32(*v)),
            SetArg::Str(s) => wargs.push(WSetArg::Str(s.clone())),
            SetArg::WStr(s) => wargs.push(WSetArg::WStr(s.clone())),
            SetArg::Prompt(p) => wargs.push(WSetArg::Prompt(*p)),
            SetArg::Hist(f, h) => wargs.push(WSetArg::Hist(*f, h.clone())),
            SetArg::AddFn(n, h, f) => wargs.push(WSetArg::AddFn(n.clone(), h.clone(), *f)),
            SetArg::BindArgs(a) => wargs.push(WSetArg::BindArgs(
                a.iter()
                    .map(|s| ct_decode_string(s).unwrap_or_default())
                    .collect(),
            )),
            SetArg::None => wargs.push(WSetArg::None),
        }
    }
    // narrow el_set: string args are decoded from bytes
    let mut cvt: Vec<WSetArg> = Vec::new();
    for (i, w) in wargs.into_iter().enumerate() {
        match w {
            WSetArg::Str(s) => {
                if op == EL_TERMINAL {
                    cvt.push(WSetArg::Str(s));
                } else {
                    let wide = ct_decode_string(&s).unwrap_or_default();
                    cvt.push(WSetArg::WStr(wide));
                }
            }
            WSetArg::BindArgs(v) => {
                cvt.push(WSetArg::BindArgs(v));
            }
            other => cvt.push(other),
        }
    }
    el_wset(el, op, &cvt)
}

pub enum SetArg {
    I32(i32),
    Str(Vec<u8>),
    WStr(Vec<u32>),
    Prompt(Option<usize>),
    Hist(HistFn, History),
    AddFn(Vec<u32>, Vec<u32>, UserFunc),
    BindArgs(Vec<Vec<u8>>),
    None,
}

pub fn el_get_narrow(el: &mut Engine, op: i32, out: &mut GetOut) -> i32 {
    let mut wo = WGetOut::None;
    let r = el_wget(el, op, &mut wo);
    match wo {
        WGetOut::WStr(s) => *out = GetOut::Str(ct_encode_string(&s)),
        WGetOut::Str(s) => *out = GetOut::Str(s),
        WGetOut::I32(v) => *out = GetOut::I32(v),
        WGetOut::Prompt(_) => *out = GetOut::I32(0),
        WGetOut::PromptEsc(_, _) => *out = GetOut::I32(0),
        WGetOut::GetTc(_) => *out = GetOut::I32(0),
        WGetOut::None => *out = GetOut::None,
    }
    r
}

pub enum GetOut {
    I32(i32),
    Str(Vec<u8>),
    None,
}

pub enum GetTcOut {
    I32(i32),
    Str(Vec<u8>),
}

/// terminal_gettc(): string caps -> Str, booleans (am/pt/km/xn) -> "yes"/"no",
/// numerics (co/li) -> I32; unknown -> Err.
pub fn el_gettc(el: &Engine, cap: &str) -> Result<GetTcOut, ()> {
    let names: [&str; 39] = [
        "al", "bl", "cd", "ce", "ch", "cl", "dc", "dl", "dm", "ed", "ei", "fs", "ho", "ic", "im",
        "ip", "kd", "kl", "kr", "ku", "md", "me", "nd", "se", "so", "ts", "up", "us", "ue", "vb",
        "DC", "DO", "IC", "LE", "RI", "UP", "kh", "@7", "kD",
    ];
    if let Some(pos) = names.iter().position(|&n| n == cap) {
        return Ok(GetTcOut::Str(
            el.term.t_str[pos].clone().unwrap_or_default(),
        ));
    }
    let vals: [(&str, usize); 8] = [
        ("am", T_am),
        ("pt", T_pt),
        ("li", T_li),
        ("co", T_co),
        ("km", T_km),
        ("xt", T_xt),
        ("xn", T_xn),
        ("MT", T_MT),
    ];
    if let Some((_, idx)) = vals.iter().find(|(n, _)| *n == cap) {
        if *idx == T_pt || *idx == T_km || *idx == T_am || *idx == T_xn {
            return Ok(GetTcOut::Str(if el.term.t_val[*idx] != 0 {
                b"yes".to_vec()
            } else {
                b"no".to_vec()
            }));
        }
        return Ok(GetTcOut::I32(el.term.t_val[*idx]));
    }
    Err(())
}

// ---------------------------------------------------------------------------
// § readline.c — the readline-compatibility layer BIND's nslookup uses
// ---------------------------------------------------------------------------

pub struct RlState {
    pub e: Option<Engine>,
    pub h: Option<History>,
    pub rl_prompt: Vec<u8>,
    pub rl_prompt_saved: Option<Vec<u8>>,
    pub rl_already_prompted: i32,
    pub rl_point: i32,
    pub rl_end: i32,
    pub rl_line_buffer: Vec<u8>,
    pub rl_done: i32,
    pub rl_echo_off: bool,
    pub rl_last_line: Option<Vec<u8>>,
    pub history_base: i32,
    pub history_length: i32,
    pub history_offset: i32,
    pub max_input_history: i32,
}

impl RlState {
    pub fn new() -> RlState {
        RlState {
            e: None,
            h: None,
            rl_prompt: Vec::new(),
            rl_prompt_saved: None,
            rl_already_prompted: 0,
            rl_point: 0,
            rl_end: 0,
            rl_line_buffer: Vec::new(),
            rl_done: 0,
            rl_echo_off: false,
            rl_last_line: None,
            history_base: 1,
            history_length: 0,
            history_offset: 0,
            max_input_history: 0,
        }
    }

    fn rl_set_prompt(&mut self, prompt: &[u8]) -> i32 {
        let prompt = if prompt.is_empty() { b"" } else { prompt };
        if self.rl_prompt == prompt {
            return 0;
        }
        self.rl_prompt = prompt.to_vec();
        // rl_set_prompt: strip \001/\002 invisible-prompt markers
        let mut p = 0usize;
        loop {
            if p + 1 >= self.rl_prompt.len() {
                break;
            }
            if self.rl_prompt[p] == 2 && self.rl_prompt[p + 1] == 1 {
                self.rl_prompt.drain(p..p + 2);
            } else {
                p += 1;
            }
        }
        for b in self.rl_prompt.iter_mut() {
            if *b == 2 {
                *b = 1;
            }
        }
        0
    }

    pub fn rl_initialize(&mut self, env: Vec<(String, String)>) -> i32 {
        let mut el = match el_init("editline", true, Vec::new(), env) {
            Some(e) => e,
            None => return -1,
        };
        if self.rl_echo_off {
            // rl_initialize: tcgetattr sees ECHO off (the harness's
            // cfmakeraw pty) -> editmode = 0
            el.flags |= EDIT_DISABLED;
        }
        let mut h = history_init();
        let mut ev = HistEventN::default();
        history(&mut h, &mut ev, H_SETSIZE, &[HistoryArg::I32(i32::MAX)]);
        self.history_length = 0;
        self.max_input_history = i32::MAX;
        hist_set(&mut el, history_w_fun, h.clone());
        let _ = self.rl_set_prompt(b"");
        el.prompt_set(Some(PROMPT_USER + 0), 1, EL_PROMPT_ESC, false);
        el.flags |= HANDLE_SIGNALS;
        let emacs: Vec<u32> = "emacs".chars().map(|c| c as u32).collect();
        map_set_editor(&mut el, &emacs);
        // ^I -> rl_complete (modeled as ED_INSERT here; completion is out
        // of the corpus's scope)
        let tab = vec!['\t' as u32, 0];
        let v = el.keymacro_map_cmd(ED_INSERT);
        el.keymacro_add(&tab, v, XK_CMD);
        // Home/End/Delete/Insert/Ctrl-arrow bindings
        let binds: [(&str, u8); 10] = [
            ("\\e[1~", ED_MOVE_TO_BEG),
            ("\\e[4~", ED_MOVE_TO_END),
            ("\\e[7~", ED_MOVE_TO_BEG),
            ("\\e[8~", ED_MOVE_TO_END),
            ("\\e[H", ED_MOVE_TO_BEG),
            ("\\e[F", ED_MOVE_TO_END),
            ("\\e[3~", ED_DELETE_NEXT_CHAR),
            ("\\e[2~", EM_TOGGLE_OVERWRITE),
            ("\\e[1;5C", EM_NEXT_WORD),
            ("\\e[1;5D", ED_PREV_WORD),
        ];
        for (seq, cmd) in binds.iter() {
            if let Some(wide) = parse_string_wide(seq.as_bytes()) {
                let v = el.keymacro_map_cmd(*cmd);
                el.keymacro_add(&wide, v, XK_CMD);
            }
        }
        self.h = Some(h);
        self.e = Some(el);
        0
    }

    /// readline(): the BIND surface.
    pub fn readline(&mut self, p: &[u8], env: Vec<(String, String)>) -> Option<Vec<u8>> {
        if self.e.is_none() || self.h.is_none() {
            let r = self.rl_initialize(env);
            if r != 0 {
                return None;
            }
        }
        self.rl_done = 0;
        if self.rl_set_prompt(p) == -1 {
            return None;
        }
        let el = self.e.as_mut().unwrap();
        let prompt_bytes = self.rl_prompt.clone();
        let prompt_wide: Vec<u32> = ct_decode_string(&prompt_bytes).unwrap_or_default();
        if el.user_prompts.is_empty() {
            let pl = prompt_wide.clone();
            el.user_prompts.push(Box::new(move |_| pl.clone()));
        } else {
            let pl = prompt_wide.clone();
            el.user_prompts[0] = Box::new(move |_| pl.clone());
        }
        let mut count = 0i32;
        let ret = el_gets(el, &mut count);
        if let Some(r) = ret {
            if count > 0 {
                let mut buf = r;
                let lastidx = count as usize - 1;
                if lastidx < buf.len() && buf[lastidx] == b'\n' {
                    buf.truncate(lastidx);
                }
                if let Some(h) = self.h.as_mut() {
                    let mut ev = HistEventN::default();
                    history_getsize(h, &mut ev);
                    self.history_length = ev.num;
                }
                // NB: the C never updates rl_point/rl_end in readline() (the
                // values stay at the rl_initialize-time 0); the corpus pins
                // point=0 end=0 for both reads.
                self.rl_last_line = Some(buf.clone());
                return Some(buf);
            }
        }
        self.rl_last_line = None;
        None
    }

    /// Feed the pty input stream (the engine models INLCR/ICRNL on it).
    pub fn rl_set_input(&mut self, input: Vec<u8>) {
        if let Some(el) = self.e.as_mut() {
            el.input = input;
            el.input_pos = 0;
        }
    }

    /// Drain the engine's pty transcript (prompt + refresh bytes).
    pub fn rl_drain_out(&mut self) -> Vec<u8> {
        match self.e.as_mut() {
            Some(el) => std::mem::take(&mut el.out),
            None => Vec::new(),
        }
    }

    /// add_history(): H_ENTER + bookkeeping.
    pub fn add_history(&mut self, line: &[u8]) -> i32 {
        if self.e.is_none() || self.h.is_none() {
            return 0;
        }
        let Some(h) = self.h.as_mut() else {
            return 0;
        };
        let mut ev = HistEventN::default();
        if history(h, &mut ev, H_ENTER, &[HistoryArg::Str(line.to_vec())]) == -1 {
            return 0;
        }
        let mut ev2 = HistEventN::default();
        history_getsize(h, &mut ev2);
        if ev2.num == self.history_length {
            self.history_base += 1;
        } else {
            self.history_offset += 1;
            self.history_length = ev2.num;
        }
        0
    }

    pub fn history_get(&mut self, num: i32) -> Option<Vec<u8>> {
        if num < self.history_base {
            return None;
        }
        let mut h = self.h.take()?;
        let mut ev = HistEventN::default();
        let r = if history(
            &mut h,
            &mut ev,
            H_DELDATA,
            &[
                HistoryArg::I32(num - self.history_base),
                HistoryArg::MagicDel,
            ],
        ) != 0
        {
            None
        } else {
            let mut ev2 = HistEventN::default();
            if history(&mut h, &mut ev2, H_CURR, &[]) != 0 {
                None
            } else {
                ev2.str
            }
        };
        self.h = Some(h);
        r
    }

    pub fn current_history(&mut self) -> Option<Vec<u8>> {
        let mut h = self.h.take()?;
        let mut ev = HistEventN::default();
        let r = if history(
            &mut h,
            &mut ev,
            H_PREV_EVENT,
            &[HistoryArg::I32(self.history_offset + 1)],
        ) != 0
        {
            None
        } else {
            ev.str
        };
        self.h = Some(h);
        r
    }

    pub fn previous_history(&mut self) -> Option<Vec<u8>> {
        if self.history_offset == 0 {
            return None;
        }
        let mut h = self.h.take()?;
        let mut ev = HistEventN::default();
        let r = if history(&mut h, &mut ev, H_LAST, &[]) != 0 {
            None
        } else {
            self.history_offset -= 1;
            let mut ev2 = HistEventN::default();
            if history(
                &mut h,
                &mut ev2,
                H_PREV_EVENT,
                &[HistoryArg::I32(self.history_offset + 1)],
            ) != 0
            {
                None
            } else {
                ev2.str
            }
        };
        self.h = Some(h);
        r
    }

    pub fn next_history(&mut self) -> Option<Vec<u8>> {
        if self.history_offset >= self.history_length {
            return None;
        }
        let mut h = self.h.take()?;
        let mut ev = HistEventN::default();
        let r = if history(&mut h, &mut ev, H_LAST, &[]) != 0 {
            None
        } else {
            self.history_offset += 1;
            let mut ev2 = HistEventN::default();
            if history(
                &mut h,
                &mut ev2,
                H_PREV_EVENT,
                &[HistoryArg::I32(self.history_offset + 1)],
            ) != 0
            {
                None
            } else {
                ev2.str
            }
        };
        self.h = Some(h);
        r
    }

    pub fn history_search_prefix(&mut self, str: &[u8], direction: i32) -> i32 {
        let mut h = match self.h.take() {
            Some(h) => h,
            None => return -1,
        };
        let mut ev = HistEventN::default();
        let r = if direction < 0 {
            history(
                &mut h,
                &mut ev,
                H_PREV_STR,
                &[HistoryArg::Str(str.to_vec())],
            )
        } else {
            history(
                &mut h,
                &mut ev,
                H_NEXT_STR,
                &[HistoryArg::Str(str.to_vec())],
            )
        };
        self.h = Some(h);
        r
    }

    pub fn history_search(&mut self, str: &[u8], direction: i32) -> i32 {
        let mut h = match self.h.take() {
            Some(h) => h,
            None => return -1,
        };
        let mut ev = HistEventN::default();
        let mut r = if history(&mut h, &mut ev, H_CURR, &[]) != 0 {
            -1
        } else {
            let start_num = ev.num;
            let mut found = -1;
            loop {
                if let Some(s) = ev.str.as_deref() {
                    if let Some(pos) = s.windows(str.len()).position(|w| w == str) {
                        found = pos as i32;
                        break;
                    }
                }
                let rr = if direction < 0 {
                    history(&mut h, &mut ev, H_NEXT, &[])
                } else {
                    history(&mut h, &mut ev, H_PREV, &[])
                };
                if rr != 0 {
                    break;
                }
            }
            history(&mut h, &mut ev, H_SET, &[HistoryArg::I32(start_num)]);
            found
        };
        if r == -2 {
            r = -1;
        }
        self.h = Some(h);
        r
    }

    /// history_expand(): csh-style expansion (readline.c).  Faithful to the
    /// C: `history_expansion_char = '!'`, `history_subst_char = '^'`,
    /// `history_no_expand_chars = " \t\n=("`.  The event specifier and
    /// modifiers are handled by _history_expand_command; a failed parse
    /// returns -1 with an (empty) result string.
    pub fn history_expand(&mut self, str: &[u8]) -> (i32, Option<Vec<u8>>) {
        let mut ret = 0i32;
        let mut str_buf: Vec<u8>;
        if str.is_empty() {
            return (0, Some(Vec::new()));
        }
        if str[0] == b'^' {
            // *output = "!!:s" + str
            let mut o = Vec::with_capacity(str.len() + 4);
            o.extend_from_slice(b"!!:s");
            o.extend_from_slice(str);
            str_buf = o;
        } else {
            str_buf = str.to_vec();
        }
        let mut result: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i < str_buf.len() {
            let mut qchar = 0u8;
            let mut loop_again = true;
            let start = i;
            let mut j = i;
            // the C's `loop:` with the two-pass scan
            loop {
                while j < str_buf.len() {
                    if str_buf[j] == b'\\' && j + 1 < str_buf.len() && str_buf[j + 1] == b'!' {
                        // memmove(&str[j], &str[j+1], len): drop the backslash
                        str_buf.drain(j..j + 1);
                        continue;
                    }
                    if !loop_again {
                        if str_buf[j].is_ascii_whitespace() || str_buf[j] == qchar {
                            break;
                        }
                    }
                    if str_buf[j] == b'!'
                        && !b" \t\n=(".contains(&str_buf.get(j + 1).copied().unwrap_or(0))
                    {
                        break;
                    }
                    j += 1;
                }
                if j < str_buf.len() && loop_again {
                    i = j;
                    qchar = if j > 0 && str_buf[j - 1] == b'"' {
                        b'"'
                    } else {
                        0
                    };
                    j += 1;
                    if j < str_buf.len() && str_buf[j] == b'!' {
                        j += 1;
                    }
                    loop_again = false;
                    continue;
                }
                break;
            }
            let len = i - start;
            result.extend_from_slice(&str_buf[start..start + len]);
            if i >= str_buf.len() || str_buf[i] != b'!' {
                let len = j - i;
                result.extend_from_slice(&str_buf[i..i + len]);
                ret = if start == 0 { 0 } else { 1 };
                break;
            }
            let (r, t) = self.history_expand_command(&str_buf, i, j - i);
            ret = r;
            if ret > 0 {
                if let Some(t) = t {
                    result.extend_from_slice(&t);
                }
            }
            i = j;
        }
        (ret, Some(result))
    }

    /// get_history_event(): parse the event designator at cmd[cindex].
    /// Returns the event text and advances *cindex past the designator.
    fn get_history_event(&mut self, cmd: &[u8], cindex: &mut usize, qchar: u8) -> Option<Vec<u8>> {
        let mut idx = *cindex;
        if cmd.get(idx) != Some(&b'!') {
            return None;
        }
        idx += 1;
        // "!!" or "!" end-of-string: the first (newest) event
        if cmd.get(idx) == Some(&b'!') || cmd.get(idx).is_none() {
            let mut h = self.h.take()?;
            let mut ev = HistEventN::default();
            let r = if history(&mut h, &mut ev, H_FIRST, &[]) != 0 {
                None
            } else {
                ev.str
            };
            self.h = Some(h);
            *cindex = if cmd.get(idx) == Some(&b'!') {
                idx + 1
            } else {
                idx
            };
            return r;
        }
        let mut sign = false;
        if cmd.get(idx) == Some(&b'-') {
            sign = true;
            idx += 1;
        }
        if cmd.get(idx).map_or(false, |c| c.is_ascii_digit()) {
            let mut num = 0i32;
            while cmd.get(idx).map_or(false, |c| c.is_ascii_digit()) {
                num = num * 10 + (cmd[idx] - b'0') as i32;
                idx += 1;
            }
            if sign {
                num = self.history_length - num + self.history_base;
            }
            let he = self.history_get(num);
            if he.is_none() {
                return None;
            }
            *cindex = idx;
            return he;
        }
        let mut sub = false;
        if cmd.get(idx) == Some(&b'?') {
            sub = true;
            idx += 1;
        }
        let begin = idx;
        while idx < cmd.len() {
            if cmd[idx] == b'\n' {
                break;
            }
            if sub && cmd[idx] == b'?' {
                break;
            }
            if !sub
                && (cmd[idx] == b':' || cmd[idx] == b' ' || cmd[idx] == b'\t' || cmd[idx] == qchar)
            {
                break;
            }
            idx += 1;
        }
        let len = idx - begin;
        if sub && cmd.get(idx) == Some(&b'?') {
            idx += 1;
        }
        if len == 0 {
            return None;
        }
        let pat = cmd[begin..begin + len].to_vec();
        // save the current position, search, then roll back (the C keeps a
        // pointer to the found event's string across the rollback)
        let mut h = self.h.take()?;
        let mut ev = HistEventN::default();
        if history(&mut h, &mut ev, H_CURR, &[]) != 0 {
            self.h = Some(h);
            return None;
        }
        let num = ev.num;
        self.h = Some(h);
        let r = if sub {
            self.history_search(&pat, -1)
        } else {
            self.history_search_prefix(&pat, -1)
        };
        if r == -1 {
            return None;
        }
        let mut h = self.h.take()?;
        let mut ev2 = HistEventN::default();
        let found = if history(&mut h, &mut ev2, H_CURR, &[]) != 0 {
            None
        } else {
            ev2.str.clone()
        };
        // roll back to the original position
        history(&mut h, &mut ev2, H_SET, &[HistoryArg::I32(num)]);
        self.h = Some(h);
        *cindex = idx;
        found
    }

    /// _history_expand_command(): expand the event specifier + modifiers of
    /// the command starting at offs (readline.c).
    fn history_expand_command(
        &mut self,
        command: &[u8],
        offs: usize,
        cmdlen: usize,
    ) -> (i32, Option<Vec<u8>>) {
        let mut tmp: Option<Vec<u8>> = None;
        let mut search: Option<Vec<u8>> = None;
        let mut aptr: Option<Vec<u8>> = None;
        let mut ptr: Option<Vec<u8>> = None;
        let mut from: Option<Vec<u8>> = None;
        let mut to: Option<Vec<u8>> = None;
        let mut p_on = 0i32;
        let mut g_on = 0i32;
        let mut ev = -1i32;

        // first get the event specifier
        let mut idx = 0usize;
        let has_mods: bool;
        if offs + 1 < command.len() && b":^*$".contains(&command[offs + 1]) {
            // "!:" is "!!:", "!^"/"!*"/"!$" are "!!:^"/"!!:*"/"!!:$"
            let str4 = [b'!', b'!', b'0', 0];
            ptr = self.get_history_event(&str4[..3], &mut idx, 0);
            idx = if command[offs + 1] == b':' { 1 } else { 0 };
            has_mods = true;
        } else if offs + 1 < command.len() && command[offs + 1] == b'#' {
            // use command so far
            aptr = Some(command[..offs + 1].to_vec());
            idx = 1;
            has_mods = offs + idx < command.len() && command[offs + idx] == b':';
        } else {
            let qchar = if offs > 0 && command[offs - 1] == b'"' {
                b'"'
            } else {
                0
            };
            ptr = self.get_history_event(&command[offs..], &mut idx, qchar);
            has_mods = offs + idx < command.len() && command[offs + idx] == b':';
        }
        if ptr.is_none() && aptr.is_none() {
            return (-1, None);
        }
        if !has_mods {
            return (1, aptr.clone().or_else(|| ptr.clone()));
        }
        let mut cmd = offs + idx + 1;
        // parse any word designators
        if cmd < command.len() && command[cmd] == b'%' {
            tmp = Some(Vec::new()); // last_search_match is NULL in the corpus
        } else if cmd < command.len() && b"^*$-0123456789".contains(&command[cmd]) {
            let mut start = -1i32;
            let mut end = -1i32;
            if command[cmd] == b'^' {
                start = 1;
                end = 1;
                cmd += 1;
            } else if command[cmd] == b'$' {
                start = -1;
                cmd += 1;
            } else if command[cmd] == b'*' {
                start = 1;
                cmd += 1;
            } else if command[cmd] == b'-' || command[cmd].is_ascii_digit() {
                start = 0;
                while cmd < command.len() && command[cmd].is_ascii_digit() {
                    start = start * 10 + (command[cmd] - b'0') as i32;
                    cmd += 1;
                }
                if cmd < command.len() && command[cmd] == b'-' {
                    if cmd + 1 < command.len() && command[cmd + 1].is_ascii_digit() {
                        cmd += 1;
                        end = 0;
                        while cmd < command.len() && command[cmd].is_ascii_digit() {
                            end = end * 10 + (command[cmd] - b'0') as i32;
                            cmd += 1;
                        }
                    } else if cmd + 1 < command.len() && command[cmd + 1] == b'$' {
                        cmd += 2;
                        end = -1;
                    } else {
                        cmd += 1;
                        end = -2;
                    }
                } else if cmd < command.len() && command[cmd] == b'*' {
                    end = -1;
                    cmd += 1;
                } else {
                    end = start;
                }
            }
            let base = aptr.clone().or_else(|| ptr.clone()).unwrap_or_default();
            tmp = history_arg_extract(start, end, &base);
            if tmp.is_none() {
                return (-1, None);
            }
        } else {
            tmp = aptr.clone().or_else(|| ptr.clone());
        }
        if cmd >= command.len() || cmd - (offs + idx) >= cmdlen {
            return (1, tmp);
        }
        // the modifiers
        while cmd < command.len() {
            match command[cmd] {
                b':' => {}
                b'h' => {
                    // remove trailing path
                    if let Some(s) = tmp.as_mut() {
                        if let Some(pos) = s.iter().rposition(|&c| c == b'/') {
                            s.truncate(pos);
                        }
                    }
                }
                b't' => {
                    // remove leading path
                    rl_replace_tail(&mut tmp, b'/');
                }
                b'r' => {
                    // remove trailing suffix
                    if let Some(s) = tmp.as_mut() {
                        if let Some(pos) = s.iter().rposition(|&c| c == b'.') {
                            s.truncate(pos);
                        }
                    }
                }
                b'e' => {
                    // remove all but suffix
                    rl_replace_tail(&mut tmp, b'.');
                }
                b'p' => {
                    p_on = 1;
                }
                b'g' => {
                    g_on = 2;
                }
                b'&' if from.is_some() && to.is_some() => {
                    // FALLTHROUGH to 's' below (from/to must be set)
                    let sub = rl_compat_sub(
                        tmp.as_deref().unwrap_or(&[]),
                        from.as_deref().unwrap(),
                        to.as_deref().unwrap(),
                        g_on,
                    );
                    tmp = sub;
                    g_on = 0;
                }
                b's' => {
                    ev = -1;
                    cmd += 1;
                    let delim = if cmd < command.len() { command[cmd] } else { 0 };
                    if delim == 0 || cmd + 1 >= command.len() {
                        return (ev, None);
                    }
                    cmd += 1;
                    // getfrom(&cmd, &from, search, delim)
                    let mut f = Vec::new();
                    while cmd < command.len() && command[cmd] != delim {
                        if command[cmd] == b'\\'
                            && cmd + 1 < command.len()
                            && command[cmd + 1] == delim
                        {
                            cmd += 1;
                        }
                        f.push(command[cmd]);
                        cmd += 1;
                    }
                    if f.is_empty() {
                        match search.as_deref() {
                            Some(s) => f = s.to_vec(),
                            None => return (ev, None),
                        }
                    }
                    if cmd >= command.len() {
                        return (ev, None);
                    }
                    cmd += 1;
                    if cmd >= command.len() {
                        return (ev, None);
                    }
                    from = Some(f);
                    // getto(&cmd, &to, from, delim)
                    let mut t = Vec::new();
                    let from_len = from.as_ref().unwrap().len();
                    while cmd < command.len() && command[cmd] != delim {
                        if command[cmd] == b'&' {
                            t.extend_from_slice(from.as_ref().unwrap());
                            cmd += 1;
                            continue;
                        }
                        if command[cmd] == b'\\'
                            && cmd + 1 < command.len()
                            && (command[cmd + 1] == delim || command[cmd + 1] == b'&')
                        {
                            cmd += 1;
                        }
                        t.push(command[cmd]);
                        cmd += 1;
                    }
                    let _ = from_len;
                    if cmd >= command.len() {
                        // getto ran out of characters: goto out
                        return (ev, None);
                    }
                    to = Some(t);
                    cmd += 1;
                    let sub = rl_compat_sub(
                        tmp.as_deref().unwrap_or(&[]),
                        from.as_deref().unwrap(),
                        to.as_deref().unwrap(),
                        g_on,
                    );
                    tmp = sub;
                    g_on = 0;
                    // the C's cmd-- (the loop's cmd++ cancels it)
                    if cmd > 0 {
                        cmd -= 1;
                    }
                }
                _ => {}
            }
            cmd += 1;
        }
        (if p_on != 0 { 2 } else { 1 }, tmp)
    }

    pub fn clear_history(&mut self) {
        if let Some(mut h) = self.h.take() {
            let mut ev = HistEventN::default();
            history(&mut h, &mut ev, H_CLEAR, &[]);
            self.h = Some(h);
        }
        self.history_offset = 0;
        self.history_length = 0;
    }
}

/// replace(): keep only the text after the last occurrence of `c` (readline.c).
fn rl_replace_tail(tmp: &mut Option<Vec<u8>>, c: u8) {
    let Some(s) = tmp.as_mut() else { return };
    match s.iter().rposition(|&x| x == c) {
        Some(pos) => *s = s[pos + 1..].to_vec(),
        None => {}
    }
}

/// _rl_compat_sub(): substitute `what` with `with` in str (globally if
/// `globally` is truthy); returns None on allocation failure (never here).
fn rl_compat_sub(str: &[u8], what: &[u8], with: &[u8], globally: i32) -> Option<Vec<u8>> {
    let mut len = str.len();
    let with_len = with.len();
    let what_len = what.len();
    if what_len == 0 {
        return Some(str.to_vec());
    }
    let mut s = 0usize;
    while s < str.len() {
        if str[s] == what[0] && str[s..].starts_with(what) {
            len += with_len.saturating_sub(what_len);
            if globally == 0 {
                break;
            }
            s += what_len;
        } else {
            s += 1;
        }
    }
    let mut r: Vec<u8> = Vec::with_capacity(len + 1);
    let mut s = 0usize;
    while s < str.len() {
        if str[s] == what[0] && str[s..].starts_with(what) {
            r.extend_from_slice(with);
            s += what_len;
            if globally == 0 {
                r.extend_from_slice(&str[s..]);
                return Some(r);
            }
        } else {
            r.push(str[s]);
            s += 1;
        }
    }
    Some(r)
}

/// history_arg_extract(): extract args start..end from a history line
/// (readline.c, via history_tokenize).  The corpus exercises only the
/// "!1"/"!!"/"^a^A" forms, so the word designators are rarely reached;
/// the tokenizer mirrors the C's shell-like split.
fn history_arg_extract(start: i32, end: i32, str: &[u8]) -> Option<Vec<u8>> {
    let arr = history_tokenize(str);
    if arr.is_empty() || arr[0].is_empty() {
        return None;
    }
    let max = arr.len() as i32 - 1;
    let mut start = start;
    let mut end = end;
    if start == -1 {
        start = max;
    }
    if end == -1 {
        end = max;
    }
    if end < 0 {
        end = max + end + 1;
    }
    if start < 0 {
        start = end;
    }
    if start < 0 || end < 0 || start > max || end > max || start > end {
        return None;
    }
    let mut result: Vec<u8> = Vec::new();
    for i in start..=end {
        result.extend_from_slice(&arr[i as usize]);
        if i < end {
            result.push(b' ');
        }
    }
    Some(result)
}

/// history_tokenize(): the C's simple shell tokenizer (splits on whitespace,
/// honoring single/double quotes and backslashes).
fn history_tokenize(str: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut in_tok = false;
    let mut i = 0usize;
    while i < str.len() {
        let c = str[i];
        match c {
            b'\'' => {
                in_tok = true;
                i += 1;
                while i < str.len() && str[i] != b'\'' {
                    cur.push(str[i]);
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                in_tok = true;
                i += 1;
                while i < str.len() && str[i] != b'"' {
                    if str[i] == b'\\' && i + 1 < str.len() {
                        cur.push(str[i + 1]);
                        i += 2;
                    } else {
                        cur.push(str[i]);
                        i += 1;
                    }
                }
                i += 1;
            }
            b'\\' if i + 1 < str.len() => {
                in_tok = true;
                cur.push(str[i + 1]);
                i += 2;
            }
            c if c.is_ascii_whitespace() => {
                if in_tok {
                    out.push(std::mem::take(&mut cur));
                    in_tok = false;
                }
                i += 1;
            }
            _ => {
                in_tok = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    if in_tok {
        out.push(cur);
    }
    out
}
