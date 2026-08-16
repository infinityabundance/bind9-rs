//! inflate.c + inffast.c — zlib decompression state machine (conservation
//! port).
//!
//! The full inflate state machine with zlib/gzip/raw/auto wrappers, gzip
//! header parsing (FEXTRA/FNAME/FCOMMENT/FHCRC), dictionary handling
//! (DICTID/DICT with the adler check), stored/fixed/dynamic blocks, the
//! literal/length-distance decode paths (including the inflate_fast path
//! with its exact `back` semantics, which is observable via inflateMark),
//! the trailer checks (adler/crc + gzip ISIZE), inflateSync
//! resynchronization, inflatePrime/inflateMark/inflateCopy/
//! inflateGetHeader/inflateValidate, and the exact error taxonomy and
//! message strings.

use super::checksum;
use super::deflate::ZStream;
use super::inftrees::{inflate_table, Code, CodeType, ENOUGH};
use crate::compat::zlib::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_FINISH, Z_MEM_ERROR, Z_NEED_DICT, Z_OK, Z_STREAM_END,
    Z_STREAM_ERROR, Z_TREES, Z_UNKNOWN,
};

/// The inflate modes (inflate.h enum values).
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Mode {
    Head = 16180,
    Flags,
    Time,
    Os,
    Exlen,
    Extra,
    Name,
    Comment,
    Hcrc,
    Dictid,
    Dict,
    Type,
    Typedo,
    Stored,
    Copy_,
    Copy,
    Table,
    Lenlens,
    Codelens,
    Len_,
    Len,
    Lenext,
    Dist,
    Distext,
    Match,
    Lit,
    Check,
    Length,
    Done,
    Bad,
    Mem,
    Sync,
}

/// The internal inflate state (inflate.h).
pub struct InflateState {
    pub mode: Mode,
    pub last: i32,
    pub wrap: i32,
    pub havedict: i32,
    pub flags: i32,
    pub dmax: u32,
    pub check: u64,
    pub total: u64,
    pub head: Option<super::deflate::GzHeader>,
    pub wbits: u32,
    pub wsize: u32,
    pub whave: u32,
    pub wnext: u32,
    pub window: Vec<u8>,
    pub hold: u64,
    pub bits: u32,
    pub length: u32,
    pub offset: u32,
    pub extra: u32,
    pub lencode: Vec<Code>,
    pub distcode: Vec<Code>,
    pub lenbits: u32,
    pub distbits: u32,
    pub ncode: u32,
    pub nlen: u32,
    pub ndist: u32,
    pub have: u32,
    pub next: usize,
    pub lens: [u16; 320],
    pub work: [u16; 288],
    pub codes: Vec<Code>,
    pub sane: i32,
    pub back: i32,
    pub was: u32,
}

impl Default for InflateState {
    fn default() -> Self {
        InflateState {
            mode: Mode::Head,
            last: 0,
            wrap: 0,
            havedict: 0,
            flags: -1,
            dmax: 32768,
            check: 0,
            total: 0,
            head: None,
            wbits: 0,
            wsize: 0,
            whave: 0,
            wnext: 0,
            window: Vec::new(),
            hold: 0,
            bits: 0,
            length: 0,
            offset: 0,
            extra: 0,
            lencode: Vec::new(),
            distcode: Vec::new(),
            lenbits: 0,
            distbits: 0,
            ncode: 0,
            nlen: 0,
            ndist: 0,
            have: 0,
            next: 0,
            lens: [0; 320],
            work: [0; 288],
            codes: vec![Code::default(); ENOUGH],
            sane: 1,
            back: -1,
            was: 0,
        }
    }
}

fn inflate_state_check(strm: &ZStream) -> bool {
    matches!(strm.state, super::deflate::StreamState::Inflate(_))
}

/// `inflateResetKeep` (inflate.c).
pub fn inflate_reset_keep(strm: &mut ZStream) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    strm.total_in = 0;
    strm.total_out = 0;
    strm.msg = None;
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.total = 0;
    if s.wrap != 0 {
        /* to support ill-conceived Java test suite */
        strm.adler = (s.wrap & 1) as u32;
    }
    s.mode = Mode::Head;
    s.last = 0;
    s.havedict = 0;
    s.flags = -1;
    s.dmax = 32768;
    s.head = None;
    s.hold = 0;
    s.bits = 0;
    s.next = 0;
    s.lencode = s.codes.clone();
    s.distcode = s.codes.clone();
    s.sane = 1;
    s.back = -1;
    Z_OK
}

/// `inflateReset` (inflate.c).
pub fn inflate_reset(strm: &mut ZStream) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.wsize = 0;
    s.whave = 0;
    s.wnext = 0;
    inflate_reset_keep(strm)
}

/// `inflateReset2` (inflate.c).
pub fn inflate_reset2(strm: &mut ZStream, window_bits: i32) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };

    /* extract wrap request from windowBits parameter */
    let (wrap, mut wb) = if window_bits < 0 {
        if window_bits < -15 {
            return Z_STREAM_ERROR;
        }
        (0, -window_bits)
    } else {
        let w = (window_bits >> 4) + 5;
        let mut b = window_bits;
        if window_bits < 48 {
            b &= 15;
        }
        (w, b)
    };

    /* set number of window bits, free window if different */
    if wb != 0 && (wb < 8 || wb > 15) {
        return Z_STREAM_ERROR;
    }
    if !s.window.is_empty() && s.wbits != wb as u32 {
        s.window = Vec::new();
    }

    /* update state and reset the rest of it */
    s.wrap = wrap;
    s.wbits = wb as u32;
    inflate_reset(strm)
}

/// `inflateInit2_` (inflate.c).
pub fn inflate_init2(strm: &mut ZStream, window_bits: i32) -> i32 {
    if !matches!(strm.state, super::deflate::StreamState::None) {
        return Z_STREAM_ERROR;
    }
    strm.msg = None;
    let mut s = InflateState::default();
    s.mode = Mode::Head; /* to pass state test in inflateReset2() */
    strm.state = super::deflate::StreamState::Inflate(Box::new(s));
    let ret = inflate_reset2(strm, window_bits);
    if ret != Z_OK {
        strm.state = super::deflate::StreamState::None;
    }
    ret
}

/// `inflateInit_` — DEF_WBITS (15).
pub fn inflate_init(strm: &mut ZStream) -> i32 {
    inflate_init2(strm, 15)
}

/// `inflatePrime` (inflate.c).
pub fn inflate_prime(strm: &mut ZStream, bits: i32, value: i32) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    if bits == 0 {
        return Z_OK;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if bits < 0 {
        s.hold = 0;
        s.bits = 0;
        return Z_OK;
    }
    if bits > 16 || s.bits + bits as u32 > 32 {
        return Z_STREAM_ERROR;
    }
    let value = (value & ((1 << bits) - 1)) as u64;
    s.hold += value << s.bits;
    s.bits += bits as u32;
    Z_OK
}

/// `updatewindow` — maintain the sliding window (inflate.c).  `produced` is
/// the slice of just-produced output bytes; `copy` is how many to copy.
/// Operates directly on the window locals (the state's window is pulled out
/// during inflate()); returns 1 on allocation failure.
fn updatewindow(
    window: &mut Vec<u8>,
    wbits: u32,
    wsize: &mut u32,
    wnext: &mut u32,
    whave: &mut u32,
    produced: &[u8],
    copy: u32,
) -> i32 {
    /* if it hasn't been done already, allocate space for the window */
    if window.is_empty() {
        *window = vec![0u8; 1 << wbits];
        if window.is_empty() {
            return 1;
        }
    }

    /* if window not in use yet, initialize */
    if *wsize == 0 {
        *wsize = 1 << wbits;
        *wnext = 0;
        *whave = 0;
    }

    let end = produced.len();
    /* copy state->wsize or less output bytes into the circular window */
    if copy >= *wsize {
        let ws = *wsize as usize;
        window[..ws].copy_from_slice(&produced[end - ws..end]);
        *wnext = 0;
        *whave = *wsize;
    } else {
        let mut dist = *wsize - *wnext;
        if dist > copy {
            dist = copy;
        }
        let wn = *wnext as usize;
        let dc = dist as usize;
        window[wn..wn + dc]
            .copy_from_slice(&produced[end - copy as usize..end - copy as usize + dc]);
        let mut copy = copy - dist;
        if copy != 0 {
            let cc = copy as usize;
            window[..cc].copy_from_slice(&produced[end - copy as usize..end]);
            *wnext = copy;
            *whave = *wsize;
        } else {
            *wnext += dist;
            if *wnext == *wsize {
                *wnext = 0;
            }
            if *whave < *wsize {
                *whave += dist;
            }
        }
    }
    0
}

/// `syncsearch` — search for the 00 00 ff ff pattern (inflate.c).
fn syncsearch(have: &mut u32, buf: &[u8]) -> u32 {
    let mut got = *have;
    let mut next = 0usize;
    while next < buf.len() && got < 4 {
        if buf[next] == if got < 2 { 0 } else { 0xff } {
            got += 1;
        } else if buf[next] != 0 {
            got = 0;
        } else {
            got = 4 - got;
        }
        next += 1;
    }
    *have = got;
    next as u32
}

/// `inflateSync` (inflate.c).
pub fn inflate_sync(strm: &mut ZStream, input: &[u8]) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let mut buf = [0u8; 4];
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    let avail_in = input.len() as u32;

    if avail_in == 0 && s.bits < 8 {
        return Z_BUF_ERROR;
    }

    /* if first time, start search in bit buffer */
    if s.mode != Mode::Sync {
        s.mode = Mode::Sync;
        s.hold >>= s.bits & 7;
        s.bits -= s.bits & 7;
        let mut len = 0usize;
        while s.bits >= 8 {
            buf[len] = (s.hold & 0xff) as u8;
            s.hold >>= 8;
            s.bits -= 8;
            len += 1;
        }
        s.have = 0;
        let _ = syncsearch(&mut s.have, &buf[..len]);
    }

    /* search available input */
    let n = syncsearch(&mut s.have, &input[..avail_in as usize]);
    strm.avail_in = avail_in - n;
    strm.total_in += n as u64;

    /* return no joy or set up to restart inflate() on a new block */
    if s.have != 4 {
        return Z_DATA_ERROR;
    }
    if s.flags == -1 {
        s.wrap = 0; /* if no header yet, treat as raw */
    } else {
        s.wrap &= !4; /* no point in computing a check value now */
    }
    let flags = s.flags;
    let in_ = strm.total_in;
    let out_ = strm.total_out;
    let _ = inflate_reset(strm);
    strm.total_in = in_;
    strm.total_out = out_;
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.flags = flags;
    s.mode = Mode::Type;
    Z_OK
}

/// `inflateSyncPoint` (inflate.c).
pub fn inflate_sync_point(strm: &ZStream) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if s.mode == Mode::Stored && s.bits == 0 {
        1
    } else {
        0
    }
}

/// `inflateEnd` (inflate.c).
pub fn inflate_end(strm: &mut ZStream) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    strm.state = super::deflate::StreamState::None;
    Z_OK
}

/// `inflateGetDictionary` (inflate.c).
pub fn inflate_get_dictionary(strm: &ZStream) -> (i32, Vec<u8>) {
    if !inflate_state_check(strm) {
        return (Z_STREAM_ERROR, Vec::new());
    }
    let s = match &strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return (Z_STREAM_ERROR, Vec::new()),
    };
    let mut dict = Vec::new();
    if s.whave != 0 {
        let wnext = s.wnext as usize;
        let whave = s.whave as usize;
        dict.extend_from_slice(&s.window[wnext..wnext + (whave - wnext)]);
        dict.extend_from_slice(&s.window[..wnext]);
    }
    (Z_OK, dict)
}

/// `inflateSetDictionary` (inflate.c).
pub fn inflate_set_dictionary(strm: &mut ZStream, dictionary: &[u8]) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let (wrap, mode) = {
        let s = match &strm.state {
            super::deflate::StreamState::Inflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        (s.wrap, s.mode)
    };
    if wrap != 0 && mode != Mode::Dict {
        return Z_STREAM_ERROR;
    }

    /* check for correct dictionary identifier */
    if mode == Mode::Dict {
        let mut dictid = checksum::adler32(0, &[]);
        dictid = checksum::adler32(dictid, dictionary);
        let s = match &strm.state {
            super::deflate::StreamState::Inflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        if dictid != s.check as u32 {
            return Z_DATA_ERROR;
        }
    }

    /* copy dictionary to window using updatewindow() */
    let ret = {
        let s = match &mut strm.state {
            super::deflate::StreamState::Inflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        let mut wsize = s.wsize;
        let mut wnext = s.wnext;
        let mut whave = s.whave;
        let mut window = std::mem::take(&mut s.window);
        let r = updatewindow(
            &mut window,
            s.wbits,
            &mut wsize,
            &mut wnext,
            &mut whave,
            dictionary,
            dictionary.len() as u32,
        );
        s.window = window;
        s.wsize = wsize;
        s.wnext = wnext;
        s.whave = whave;
        r
    };
    if ret != 0 {
        let s = match &mut strm.state {
            super::deflate::StreamState::Inflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        s.mode = Mode::Mem;
        return Z_MEM_ERROR;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.havedict = 1;
    Z_OK
}

/// `inflateGetHeader` (inflate.c).
///
/// Registers a `gz_header` for the gzip-header fields (text/time/xflags/os/
/// extra/name/comment/hcrc) to be filled as the header is parsed, or
/// retrieves the currently registered header:
///
/// - `Some(head)` — register `head` (its `done` is set to -1; fields are
///   filled during the following `inflate` calls).  Returns `(Z_OK, head)`.
/// - `None` — retrieve the registered header after parsing.  Returns
///   `(Z_OK, filled_head)` with `done == 1` once the header is complete.
///
/// The caller pre-sizes `extra`/`name`/`comment` to their `*_max`
/// capacities exactly like the C `gz_headerp` (the C stores the pointer and
/// fills the caller's buffers; the Rust registers the struct by value and
/// returns the filled copy, keeping the observable surface identical).
pub fn inflate_get_header(
    strm: &mut ZStream,
    head: Option<super::deflate::GzHeader>,
) -> (i32, super::deflate::GzHeader) {
    if !inflate_state_check(strm) {
        return (Z_STREAM_ERROR, head.unwrap_or_default());
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return (Z_STREAM_ERROR, head.unwrap_or_default()),
    };
    if (s.wrap & 2) == 0 {
        return (Z_STREAM_ERROR, head.unwrap_or_default());
    }
    if let Some(mut h) = head {
        h.done = -1;
        s.head = Some(h);
    }
    (Z_OK, s.head.as_ref().cloned().unwrap_or_default())
}

/// `inflateValidate` (inflate.c).
pub fn inflate_validate(strm: &mut ZStream, check: i32) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if check != 0 && s.wrap != 0 {
        s.wrap |= 4;
    } else {
        s.wrap &= !4;
    }
    Z_OK
}

/// `inflateUndermine` (inflate.c; the INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR
/// path is not compiled in stock zlib, so this always returns Z_DATA_ERROR).
pub fn inflate_undermine(strm: &mut ZStream, _subvert: i32) -> i32 {
    if !inflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.sane = 1;
    Z_DATA_ERROR
}

/// `inflateMark` (inflate.c).
pub fn inflate_mark(strm: &ZStream) -> i64 {
    if !inflate_state_check(strm) {
        return -(1i64 << 16);
    }
    let s = match &strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return -(1i64 << 16),
    };
    ((s.back as i64) << 16)
        + if s.mode == Mode::Copy {
            s.length as i64
        } else if s.mode == Mode::Match {
            s.was as i64 - s.length as i64
        } else {
            0
        }
}

/// `inflateCodesUsed` (inflate.c).
pub fn inflate_codes_used(strm: &ZStream) -> u64 {
    if !inflate_state_check(strm) {
        return u64::MAX;
    }
    let s = match &strm.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return u64::MAX,
    };
    s.next as u64
}

/// `inflateCopy` (inflate.c).
pub fn inflate_copy(dest: &mut ZStream, source: &ZStream) -> i32 {
    if !inflate_state_check(source) {
        return Z_STREAM_ERROR;
    }
    let s = match &source.state {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    dest.avail_in = source.avail_in;
    dest.total_in = source.total_in;
    dest.avail_out = source.avail_out;
    dest.total_out = source.total_out;
    dest.msg = source.msg;
    dest.data_type = source.data_type;
    dest.adler = source.adler;
    let mut c = InflateState::default();
    c.mode = s.mode;
    c.last = s.last;
    c.wrap = s.wrap;
    c.havedict = s.havedict;
    c.flags = s.flags;
    c.dmax = s.dmax;
    c.check = s.check;
    c.total = s.total;
    c.head = s.head.clone();
    c.wbits = s.wbits;
    c.wsize = s.wsize;
    c.whave = s.whave;
    c.wnext = s.wnext;
    c.window = s.window.clone();
    c.hold = s.hold;
    c.bits = s.bits;
    c.length = s.length;
    c.offset = s.offset;
    c.extra = s.extra;
    c.lenbits = s.lenbits;
    c.distbits = s.distbits;
    c.ncode = s.ncode;
    c.nlen = s.nlen;
    c.ndist = s.ndist;
    c.have = s.have;
    c.next = s.next;
    c.lens = s.lens;
    c.work = s.work;
    c.codes = s.codes.clone();
    c.sane = s.sane;
    c.back = s.back;
    c.was = s.was;
    /* the active code tables are the source's lencode/distcode slices
     * (the C's pointers into codes), NOT the whole codes workspace */
    c.lencode = s.lencode.clone();
    c.distcode = s.distcode.clone();
    dest.state = super::deflate::StreamState::Inflate(Box::new(c));
    Z_OK
}

// ---------------------------------------------------------------------------
// inflate() — the main state machine
// ---------------------------------------------------------------------------

/// `inflate(strm, flush)` — the public entry.  `input`/`output` are the
/// per-call buffers; `strm.avail_in`/`strm.avail_out` are set from them.
pub fn inflate(strm: &mut ZStream, input: &[u8], output: &mut [u8], flush: i32) -> i32 {
    strm.avail_in = input.len() as u32;
    strm.avail_out = output.len() as u32;
    inflate_call_internal(strm, input, output, flush)
}

/// The fast decode loop (inffast.c).  Operates on the caller's locals;
/// returns Ok(()) with `mode` updated on EOB (Type) or error (Bad, msg
/// set), Err(()) if the resource limits were hit mid-block (mode remains
/// Len).  `back` is NOT touched here (inffast.c semantics).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn inflate_fast(
    input: &[u8],
    next: &mut usize,
    have: &mut u32,
    output: &mut [u8],
    put: &mut usize,
    left: &mut u32,
    hold: &mut u64,
    bits: &mut u32,
    lcode: &[Code],
    lenbits: u32,
    dcode: &[Code],
    distbits: u32,
    window: &[u8],
    wsize: u32,
    whave: u32,
    wnext: u32,
    sane: i32,
    entry_left: u32,
    mode: &mut Mode,
    msg: &mut Option<&'static str>,
) -> Result<(), ()> {
    let lmask = (1u64 << lenbits) - 1;
    let dmask = (1u64 << distbits) - 1;

    macro_rules! pull2 {
        () => {
            *hold += (input[*next] as u64) << *bits;
            *bits += 8;
            *next += 1;
            *have -= 1;
            *hold += (input[*next] as u64) << *bits;
            *bits += 8;
            *next += 1;
            *have -= 1;
        };
    }
    macro_rules! pull1 {
        () => {
            *hold += (input[*next] as u64) << *bits;
            *bits += 8;
            *next += 1;
            *have -= 1;
        };
    }
    macro_rules! bad {
        ($m:expr) => {
            *msg = Some($m);
            *mode = Mode::Bad;
            return Ok(());
        };
    }

    loop {
        /* decode one symbol (literal or length/dist pair) without back */
        if *bits < 15 {
            pull2!();
        }
        let mut here = lcode[(*hold & lmask) as usize];
        'dolen: loop {
            let op = here.bits as u32;
            *hold >>= op;
            *bits -= op;
            let op = here.op as u32;
            if op == 0 {
                /* literal */
                output[*put] = here.val as u8;
                *put += 1;
                *left -= 1;
                break 'dolen;
            }
            if op & 16 != 0 {
                /* length base */
                let mut len = here.val as u32;
                let e = op & 15; /* extra bits */
                if std::env::var("ZLIB_TRACE").is_ok() && *put >= 810 {
                    eprintln!(
                        "FLEN put={} op={} e={} len={} bits={} hold={:x}",
                        *put, op, e, len, *bits, *hold
                    );
                }
                if e != 0 {
                    if *bits < e {
                        pull1!();
                    }
                    len += (*hold & ((1u64 << e) - 1)) as u32;
                    *hold >>= e;
                    *bits -= e;
                }
                /* distance code */
                if *bits < 15 {
                    pull2!();
                }
                here = dcode[(*hold & dmask) as usize];
                loop {
                    let op = here.bits as u32;
                    *hold >>= op;
                    *bits -= op;
                    let op = here.op as u32;
                    if op & 16 != 0 {
                        /* distance base */
                        let mut dist = here.val as u32;
                        let e = op & 15;
                        if e != 0 {
                            if *bits < e {
                                pull1!();
                                if *bits < e {
                                    pull1!();
                                }
                            }
                            dist += (*hold & ((1u64 << e) - 1)) as u32;
                            *hold >>= e;
                            *bits -= e;
                        }
                        /* copy the match — the fast path copies the whole
                         * match (window portion then output portion), like
                         * inffast.c (entry guarantees left >= 258 so a full
                         * match always fits) */
                        if let Err(m) = copy_match_fast(
                            output,
                            put,
                            left,
                            window,
                            wsize,
                            whave,
                            wnext,
                            sane,
                            dist,
                            len,
                            entry_left - *left,
                        ) {
                            bad!(m);
                        }
                        break 'dolen;
                    }
                    if (op & 64) == 0 {
                        /* 2nd level distance code */
                        let idx = here.val as usize + ((*hold & ((1u64 << op) - 1)) as usize);
                        here = dcode[idx];
                    } else {
                        bad!("invalid distance code");
                    }
                }
                break 'dolen;
            }
            if (op & 64) == 0 {
                /* 2nd level length code */
                let idx = here.val as usize + ((*hold & ((1u64 << op) - 1)) as usize);
                here = lcode[idx];
            } else if op & 32 != 0 {
                /* end of block */
                *mode = Mode::Type;
                return Ok(());
            } else {
                bad!("invalid literal/length code");
            }
        }
        /* resource limits: the C's `while (in < last && out < end)` */
        if std::env::var("ZLIB_TRACE").is_ok() {
            eprintln!(
                "FASTSYM put={} have={} left={} mode={:?}",
                *put, *have, *left, mode
            );
        }
        if *have < 6 || *left < 258 {
            return Err(());
        }
    }
}

/// The fast-path match copy (inffast.c).  Copies the ENTIRE match: the
/// window portion first if the distance reaches into the window, then the
/// rest from the output.  Entry guarantees left >= 258 so a full match
/// always fits.  Returns Err(message) for invalid-distance-too-far-back.
#[allow(clippy::too_many_arguments)]
fn copy_match_fast(
    output: &mut [u8],
    put: &mut usize,
    left: &mut u32,
    window: &[u8],
    wsize: u32,
    whave: u32,
    wnext: u32,
    sane: i32,
    dist: u32,
    mut len: u32,
    produced: u32,
) -> Result<(), &'static str> {
    let mut from_idx: usize; // into window or output
    let mut from_window: bool;
    let mut op = produced; /* max distance in output */
    if std::env::var("ZLIB_TRACE").is_ok() {
        eprintln!(
            "CMF put={} dist={} len={} produced={} wsize={} whave={} wnext={}",
            *put, dist, len, produced, wsize, whave, wnext
        );
    }
    if dist > op {
        /* see if copy from window */
        op = dist - op; /* distance back in window */
        if op > whave {
            if sane != 0 {
                return Err("invalid distance too far back");
            }
            // INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR not compiled
        }
        if wnext == 0 {
            /* very common case */
            from_idx = (wsize - op) as usize;
            from_window = true;
            if op < len {
                /* some from window */
                len -= op;
                let n = op as usize;
                output[*put..*put + n].copy_from_slice(&window[from_idx..from_idx + n]);
                *put += n;
                *left -= op;
                from_idx = *put - dist as usize; /* rest from output */
                from_window = false;
            }
        } else if wnext < op {
            /* wrap around window */
            from_idx = (wsize + wnext - op) as usize;
            op -= wnext;
            if op < len {
                /* some from end of window */
                len -= op;
                let n = op as usize;
                output[*put..*put + n].copy_from_slice(&window[from_idx..from_idx + n]);
                *put += n;
                *left -= op;
                from_idx = 0;
                if wnext < len {
                    /* some from start of window */
                    let wn = wnext as usize;
                    output[*put..*put + wn].copy_from_slice(&window[..wn]);
                    *put += wn;
                    *left -= wnext;
                    len -= wnext;
                    from_idx = *put - dist as usize; /* rest from output */
                    from_window = false;
                } else {
                    from_window = true;
                }
            } else {
                from_window = true;
            }
        } else {
            /* contiguous in window */
            from_idx = (wnext - op) as usize;
            from_window = true;
            if op < len {
                /* some from window */
                len -= op;
                let n = op as usize;
                output[*put..*put + n].copy_from_slice(&window[from_idx..from_idx + n]);
                *put += n;
                *left -= op;
                from_idx = *put - dist as usize; /* rest from output */
                from_window = false;
            }
        }
    } else {
        /* copy direct from output */
        from_idx = *put - dist as usize;
        from_window = false;
    }
    // copy the remaining `len` bytes from `from_idx` (window or output)
    if from_window {
        /* window source: non-overlapping, bulk copy */
        let n = len as usize;
        output[*put..*put + n].copy_from_slice(&window[from_idx..from_idx + n]);
        *put += n;
        *left -= len;
    } else {
        /* output source: overlapping copies must be byte-by-byte in order
         * (the C's `do { *put++ = *from++; } while (--op)`), e.g. dist=1
         * runs where each read sees the freshly written byte */
        for _ in 0..len {
            output[*put] = output[from_idx];
            *put += 1;
            from_idx += 1;
        }
        *left -= len;
    }
    Ok(())
}

/// The match copy (slow MATCH / inffast copy logic shared).  `produced` is
/// the number of output bytes produced so far (since the whole call or since
/// fast entry, depending on the caller).  `length` is updated to the
/// remaining bytes (the C loops back to MATCH when nonzero).  Returns
/// Err(message) for the invalid-distance-too-far-back error.
#[allow(clippy::too_many_arguments)]
fn copy_match(
    output: &mut [u8],
    put: &mut usize,
    left: &mut u32,
    window: &[u8],
    wsize: u32,
    whave: u32,
    wnext: u32,
    sane: i32,
    offset: u32,
    length: &mut u32,
    produced: u32,
) -> Result<(), &'static str> {
    let mut copy = produced;
    if offset > copy {
        /* copy from window */
        copy = offset - copy;
        if copy > whave {
            if sane != 0 {
                return Err("invalid distance too far back");
            }
            // INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR not compiled
        }
        let from;
        if copy > wnext {
            copy -= wnext;
            from = wsize - copy;
        } else {
            from = wnext - copy;
        }
        if copy > *length {
            copy = *length;
        }
        if copy > *left {
            copy = *left;
        }
        *left -= copy;
        *length -= copy;
        let n = copy as usize;
        let f = from as usize;
        let src = window[f..f + n].to_vec();
        output[*put..*put + n].copy_from_slice(&src);
        *put += n;
    } else {
        /* copy from output */
        let from = *put - offset as usize;
        copy = *length;
        if copy > *left {
            copy = *left;
        }
        *left -= copy;
        *length -= copy;
        let n = copy as usize;
        // overlapping byte-by-byte copy (matches the C do-while)
        for i in 0..n {
            output[*put + i] = output[from + i];
        }
        *put += n;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn inflate_call_internal(
    strm: &mut ZStream,
    input: &[u8],
    output: &mut [u8],
    flush: i32,
) -> i32 {
    if !inflate_state_check(strm) || (strm.avail_in != 0 && input.is_empty()) {
        /* note: avail_out == 0 is legal (the C allows it; no progress then
         * yields Z_BUF_ERROR via the inf_leave check below) */
        return Z_STREAM_ERROR;
    }

    let mut state = match std::mem::replace(&mut strm.state, super::deflate::StreamState::None) {
        super::deflate::StreamState::Inflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };

    let in0 = strm.avail_in;
    let out0 = strm.avail_out;
    let mut have = strm.avail_in;
    let mut next = 0usize;
    let mut left = strm.avail_out;
    let mut put = 0usize;
    let mut hold = state.hold;
    let mut bits = state.bits;
    let mut ret = Z_OK;
    let mut msg: Option<&'static str> = strm.msg;
    let mut hbuf = [0u8; 4];

    let mut mode = state.mode;
    let mut last = state.last;
    let mut wrap = state.wrap;
    let mut havedict = state.havedict;
    let mut flags = state.flags;
    let mut dmax = state.dmax;
    let mut check = state.check;
    let mut total = state.total;
    let mut length = state.length;
    let mut offset = state.offset;
    let mut extra = state.extra;
    let mut lenbits = state.lenbits;
    let mut distbits = state.distbits;
    let mut ncode = state.ncode;
    let mut nlen = state.nlen;
    let mut ndist = state.ndist;
    let mut have_codes = state.have;
    let mut next_codes = state.next;
    let mut sane = state.sane;
    let mut back = state.back;
    let mut was = state.was;
    let mut wsize = state.wsize;
    let mut whave = state.whave;
    let mut wnext = state.wnext;
    let mut wbits = state.wbits;
    let mut window = std::mem::take(&mut state.window);
    let mut lens = state.lens;
    let mut work = state.work;
    let mut codes = std::mem::take(&mut state.codes);
    let mut lencode = std::mem::take(&mut state.lencode);
    let mut distcode = std::mem::take(&mut state.distcode);
    let mut head = state.head.take();
    let mut adler = strm.adler;
    let mut out = out0; /* produced-so-far tracker (the C's `out` local) */

    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    let mut leave = false;

    macro_rules! pullbyte {
        ($outer:lifetime) => {
            if have == 0 {
                leave = true;
                break $outer;
            }
            have -= 1;
            hold += (input[next] as u64) << bits;
            next += 1;
            bits += 8;
        };
    }
    macro_rules! needbits {
        ($outer:lifetime, $n:expr) => {
            while bits < ($n as u32) {
                pullbyte!($outer);
            }
        };
    }
    macro_rules! bbits {
        ($n:expr) => {
            (hold & ((1u64 << ($n)) - 1)) as u32
        };
    }
    macro_rules! dropbits {
        ($n:expr) => {
            hold >>= ($n);
            bits -= ($n) as u32;
        };
    }
    macro_rules! initbits {
        () => {
            hold = 0;
            bits = 0;
        };
    }
    macro_rules! bytebits {
        () => {
            hold >>= bits & 7;
            bits -= bits & 7;
        };
    }
    let mut leave = false;

    'outer: loop {
        match mode {
            Mode::Head => {
                if wrap == 0 {
                    mode = Mode::Typedo;
                    continue;
                }
                needbits!('outer, 16);
                if (wrap & 2) != 0 && hold == 0x8b1f {
                    /* gzip header */
                    if wbits == 0 {
                        wbits = 15;
                    }
                    check = checksum::crc32(0, &[]) as u64;
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    check = checksum::crc32(check as u32, &hbuf[..2]) as u64;
                    initbits!();
                    mode = Mode::Flags;
                    continue;
                }
                if let Some(h) = head.as_mut() {
                    h.done = -1;
                }
                if (wrap & 1) == 0 || ((((bbits!(8) as u64) << 8) + (hold >> 8)) % 31) != 0 {
                    msg = Some("incorrect header check");
                    mode = Mode::Bad;
                    continue;
                }
                if bbits!(4) != 8 {
                    msg = Some("unknown compression method");
                    mode = Mode::Bad;
                    continue;
                }
                dropbits!(4);
                let len = bbits!(4) + 8;
                if wbits == 0 {
                    wbits = len;
                }
                if len > 15 || len > wbits {
                    msg = Some("invalid window size");
                    mode = Mode::Bad;
                    continue;
                }
                dmax = 1 << len;
                flags = 0; /* indicate zlib header */
                adler = checksum::adler32(0, &[]) as u32;
                check = adler as u64;
                mode = if hold & 0x200 != 0 {
                    Mode::Dictid
                } else {
                    Mode::Type
                };
                initbits!();
            }
            Mode::Flags => {
                needbits!('outer, 16);
                flags = (hold & 0xffff) as i32;
                if (flags & 0xff) != 8 {
                    msg = Some("unknown compression method");
                    mode = Mode::Bad;
                    continue;
                }
                if flags & 0xe000 != 0 {
                    msg = Some("unknown header flags set");
                    mode = Mode::Bad;
                    continue;
                }
                if let Some(h) = head.as_mut() {
                    h.text = ((hold >> 8) & 1) != 0;
                }
                if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    check = checksum::crc32(check as u32, &hbuf[..2]) as u64;
                }
                initbits!();
                mode = Mode::Time;
            }
            Mode::Time => {
                needbits!('outer, 32);
                if let Some(h) = head.as_mut() {
                    h.time = (hold & 0xffff_ffff) as u32;
                }
                if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    hbuf[2] = ((hold >> 16) & 0xff) as u8;
                    hbuf[3] = ((hold >> 24) & 0xff) as u8;
                    check = checksum::crc32(check as u32, &hbuf) as u64;
                }
                initbits!();
                mode = Mode::Os;
            }
            Mode::Os => {
                needbits!('outer, 16);
                if let Some(h) = head.as_mut() {
                    h.xflags = (hold & 0xff) as i32;
                    h.os = ((hold >> 8) & 0xff) as i32;
                }
                if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                    hbuf[0] = (hold & 0xff) as u8;
                    hbuf[1] = ((hold >> 8) & 0xff) as u8;
                    check = checksum::crc32(check as u32, &hbuf[..2]) as u64;
                }
                initbits!();
                mode = Mode::Exlen;
            }
            Mode::Exlen => {
                if flags & 0x0400 != 0 {
                    needbits!('outer, 16);
                    length = bbits!(16);
                    if let Some(h) = head.as_mut() {
                        h.extra_len = length;
                    }
                    if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                        hbuf[0] = (hold & 0xff) as u8;
                        hbuf[1] = ((hold >> 8) & 0xff) as u8;
                        check = checksum::crc32(check as u32, &hbuf[..2]) as u64;
                    }
                    initbits!();
                } else if let Some(h) = head.as_mut() {
                    h.extra = None;
                }
                mode = Mode::Extra;
            }
            Mode::Extra => {
                if flags & 0x0400 != 0 {
                    let mut copy = length;
                    if copy > have {
                        copy = have;
                    }
                    if copy != 0 {
                        if let Some(h) = head.as_mut() {
                            if let Some(extra_buf) = h.extra.as_mut() {
                                let len = (h.extra_len - length) as usize;
                                if (len as u32) < h.extra_max {
                                    let n = if len + copy as usize > h.extra_max as usize {
                                        h.extra_max as usize - len
                                    } else {
                                        copy as usize
                                    };
                                    extra_buf[len..len + n].copy_from_slice(&input[next..next + n]);
                                }
                            }
                        }
                        if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                            check =
                                checksum::crc32(check as u32, &input[next..next + copy as usize])
                                    as u64;
                        }
                        have -= copy;
                        next += copy as usize;
                        length -= copy;
                    }
                    if length != 0 {
                        leave = true;
                        break 'outer;
                    }
                }
                length = 0;
                mode = Mode::Name;
            }
            Mode::Name => {
                if flags & 0x0800 != 0 {
                    if have == 0 {
                        leave = true;
                        break 'outer;
                    }
                    let mut copy = 0usize;
                    let mut len;
                    loop {
                        len = input[next + copy];
                        if let Some(h) = head.as_mut() {
                            if let Some(name) = h.name.as_mut() {
                                if length < h.name_max {
                                    name[length as usize] = len;
                                    length += 1;
                                }
                            }
                        }
                        copy += 1;
                        if len == 0 || copy >= have as usize {
                            break;
                        }
                    }
                    if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                        check = checksum::crc32(check as u32, &input[next..next + copy]) as u64;
                    }
                    have -= copy as u32;
                    next += copy;
                    if len != 0 {
                        leave = true;
                        break 'outer;
                    }
                } else if let Some(h) = head.as_mut() {
                    h.name = None;
                }
                length = 0;
                mode = Mode::Comment;
            }
            Mode::Comment => {
                if flags & 0x1000 != 0 {
                    if have == 0 {
                        leave = true;
                        break 'outer;
                    }
                    let mut copy = 0usize;
                    let mut len;
                    loop {
                        len = input[next + copy];
                        if let Some(h) = head.as_mut() {
                            if let Some(comment) = h.comment.as_mut() {
                                if length < h.comm_max {
                                    comment[length as usize] = len;
                                    length += 1;
                                }
                            }
                        }
                        copy += 1;
                        if len == 0 || copy >= have as usize {
                            break;
                        }
                    }
                    if flags & 0x0200 != 0 && (wrap & 4) != 0 {
                        check = checksum::crc32(check as u32, &input[next..next + copy]) as u64;
                    }
                    have -= copy as u32;
                    next += copy;
                    if len != 0 {
                        leave = true;
                        break 'outer;
                    }
                } else if let Some(h) = head.as_mut() {
                    h.comment = None;
                }
                mode = Mode::Hcrc;
            }
            Mode::Hcrc => {
                if flags & 0x0200 != 0 {
                    needbits!('outer, 16);
                    if (wrap & 4) != 0 && (hold & 0xffff) != (check & 0xffff) {
                        msg = Some("header crc mismatch");
                        mode = Mode::Bad;
                        continue;
                    }
                    initbits!();
                }
                if let Some(h) = head.as_mut() {
                    h.hcrc = (flags >> 9) & 1 != 0;
                    h.done = 1;
                }
                adler = checksum::crc32(0, &[]) as u32;
                check = adler as u64;
                mode = Mode::Type;
            }
            Mode::Dictid => {
                needbits!('outer, 32);
                adler = (hold >> 24 | (hold >> 8) & 0xff00 | (hold << 8) & 0xff0000 | (hold << 24))
                    as u32;
                check = adler as u64;
                initbits!();
                mode = Mode::Dict;
            }
            Mode::Dict => {
                if havedict == 0 {
                    ret = Z_NEED_DICT;
                    leave = true;
                    break 'outer;
                }
                adler = checksum::adler32(0, &[]) as u32;
                check = adler as u64;
                mode = Mode::Type;
            }
            Mode::Type => {
                if flush == Z_BLOCK || flush == Z_TREES {
                    leave = true;
                    break 'outer;
                }
                mode = Mode::Typedo;
            }
            Mode::Typedo => {
                if last != 0 {
                    bytebits!();
                    mode = Mode::Check;
                    continue;
                }
                needbits!('outer, 3);
                last = bbits!(1) as i32;
                dropbits!(1);
                match bbits!(2) {
                    0 => {
                        /* stored block */
                        mode = Mode::Stored;
                    }
                    1 => {
                        /* fixed block: build the fixed tables */
                        next_codes = 0;
                        codes = vec![Code::default(); ENOUGH];
                        let mut flens = [0u16; 288];
                        let mut sym = 0usize;
                        while sym < 144 {
                            flens[sym] = 8;
                            sym += 1;
                        }
                        while sym < 256 {
                            flens[sym] = 9;
                            sym += 1;
                        }
                        while sym < 280 {
                            flens[sym] = 7;
                            sym += 1;
                        }
                        while sym < 288 {
                            flens[sym] = 8;
                            sym += 1;
                        }
                        let mut lbits = 9u32;
                        let lens_start = next_codes;
                        let _ = inflate_table(
                            CodeType::Lens,
                            &flens,
                            288,
                            &mut codes,
                            &mut next_codes,
                            &mut lbits,
                            &mut work,
                        );
                        lenbits = lbits;
                        lencode = codes[..next_codes].to_vec();
                        let mut dlens = [5u16; 32];
                        let mut dbits2 = 5u32;
                        let dist_start = next_codes;
                        let _ = inflate_table(
                            CodeType::Dists,
                            &dlens,
                            32,
                            &mut codes,
                            &mut next_codes,
                            &mut dbits2,
                            &mut work,
                        );
                        distbits = dbits2;
                        distcode = codes[dist_start..next_codes].to_vec();
                        let _ = lens_start;
                        mode = Mode::Len_;
                        if flush == Z_TREES {
                            dropbits!(2);
                            leave = true;
                            break 'outer;
                        }
                    }
                    _ => {
                        /* dynamic block */
                        mode = Mode::Table;
                    }
                }
                dropbits!(2);
            }
            Mode::Stored => {
                bytebits!();
                needbits!('outer, 32);
                if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                    msg = Some("invalid stored block lengths");
                    mode = Mode::Bad;
                    continue;
                }
                length = bbits!(16);
                initbits!();
                mode = Mode::Copy_;
            }
            Mode::Copy_ => {
                mode = Mode::Copy;
            }
            Mode::Copy => {
                let mut copy = length;
                if copy != 0 {
                    if copy > have {
                        copy = have;
                    }
                    if copy > left {
                        copy = left;
                    }
                    if copy == 0 {
                        leave = true;
                        break 'outer;
                    }
                    let n = copy as usize;
                    output[put..put + n].copy_from_slice(&input[next..next + n]);
                    next += n;
                    put += n;
                    have -= copy;
                    left -= copy;
                    length -= copy;
                    if length == 0 {
                        mode = Mode::Type;
                    }
                } else {
                    /* zero-length stored block (e.g. the Z_SYNC_FLUSH
                     * marker): the C goes straight to TYPE */
                    mode = Mode::Type;
                }
            }
            Mode::Table => {
                needbits!('outer, 14);
                nlen = bbits!(5) + 257;
                dropbits!(5);
                ndist = bbits!(5) + 1;
                dropbits!(5);
                ncode = bbits!(4) + 4;
                dropbits!(4);
                /* decode code length code lengths */
                if nlen > 286 || ndist > 30 {
                    msg = Some("too many length or distance symbols");
                    mode = Mode::Bad;
                    continue;
                }
                for sym in 0..ncode as usize {
                    needbits!('outer, 3);
                    lens[ORDER[sym]] = bbits!(3) as u16;
                    dropbits!(3);
                }
                for sym in ncode as usize..19 {
                    lens[ORDER[sym]] = 0;
                }
                have_codes = 0;
                mode = Mode::Lenlens;
            }
            Mode::Lenlens => {
                /* build the code length code table (root 7) */
                next_codes = 0;
                codes = vec![Code::default(); ENOUGH];
                let mut tbits = 7u32;
                let r = inflate_table(
                    CodeType::Codes,
                    &lens,
                    19,
                    &mut codes,
                    &mut next_codes,
                    &mut tbits,
                    &mut work,
                );
                if r != 0 {
                    msg = Some("invalid code lengths set");
                    mode = Mode::Bad;
                    continue;
                }
                lenbits = tbits;
                lencode = codes.clone();
                have_codes = 0;
                mode = Mode::Codelens;
            }
            Mode::Codelens => {
                while have_codes < nlen + ndist {
                    let mut here;
                    loop {
                        here = lencode[bbits!(lenbits) as usize];
                        if (here.bits as u32) <= bits {
                            break;
                        }
                        pullbyte!('outer);
                    }
                    if here.val < 16 {
                        dropbits!(here.bits as u32);
                        lens[have_codes as usize] = here.val;
                        have_codes += 1;
                    } else {
                        let len;
                        let copy;
                        if here.val == 16 {
                            needbits!('outer, here.bits as u32 + 2);
                            dropbits!(here.bits as u32);
                            if have_codes == 0 {
                                msg = Some("invalid bit length repeat");
                                mode = Mode::Bad;
                                break;
                            }
                            len = lens[have_codes as usize - 1];
                            copy = 3 + bbits!(2);
                            dropbits!(2);
                        } else if here.val == 17 {
                            needbits!('outer, here.bits as u32 + 3);
                            dropbits!(here.bits as u32);
                            len = 0;
                            copy = 3 + bbits!(3);
                            dropbits!(3);
                        } else {
                            needbits!('outer, here.bits as u32 + 7);
                            dropbits!(here.bits as u32);
                            len = 0;
                            copy = 11 + bbits!(7);
                            dropbits!(7);
                        }
                        if have_codes + copy > nlen + ndist {
                            msg = Some("invalid bit length repeat");
                            mode = Mode::Bad;
                            break;
                        }
                        let mut c = copy;
                        while c != 0 {
                            lens[have_codes as usize] = len as u16;
                            have_codes += 1;
                            c -= 1;
                        }
                    }
                }
                /* handle error breaks in while */
                if mode == Mode::Bad {
                    continue;
                }
                /* check for end-of-block code (better have one) */
                if lens[256] == 0 {
                    msg = Some("invalid code -- missing end-of-block");
                    mode = Mode::Bad;
                    continue;
                }
                /* build code tables */
                next_codes = 0;
                codes = vec![Code::default(); ENOUGH];
                let mut lbits = 9u32;
                let r1 = inflate_table(
                    CodeType::Lens,
                    &lens[..nlen as usize],
                    nlen as usize,
                    &mut codes,
                    &mut next_codes,
                    &mut lbits,
                    &mut work,
                );
                if r1 != 0 {
                    msg = Some("invalid literal/lengths set");
                    mode = Mode::Bad;
                    continue;
                }
                lenbits = lbits;
                lencode = codes[..next_codes].to_vec();
                let mut dbits2 = 6u32;
                let dist_start = next_codes;
                let r2 = inflate_table(
                    CodeType::Dists,
                    &lens[nlen as usize..nlen as usize + ndist as usize],
                    ndist as usize,
                    &mut codes,
                    &mut next_codes,
                    &mut dbits2,
                    &mut work,
                );
                if r2 != 0 {
                    msg = Some("invalid distances set");
                    mode = Mode::Bad;
                    continue;
                }
                distbits = dbits2;
                distcode = codes[dist_start..next_codes].to_vec();
                mode = Mode::Len_;
                if flush == Z_TREES {
                    leave = true;
                    break 'outer;
                }
            }
            Mode::Len_ => {
                mode = Mode::Len;
            }
            Mode::Len => {
                if have >= 6 && left >= 258 {
                    /* inflate_fast path: does not touch `back` */
                    let entry_left = left;
                    let r = inflate_fast(
                        input, &mut next, &mut have, output, &mut put, &mut left, &mut hold,
                        &mut bits, &lencode, lenbits, &distcode, distbits, &window, wsize, whave,
                        wnext, sane, entry_left, &mut mode, &mut msg,
                    );
                    let _ = r;
                    if mode == Mode::Type || mode == Mode::Bad {
                        if mode == Mode::Type {
                            back = -1;
                        }
                        continue;
                    }
                    // resource limit: fall through to the slow path
                    // (back is NOT reset here, matching the C where the
                    // fast path left it untouched and the next LEN entry
                    // resets it via the slow path below)
                }
                back = 0;
                let mut here;
                loop {
                    here = lencode[bbits!(lenbits) as usize];
                    if (here.bits as u32) <= bits {
                        break;
                    }
                    pullbyte!('outer);
                }
                if here.op != 0 && (here.op & 0xf0) == 0 {
                    /* table link */
                    let last_entry = here;
                    loop {
                        let idx = (last_entry.val as usize)
                            + (((hold >> last_entry.bits) & ((1u64 << (last_entry.op & 15)) - 1))
                                as usize);
                        here = lencode[idx];
                        if (last_entry.bits as u32 + here.bits as u32) <= bits {
                            break;
                        }
                        pullbyte!('outer);
                    }
                    dropbits!(last_entry.bits as u32);
                    back += last_entry.bits as i32;
                }
                dropbits!(here.bits as u32);
                back += here.bits as i32;
                length = here.val as u32;
                if std::env::var("ZLIB_TRACE").is_ok() && length < 300 {
                    eprintln!(
                        "LEN put={put} op={} bits={} val={} hold_bits={bits}",
                        here.op, here.bits, here.val
                    );
                }
                if here.op == 0 {
                    /* literal */
                    mode = Mode::Lit;
                } else if here.op & 32 != 0 {
                    /* end of block */
                    back = -1;
                    mode = Mode::Type;
                } else if here.op & 64 != 0 {
                    msg = Some("invalid literal/length code");
                    mode = Mode::Bad;
                } else {
                    extra = (here.op & 15) as u32;
                    mode = Mode::Lenext;
                }
            }
            Mode::Lenext => {
                if extra != 0 {
                    needbits!('outer, extra);
                    length += bbits!(extra);
                    dropbits!(extra);
                    back += extra as i32;
                }
                was = length;
                mode = Mode::Dist;
            }
            Mode::Dist => {
                let mut here;
                loop {
                    here = distcode[bbits!(distbits) as usize];
                    if (here.bits as u32) <= bits {
                        break;
                    }
                    pullbyte!('outer);
                }
                if (here.op & 0xf0) == 0 {
                    let last_entry = here;
                    loop {
                        let idx = (last_entry.val as usize)
                            + (((hold >> last_entry.bits) & ((1u64 << (last_entry.op & 15)) - 1))
                                as usize);
                        here = distcode[idx];
                        if (last_entry.bits as u32 + here.bits as u32) <= bits {
                            break;
                        }
                        pullbyte!('outer);
                    }
                    dropbits!(last_entry.bits as u32);
                    back += last_entry.bits as i32;
                }
                dropbits!(here.bits as u32);
                back += here.bits as i32;
                if std::env::var("ZLIB_TRACE").is_ok() {
                    eprintln!(
                        "DIST put={put} op={} bits={} val={} hold_bits={bits}",
                        here.op, here.bits, here.val
                    );
                }
                if here.op & 64 != 0 {
                    msg = Some("invalid distance code");
                    mode = Mode::Bad;
                } else {
                    offset = here.val as u32;
                    extra = (here.op & 15) as u32;
                    mode = Mode::Distext;
                }
            }
            Mode::Distext => {
                if extra != 0 {
                    needbits!('outer, extra);
                    offset += bbits!(extra);
                    dropbits!(extra);
                    back += extra as i32;
                }
                mode = Mode::Match;
            }
            Mode::Match => {
                if left == 0 {
                    leave = true;
                    break 'outer;
                }
                let produced = out - left;
                if std::env::var("ZLIB_TRACE").is_ok() {
                    eprintln!("MATCH put={put} offset={offset} length={length} produced={produced} wsize={wsize} whave={whave} wnext={wnext} window0={:?}", &window[..whave.min(40) as usize]);
                }
                if let Err(m) = copy_match(
                    output,
                    &mut put,
                    &mut left,
                    &window,
                    wsize,
                    whave,
                    wnext,
                    sane,
                    offset,
                    &mut length,
                    produced,
                ) {
                    msg = Some(m);
                    mode = Mode::Bad;
                    continue;
                }
                if length == 0 {
                    mode = Mode::Len;
                }
            }
            Mode::Lit => {
                if left == 0 {
                    leave = true;
                    break 'outer;
                }
                output[put] = length as u8;
                put += 1;
                left -= 1;
                mode = Mode::Len;
            }
            Mode::Check => {
                if wrap != 0 {
                    needbits!('outer, 32);
                    let produced = out - left;
                    if std::env::var("ZLIB_TRACE").is_ok() {
                        eprintln!("CHECK out={out} left={left} produced={produced} put={put} hold={hold:x} check={check:x} flags={flags}");
                    }
                    strm.total_out += produced as u64;
                    total += produced as u64;
                    if (wrap & 4) != 0 && produced != 0 {
                        let start = put - produced as usize;
                        check = if flags != 0 {
                            checksum::crc32(check as u32, &output[start..put]) as u64
                        } else {
                            checksum::adler32(check as u32, &output[start..put]) as u64
                        };
                        adler = check as u32;
                    }
                    if std::env::var("ZLIB_TRACE").is_ok() {
                        eprintln!(
                            "CHECK2 check={check:x} swap={:x}",
                            (hold >> 24) & 0xff
                                | ((hold >> 8) & 0xff00)
                                | ((hold & 0xff00) << 8)
                                | ((hold & 0xff) << 24)
                        );
                    }
                    if (wrap & 4) != 0
                        && ((if flags != 0 {
                            hold
                        } else {
                            (hold >> 24) & 0xff
                                | ((hold >> 8) & 0xff00)
                                | ((hold & 0xff00) << 8)
                                | ((hold & 0xff) << 24)
                        }) as u32)
                            != check as u32
                    {
                        msg = Some("incorrect data check");
                        mode = Mode::Bad;
                        continue;
                    }
                    initbits!();
                    out = left; /* reset produced tracker (the C does this
                                 * before the check comparison) */
                }
                mode = Mode::Length;
            }
            Mode::Length => {
                if wrap != 0 && flags != 0 {
                    needbits!('outer, 32);
                    if (wrap & 4) != 0 && (hold & 0xffff_ffff) != (total & 0xffff_ffff) {
                        msg = Some("incorrect length check");
                        mode = Mode::Bad;
                        continue;
                    }
                    initbits!();
                }
                mode = Mode::Done;
            }
            Mode::Done => {
                ret = Z_STREAM_END;
                leave = true;
                break 'outer;
            }
            Mode::Bad => {
                ret = Z_DATA_ERROR;
                leave = true;
                break 'outer;
            }
            Mode::Mem => {
                strm.state = super::deflate::StreamState::Inflate(state);
                return Z_MEM_ERROR;
            }
            Mode::Sync => {
                strm.state = super::deflate::StreamState::Inflate(state);
                return Z_STREAM_ERROR;
            }
        }
    }

    // ---- inf_leave ----
    let produced = out - left;
    let consumed = in0 - have;

    // The window update happens for the produced bytes when needed.
    if produced != 0 {
        let start = put - produced as usize;
        let produced_slice = &output[start..put];
        if wsize != 0
            || (!matches!(mode, Mode::Bad) && !(matches!(mode, Mode::Check) && flush != Z_FINISH))
        {
            let copy = produced;
            if updatewindow(
                &mut window,
                wbits,
                &mut wsize,
                &mut wnext,
                &mut whave,
                produced_slice,
                copy,
            ) != 0
            {
                state.mode = Mode::Mem;
                strm.state = super::deflate::StreamState::Inflate(state);
                return Z_MEM_ERROR;
            }
        }
    }

    strm.total_in += consumed as u64;
    strm.total_out += produced as u64;
    total += produced as u64;
    /* advance the buffer cursors (the C's next_in/next_out pointers); the
     * output cursor advances by the full `put` (the CHECK state resets the
     * produced tracker via `out = left`, so `produced` undercounts) */
    strm.next_in_pos += consumed as usize;
    strm.next_out_pos += put;

    if (wrap & 4) != 0 && produced != 0 {
        let start = put - produced as usize;
        check = if flags != 0 {
            checksum::crc32(check as u32, &output[start..put]) as u64
        } else {
            checksum::adler32(check as u32, &output[start..put]) as u64
        };
        adler = check as u32;
    }

    strm.data_type = bits as i32
        + if last != 0 { 64 } else { 0 }
        + if mode == Mode::Type { 128 } else { 0 }
        + if mode == Mode::Len_ || mode == Mode::Copy_ {
            256
        } else {
            0
        };

    strm.avail_in = have;
    strm.avail_out = left;
    strm.adler = adler;
    strm.msg = msg;

    // write back the state
    state.mode = mode;
    state.last = last;
    state.wrap = wrap;
    state.havedict = havedict;
    state.flags = flags;
    state.dmax = dmax;
    state.check = check;
    state.total = total;
    state.head = head;
    state.length = length;
    state.offset = offset;
    state.extra = extra;
    state.lenbits = lenbits;
    state.distbits = distbits;
    state.ncode = ncode;
    state.nlen = nlen;
    state.ndist = ndist;
    state.have = have_codes;
    state.next = next_codes;
    state.lens = lens;
    state.work = work;
    state.codes = codes;
    state.lencode = lencode;
    state.distcode = distcode;
    state.sane = sane;
    state.back = back;
    state.was = was;
    state.hold = hold;
    state.bits = bits;
    state.window = window;
    state.wsize = wsize;
    state.whave = whave;
    state.wnext = wnext;
    state.wbits = wbits;

    strm.state = super::deflate::StreamState::Inflate(state);

    if ((consumed == 0 && produced == 0) || flush == Z_FINISH) && ret == Z_OK {
        ret = Z_BUF_ERROR;
    }
    ret
}
