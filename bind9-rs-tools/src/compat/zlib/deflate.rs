//! deflate.c + compress.c + uncompr.c — the deflate encoder and the
//! one-shot compress/uncompress API (conservation port).
//!
//! This is the heart of byte-exact encoder output parity: the LZ77 hash
//! chain matcher (longest_match with the exact chain limit / good_match /
//! nice_match behavior), the per-level configuration table, lazy matching
//! (deflate_slow), the stored/fast/rle/huff strategies, fill_window with
//! the high-water zeroing, the zlib/gzip/raw wrappers (headers incl. the
//! FCHECK computation and gz_header fields, trailers), flush semantics
//! (Z_NO_FLUSH .. Z_TREES with the RANK ordering), and the return-code
//! discipline (Z_BUF_ERROR when no progress, Z_STREAM_END after Z_FINISH).
//!
//! The caller drives the stream exactly like the C API: `avail_in`/
//! `avail_out` are set before each call and the state machine consumes from
//! the front of the provided slices; `total_in`/`total_out`/`msg`/
//! `data_type`/`adler` are updated in place.  The internal pending_buf/
//! sym_buf overlay of the C is split into two buffers here (a layout-only
//! difference; the C's overlap analysis guarantees the same bytes are never
//! live in both at once, so separate buffers are behaviorally identical).

use super::checksum;
use super::trees::{
    put_byte, put_short, tr_align, tr_flush_block, tr_init, tr_stored_block, tr_tally_dist,
    tr_tally_lit, CtData, BL_CODES, D_CODES, LITERALS, L_CODES,
};
use crate::compat::zlib::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED,
    Z_FILTERED, Z_FINISH, Z_FIXED, Z_FULL_FLUSH, Z_HUFFMAN_ONLY, Z_NEED_DICT, Z_NO_FLUSH, Z_OK,
    Z_PARTIAL_FLUSH, Z_RLE, Z_STREAM_END, Z_STREAM_ERROR, Z_SYNC_FLUSH, Z_UNKNOWN, Z_VERSION_ERROR,
};

// ---------------------------------------------------------------------------
// Constants (deflate.h)
// ---------------------------------------------------------------------------

const HEAP_SIZE: usize = 2 * L_CODES + 1;
const MAX_BITS: usize = 15;

const INIT_STATE: u32 = 42;
const GZIP_STATE: u32 = 57;
const EXTRA_STATE: u32 = 69;
const NAME_STATE: u32 = 73;
const COMMENT_STATE: u32 = 91;
const HCRC_STATE: u32 = 103;
const BUSY_STATE: u32 = 113;
const FINISH_STATE: u32 = 666;

const MIN_MATCH: u32 = 3;
const MAX_MATCH: u32 = 258;
const MIN_LOOKAHEAD: u32 = MAX_MATCH + MIN_MATCH + 1;
const WIN_INIT: u32 = MAX_MATCH;
const MAX_STORED: u32 = 65535;
const PRESET_DICT: u32 = 0x20;
const OS_CODE: u8 = 3; /* Unix */

const DEF_MEM_LEVEL: u32 = 8;
const MAX_WBITS: u32 = 15;
const TOO_FAR: u32 = 4096;

/// `RANK(f)` — rank Z_BLOCK between Z_NO_FLUSH and Z_PARTIAL_FLUSH.
fn rank(f: i32) -> i32 {
    f * 2 - if f > 4 { 9 } else { 0 }
}

fn min_u32(a: u32, b: u32) -> u32 {
    if a > b {
        b
    } else {
        a
    }
}

// ---------------------------------------------------------------------------
// Configuration table (deflate.c)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum CompressFunc {
    Stored,
    Fast,
    Slow,
    Rle,
    Huff,
}

struct Config {
    good_length: u32,
    max_lazy: u32,
    nice_length: u32,
    max_chain: u32,
    func: CompressFunc,
}

static CONFIGURATION_TABLE: [Config; 10] = [
    Config {
        good_length: 0,
        max_lazy: 0,
        nice_length: 0,
        max_chain: 0,
        func: CompressFunc::Stored,
    },
    Config {
        good_length: 4,
        max_lazy: 4,
        nice_length: 8,
        max_chain: 4,
        func: CompressFunc::Fast,
    },
    Config {
        good_length: 4,
        max_lazy: 5,
        nice_length: 16,
        max_chain: 8,
        func: CompressFunc::Fast,
    },
    Config {
        good_length: 4,
        max_lazy: 6,
        nice_length: 32,
        max_chain: 32,
        func: CompressFunc::Fast,
    },
    Config {
        good_length: 4,
        max_lazy: 4,
        nice_length: 16,
        max_chain: 16,
        func: CompressFunc::Slow,
    },
    Config {
        good_length: 8,
        max_lazy: 16,
        nice_length: 32,
        max_chain: 32,
        func: CompressFunc::Slow,
    },
    Config {
        good_length: 8,
        max_lazy: 16,
        nice_length: 128,
        max_chain: 128,
        func: CompressFunc::Slow,
    },
    Config {
        good_length: 8,
        max_lazy: 32,
        nice_length: 128,
        max_chain: 256,
        func: CompressFunc::Slow,
    },
    Config {
        good_length: 32,
        max_lazy: 128,
        nice_length: 258,
        max_chain: 1024,
        func: CompressFunc::Slow,
    },
    Config {
        good_length: 32,
        max_lazy: 258,
        nice_length: 258,
        max_chain: 4096,
        func: CompressFunc::Slow,
    },
];

// ---------------------------------------------------------------------------
// Stream state
// ---------------------------------------------------------------------------

pub(crate) enum StreamState {
    None,
    Deflate(Box<DeflateState>),
    Inflate(Box<crate::compat::zlib::inflate::InflateState>),
}

impl Default for StreamState {
    fn default() -> Self {
        StreamState::None
    }
}

/// The public stream mirroring `z_stream`'s observable fields.  The caller
/// manages `avail_in`/`avail_out` and passes the per-call buffers, exactly
/// like the C API.  `next_in_pos`/`next_out_pos` are the buffer cursors the
/// gz* layer tracks (the C's next_in/next_out pointers).
#[derive(Default)]
pub struct ZStream {
    pub avail_in: u32,
    pub total_in: u64,
    pub avail_out: u32,
    pub total_out: u64,
    pub msg: Option<&'static str>,
    pub data_type: i32,
    pub adler: u32,
    pub(crate) state: StreamState,
    pub(crate) next_in_pos: usize,
    pub(crate) next_out_pos: usize,
}

/// The gzip header (`gz_header` in zlib.h).  name/comment are stored without
/// their trailing NUL (the C stores NUL-terminated strings; the writer
/// appends the NUL byte when emitting).  `extra`/`name`/`comment` Vecs are
/// pre-sized by the caller to their `*_max` capacity; the *_max fields mirror
/// the C's gz_header (the Vec lengths are the capacities).
#[derive(Debug, Clone, Default)]
pub struct GzHeader {
    pub text: bool,
    pub time: u32,
    pub xflags: i32,
    pub os: i32,
    pub extra: Option<Vec<u8>>,
    pub extra_len: u32,
    pub extra_max: u32,
    pub name: Option<Vec<u8>>,
    pub name_max: u32,
    pub comment: Option<Vec<u8>>,
    pub comm_max: u32,
    pub hcrc: bool,
    pub done: i32,
}

// ---------------------------------------------------------------------------
// deflate_state
// ---------------------------------------------------------------------------

/// The internal compression state (deflate.h).
pub struct DeflateState {
    pub status: u32,
    pub pending_buf: Vec<u8>,
    pub pending: u32,
    pub pending_out: u32,
    pub wrap: i32,
    pub gzhead: Option<GzHeader>,
    pub gzindex: u32,
    pub method: u8,
    pub last_flush: i32,

    pub w_size: u32,
    pub w_bits: u32,
    pub w_mask: u32,

    pub window: Vec<u8>,
    pub window_size: u64,
    pub prev: Vec<u16>,
    pub head: Vec<u16>,

    pub ins_h: u32,
    pub hash_size: u32,
    pub hash_bits: u32,
    pub hash_mask: u32,
    pub hash_shift: u32,

    pub block_start: i64,
    pub match_length: u32,
    pub prev_match: u32,
    pub match_available: bool,
    pub strstart: u32,
    pub match_start: u32,
    pub lookahead: u32,
    pub prev_length: u32,

    pub max_chain_length: u32,
    pub max_lazy_match: u32,
    pub level: i32,
    pub strategy: i32,
    pub good_match: u32,
    pub nice_match: i32,

    pub dyn_ltree: Vec<CtData>,
    pub dyn_dtree: Vec<CtData>,
    pub bl_tree: Vec<CtData>,
    pub bl_count: [u32; MAX_BITS + 1],
    pub heap: Vec<usize>,
    pub heap_len: usize,
    pub heap_max: usize,
    pub depth: Vec<u8>,

    pub sym_buf: Vec<u8>,
    pub lit_bufsize: u32,
    pub sym_next: u32,
    pub sym_end: u32,
    pub opt_len: u64,
    pub static_len: u64,
    pub matches: u32,
    pub insert: u32,

    pub bi_buf: u16,
    pub bi_valid: u32,
    pub high_water: u64,

    pub l_max_code: usize,
    pub d_max_code: usize,
    pub strm_data_type: i32,

    /// Bytes produced by a `deflateParams` internal Z_BLOCK flush, pending
    /// emission at the start of the next `deflate` call (the Rust analogue of
    /// the C writing the flush into the caller's next_out).
    pub params_flush: Vec<u8>,
}

impl DeflateState {
    fn new() -> Self {
        DeflateState {
            status: INIT_STATE,
            pending_buf: Vec::new(),
            pending: 0,
            pending_out: 0,
            wrap: 1,
            gzhead: None,
            gzindex: 0,
            method: Z_DEFLATED as u8,
            last_flush: -2,
            w_size: 0,
            w_bits: 0,
            w_mask: 0,
            window: Vec::new(),
            window_size: 0,
            prev: Vec::new(),
            head: Vec::new(),
            ins_h: 0,
            hash_size: 0,
            hash_bits: 0,
            hash_mask: 0,
            hash_shift: 0,
            block_start: 0,
            match_length: MIN_MATCH - 1,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: MIN_MATCH - 1,
            max_chain_length: 0,
            max_lazy_match: 0,
            level: 0,
            strategy: Z_DEFAULT_STRATEGY,
            good_match: 0,
            nice_match: 0,
            dyn_ltree: vec![CtData::new(); HEAP_SIZE],
            dyn_dtree: vec![CtData::new(); 2 * D_CODES + 1],
            bl_tree: vec![CtData::new(); 2 * BL_CODES + 1],
            bl_count: [0; MAX_BITS + 1],
            heap: vec![0; HEAP_SIZE],
            heap_len: 0,
            heap_max: 0,
            depth: vec![0; 2 * L_CODES + 1],
            sym_buf: Vec::new(),
            lit_bufsize: 0,
            sym_next: 0,
            sym_end: 0,
            opt_len: 0,
            static_len: 0,
            matches: 0,
            insert: 0,
            bi_buf: 0,
            bi_valid: 0,
            high_water: 0,
            l_max_code: 0,
            d_max_code: 0,
            strm_data_type: Z_UNKNOWN,
            params_flush: Vec::new(),
        }
    }
}

fn deflate_state_check(strm: &ZStream) -> bool {
    matches!(strm.state, StreamState::Deflate(_))
}

// ---------------------------------------------------------------------------
// Hash macros (deflate.c)
// ---------------------------------------------------------------------------

#[inline]
fn update_hash(s: &DeflateState, h: u32, c: u8) -> u32 {
    ((h << s.hash_shift) ^ (c as u32)) & s.hash_mask
}

fn clear_hash(s: &mut DeflateState) {
    let n = s.hash_size as usize;
    s.head[n - 1] = 0;
    for x in s.head[..n - 1].iter_mut() {
        *x = 0;
    }
}

fn slide_hash(s: &mut DeflateState) {
    let wsize = s.w_size;
    let mut n = s.hash_size;
    let mut p = n as usize;
    while n > 0 {
        p -= 1;
        let m = s.head[p];
        s.head[p] = if m >= wsize as u16 {
            m - wsize as u16
        } else {
            0
        };
        n -= 1;
    }
    let mut n = wsize;
    let mut p = n as usize;
    while n > 0 {
        p -= 1;
        let m = s.prev[p];
        s.prev[p] = if m >= wsize as u16 {
            m - wsize as u16
        } else {
            0
        };
        n -= 1;
    }
}

// ---------------------------------------------------------------------------
// IO context, read_buf, flush_pending, fill_window
// ---------------------------------------------------------------------------

/// The IO context for one deflate() call.  `next_in`/`next_out` are the full
/// per-call buffers; `in_pos`/`out_pos` track consumption (mirroring the C's
/// advancing `next_in`/`next_out` pointers, which the C also uses to read
/// back already-consumed input in deflate_stored's window update).
pub(crate) struct Io<'a> {
    pub next_in: &'a [u8],
    pub in_pos: usize,
    pub avail_in: u32,
    pub total_in: u64,
    pub next_out: &'a mut [u8],
    pub out_pos: usize,
    pub avail_out: u32,
    pub total_out: u64,
    pub adler: u32,
    pub data_type: i32,
    pub msg: Option<&'static str>,
    pub wrap: i32,
    pub status: u32,
}

/// `read_buf` — copy up to `size` bytes from the caller's input into `buf`,
/// updating the checksum and totals (deflate.c).
fn read_buf(io: &mut Io, buf: &mut [u8]) -> u32 {
    let mut len = io.avail_in;
    if len > buf.len() as u32 {
        len = buf.len() as u32;
    }
    if len == 0 {
        return 0;
    }
    io.avail_in -= len;
    let take = len as usize;
    buf[..take].copy_from_slice(&io.next_in[io.in_pos..io.in_pos + take]);
    if io.wrap == 1 {
        io.adler = checksum::adler32(io.adler, &io.next_in[io.in_pos..io.in_pos + take]);
    } else if io.wrap == 2 {
        io.adler = checksum::crc32(io.adler, &io.next_in[io.in_pos..io.in_pos + take]);
    }
    io.in_pos += take;
    io.total_in += len as u64;
    len
}

/// `putShortMSB` (deflate.c) — put a 16-bit value MSB first.
fn put_short_msb(s: &mut DeflateState, b: u32) {
    put_byte(s, ((b >> 8) & 0xff) as u8);
    put_byte(s, (b & 0xff) as u8);
}

/// `flush_pending` — copy pending output to the caller's output (deflate.c).
fn flush_pending(s: &mut DeflateState, io: &mut Io) {
    super::trees::tr_flush_bits(s);
    let mut len = s.pending;
    if len > io.avail_out {
        len = io.avail_out;
    }
    if len == 0 {
        return;
    }
    let start = s.pending_out as usize;
    let take = len as usize;
    io.next_out[io.out_pos..io.out_pos + take].copy_from_slice(&s.pending_buf[start..start + take]);
    s.pending_out += len;
    io.out_pos += take;
    io.total_out += len as u64;
    io.avail_out -= len;
    s.pending -= len;
    if s.pending == 0 {
        s.pending_out = 0;
    }
}

/// `fill_window` — refill the window when lookahead is insufficient.
#[allow(clippy::too_many_lines)]
fn fill_window(s: &mut DeflateState, io: &mut Io) {
    let wsize = s.w_size;

    loop {
        let mut more: u32 = (s.window_size as u32) - s.lookahead - s.strstart;

        /* If the window is almost full and there is insufficient lookahead,
         * move the upper half to the lower one to make room. */
        if s.strstart >= wsize + (wsize - MIN_LOOKAHEAD) {
            let copy = wsize - more;
            s.window
                .copy_within(wsize as usize..(wsize + copy) as usize, 0);
            s.match_start -= wsize;
            s.strstart -= wsize;
            s.block_start -= wsize as i64;
            if s.insert > s.strstart {
                s.insert = s.strstart;
            }
            slide_hash(s);
            more += wsize;
        }
        if io.avail_in == 0 {
            break;
        }

        let n = {
            let dst = (s.strstart + s.lookahead) as usize;
            let cap = more as usize;
            let available = s.window.len() - dst;
            let cap = min_u32(cap as u32, available as u32) as usize;
            read_buf(io, &mut s.window[dst..dst + cap])
        };
        s.lookahead += n;

        /* Initialize the hash value now that we have some input: */
        if s.lookahead + s.insert >= MIN_MATCH {
            let mut str = s.strstart - s.insert;
            s.ins_h = s.window[str as usize] as u32;
            s.ins_h = update_hash(s, s.ins_h, s.window[(str + 1) as usize]);
            while s.insert != 0 {
                s.ins_h = update_hash(s, s.ins_h, s.window[(str + MIN_MATCH - 1) as usize]);
                s.prev[(str & s.w_mask) as usize] = s.head[s.ins_h as usize];
                s.head[s.ins_h as usize] = str as u16;
                str += 1;
                s.insert -= 1;
                if s.lookahead + s.insert < MIN_MATCH {
                    break;
                }
            }
        }
        /* If the whole input has less than MIN_MATCH bytes, ins_h is garbage,
         * but this is not important since only literal bytes will be emitted.
         */

        if !(s.lookahead < MIN_LOOKAHEAD && io.avail_in != 0) {
            break;
        }
    }

    /* Zero WIN_INIT bytes after the current data (memory-checker
     * determinism; the C does this so longest_match's reads past lookahead
     * are well-defined). */
    if s.high_water < s.window_size {
        let curr = s.strstart as u64 + s.lookahead as u64;
        let mut init: u64;
        if s.high_water < curr {
            init = s.window_size - curr;
            if init > WIN_INIT as u64 {
                init = WIN_INIT as u64;
            }
            let base = curr as usize;
            s.window[base..base + init as usize].fill(0);
            s.high_water = curr + init;
        } else if s.high_water < curr + WIN_INIT as u64 {
            init = curr + WIN_INIT as u64 - s.high_water;
            if init > s.window_size - s.high_water {
                init = s.window_size - s.high_water;
            }
            let base = s.high_water as usize;
            s.window[base..base + init as usize].fill(0);
            s.high_water += init;
        }
    }
}

// ---------------------------------------------------------------------------
// longest_match
// ---------------------------------------------------------------------------

/// `longest_match(s, cur_match)` — the byte-wise variant.  The C's
/// UNALIGNED_OK path is a speed-only optimization that selects the same
/// longest match; the byte-wise loop is behaviorally identical.
#[allow(clippy::too_many_lines)]
fn longest_match(s: &mut DeflateState, cur_match: u32) -> u32 {
    let strstart = s.strstart as usize;
    let scan = &s.window[strstart..];
    let mut best_len = s.prev_length as usize; /* best match length so far */
    let mut nice_match = s.nice_match as usize; /* stop if match long enough */
    let limit: u32 = if s.strstart > s.w_size - MIN_LOOKAHEAD {
        s.strstart - (s.w_size - MIN_LOOKAHEAD)
    } else {
        0
    };
    let wmask = s.w_mask as usize;
    let mut chain_length = s.max_chain_length;
    let strend = strstart + MAX_MATCH as usize;

    /* Do not waste too much time if we already have a good match: */
    if s.prev_length >= s.good_match {
        chain_length >>= 2;
    }
    /* Do not look for matches beyond the end of the input. This is necessary
     * to make deflate deterministic. */
    if nice_match > s.lookahead as usize {
        nice_match = s.lookahead as usize;
    }

    let mut cur = cur_match;
    loop {
        let match_off = cur as usize;
        let m = &s.window[match_off..];

        /* Skip to next match if the match length cannot increase or if the
         * match length is less than 2. */
        if m[best_len] != scan[best_len]
            || m[best_len.saturating_sub(1)] != scan[best_len.saturating_sub(1)]
            || m[0] != scan[0]
            || m[1] != scan[1]
        {
            cur = s.prev[cur as usize & wmask] as u32;
            if cur <= limit || chain_length == 0 {
                break;
            }
            chain_length -= 1;
            continue;
        }

        /* It is not necessary to compare scan[2] and match[2] since they are
         * always equal when the other bytes match, given that the hash keys
         * are equal and that HASH_BITS >= 8. */
        let mut scan_i = 2usize;
        let mut match_i = 2usize;

        /* Compare up to strend in 8-byte steps (the window is zero-padded
         * past the input via high_water, so reads past lookahead are
         * deterministic zeros exactly like the C). */
        loop {
            let a = &s.window[strstart + scan_i..];
            let b = &s.window[match_off + match_i..];
            let mut matched = 0usize;
            while matched < 8 && (strstart + scan_i + matched) < strend {
                if a[matched] != b[matched] {
                    break;
                }
                matched += 1;
            }
            scan_i += matched;
            match_i += matched;
            if matched < 8 || (strstart + scan_i) >= strend {
                break;
            }
        }
        let len = MAX_MATCH as usize - (strend - (strstart + scan_i));

        if len > best_len {
            s.match_start = cur;
            best_len = len;
            if len >= nice_match {
                break;
            }
        }
        cur = s.prev[cur as usize & wmask] as u32;
        if cur <= limit || chain_length == 0 {
            break;
        }
        chain_length -= 1;
    }

    if best_len <= s.lookahead as usize {
        best_len as u32
    } else {
        s.lookahead
    }
}

// ---------------------------------------------------------------------------
// Block state and the compression functions
// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
enum BlockState {
    NeedMore,
    BlockDone,
    FinishStarted,
    FinishDone,
}

/// `FLUSH_BLOCK(s, last)` — flush the current block, returning the early-exit
/// state when avail_out hits zero (deflate.c macro).
fn flush_block(s: &mut DeflateState, io: &mut Io, last: bool) -> Option<BlockState> {
    let stored: Vec<u8> = if s.block_start >= 0 {
        s.window[s.block_start as usize..].to_vec()
    } else {
        Vec::new()
    };
    let stored_len = (s.strstart as i64 - s.block_start) as u32;
    tr_flush_block(s, &stored, stored_len, last);
    s.block_start = s.strstart as i64;
    flush_pending(s, io);
    if io.avail_out == 0 {
        Some(if last {
            BlockState::FinishStarted
        } else {
            BlockState::NeedMore
        })
    } else {
        None
    }
}

/// `deflate_stored` (deflate.c).
#[allow(clippy::too_many_lines)]
fn deflate_stored(s: &mut DeflateState, io: &mut Io, flush: i32) -> BlockState {
    /* Smallest worthy block size when not flushing or finishing. */
    let mut min_block = min_u32(s.pending_buf.len() as u32 - 5, s.w_size);

    let mut last = 0u32;
    let used = io.avail_in;
    loop {
        /* Set len to the maximum size block that we can copy directly. */
        let mut len = MAX_STORED;
        let mut have = (s.bi_valid + 42) >> 3; /* number of header bytes */
        if io.avail_out < have {
            break; /* need room for header */
        }
        have = io.avail_out - have;
        let left = s.strstart - s.block_start as u32; /* bytes left in window */
        if len > left + io.avail_in {
            len = left + io.avail_in;
        }
        if len > have {
            len = have;
        }

        if len < min_block
            && ((len == 0 && flush != Z_FINISH) || flush == Z_NO_FLUSH || len != left + io.avail_in)
        {
            break;
        }

        last = if flush == Z_FINISH && len == left + io.avail_in {
            1
        } else {
            0
        };
        tr_stored_block(s, &[], 0, last != 0);

        /* Replace the lengths in the dummy stored block with len. */
        let p = s.pending as usize;
        s.pending_buf[p - 4] = len as u8;
        s.pending_buf[p - 3] = (len >> 8) as u8;
        s.pending_buf[p - 2] = (!len) as u8;
        s.pending_buf[p - 1] = ((!len) >> 8) as u8;

        flush_pending(s, io);

        /* Copy uncompressed bytes from the window to next_out. */
        if left != 0 {
            let mut l = left;
            if l > len {
                l = len;
            }
            let src = s.block_start as usize;
            let take = l as usize;
            io.next_out[io.out_pos..io.out_pos + take].copy_from_slice(&s.window[src..src + take]);
            io.out_pos += take;
            io.total_out += l as u64;
            io.avail_out -= l;
            s.block_start += l as i64;
            len -= l;
        }

        /* Copy uncompressed bytes directly from next_in to next_out. */
        if len != 0 {
            let take = len as usize;
            let start = io.in_pos;
            io.next_out[io.out_pos..io.out_pos + take]
                .copy_from_slice(&io.next_in[start..start + take]);
            if io.wrap == 1 {
                io.adler = checksum::adler32(io.adler, &io.next_in[start..start + take]);
            } else if io.wrap == 2 {
                io.adler = checksum::crc32(io.adler, &io.next_in[start..start + take]);
            }
            io.in_pos += take;
            io.avail_in -= len;
            io.total_in += len as u64;
            io.out_pos += take;
            io.total_out += len as u64;
            io.avail_out -= len;
        }

        if last != 0 {
            break;
        }
    }

    /* Update the sliding window with the last s->w_size bytes of the copied
     * data. */
    let used_delta = used - io.avail_in; /* number of input bytes directly copied */
    if used_delta != 0 {
        if used_delta >= s.w_size {
            /* supplant the previous history */
            s.matches = 2; /* clear hash */
            let end = io.in_pos;
            s.window[..s.w_size as usize]
                .copy_from_slice(&io.next_in[end - s.w_size as usize..end]);
            s.strstart = s.w_size;
            s.insert = s.strstart;
        } else {
            if s.window_size as u32 - s.strstart <= used_delta {
                /* Slide the window down. */
                s.strstart -= s.w_size;
                let n = s.strstart as usize;
                s.window
                    .copy_within(s.w_size as usize..(s.w_size as usize + n), 0);
                if s.matches < 2 {
                    s.matches += 1;
                }
                if s.insert > s.strstart {
                    s.insert = s.strstart;
                }
            }
            let end = io.in_pos;
            let dst = s.strstart as usize;
            let take = used_delta as usize;
            s.window[dst..dst + take].copy_from_slice(&io.next_in[end - take..end]);
            s.strstart += used_delta;
            s.insert += min_u32(used_delta, s.w_size - s.insert);
        }
        s.block_start = s.strstart as i64;
    }
    if s.high_water < s.strstart as u64 {
        s.high_water = s.strstart as u64;
    }

    if last != 0 {
        return BlockState::FinishDone;
    }

    if flush != Z_NO_FLUSH
        && flush != Z_FINISH
        && io.avail_in == 0
        && s.strstart as i64 == s.block_start
    {
        return BlockState::BlockDone;
    }

    /* Fill the window with any remaining input. */
    let mut have = s.window_size as u32 - s.strstart;
    if io.avail_in > have && s.block_start >= s.w_size as i64 {
        s.block_start -= s.w_size as i64;
        s.strstart -= s.w_size;
        let n = s.strstart as usize;
        s.window
            .copy_within(s.w_size as usize..(s.w_size as usize + n), 0);
        if s.matches < 2 {
            s.matches += 1;
        }
        have += s.w_size;
        if s.insert > s.strstart {
            s.insert = s.strstart;
        }
    }
    if have > io.avail_in {
        have = io.avail_in;
    }
    if have != 0 {
        let dst = s.strstart as usize;
        let take = have as usize;
        read_buf(io, &mut s.window[dst..dst + take]);
        s.strstart += have;
        s.insert += min_u32(have, s.w_size - s.insert);
    }
    if s.high_water < s.strstart as u64 {
        s.high_water = s.strstart as u64;
    }

    /* Write a stored block to pending if we have enough input for a worthy
     * block, or if flushing and there is enough room. */
    have = (s.bi_valid + 42) >> 3;
    have = min_u32(s.pending_buf.len() as u32 - have, MAX_STORED);
    min_block = min_u32(have, s.w_size);
    let left = s.strstart - s.block_start as u32;
    if left >= min_block
        || ((left != 0 || flush == Z_FINISH)
            && flush != Z_NO_FLUSH
            && io.avail_in == 0
            && left <= have)
    {
        let len = min_u32(left, have);
        let is_last = flush == Z_FINISH && io.avail_in == 0 && len == left;
        let start = s.block_start as usize;
        let take = len as usize;
        let window_chunk = s.window[start..start + take].to_vec();
        tr_stored_block(s, &window_chunk, len, is_last);
        s.block_start += len as i64;
        flush_pending(s, io);
        if is_last {
            return BlockState::FinishStarted;
        }
    }

    BlockState::NeedMore
}

/// `deflate_fast` (deflate.c).
#[allow(clippy::too_many_lines)]
fn deflate_fast(s: &mut DeflateState, io: &mut Io, flush: i32) -> BlockState {
    loop {
        if s.lookahead < MIN_LOOKAHEAD {
            fill_window(s, io);
            if s.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                return BlockState::NeedMore;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        /* Insert the string window[strstart .. strstart + 2] in the
         * dictionary, and set hash_head to the head of the hash chain: */
        let mut hash_head: u32 = 0;
        let mut bflush;
        if s.lookahead >= MIN_MATCH {
            s.ins_h = update_hash(s, s.ins_h, s.window[(s.strstart + MIN_MATCH - 1) as usize]);
            hash_head = s.head[s.ins_h as usize] as u32;
            s.prev[(s.strstart & s.w_mask) as usize] = hash_head as u16;
            s.head[s.ins_h as usize] = s.strstart as u16;
        }

        /* Find the longest match, discarding those <= prev_length. */
        if hash_head != 0 && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD {
            s.match_length = longest_match(s, hash_head);
        }
        if s.match_length >= MIN_MATCH {
            bflush = tr_tally_dist(s, s.strstart - s.match_start, s.match_length - MIN_MATCH);
            s.lookahead -= s.match_length;

            /* Insert new strings in the hash table only if the match length
             * is not too large. */
            if s.match_length <= s.max_lazy_match && s.lookahead >= MIN_MATCH {
                s.match_length -= 1; /* string at strstart already in table */
                while s.match_length != 0 {
                    s.strstart += 1;
                    s.ins_h =
                        update_hash(s, s.ins_h, s.window[(s.strstart + MIN_MATCH - 1) as usize]);
                    s.prev[(s.strstart & s.w_mask) as usize] = s.head[s.ins_h as usize];
                    s.head[s.ins_h as usize] = s.strstart as u16;
                    s.match_length -= 1;
                }
                s.strstart += 1;
            } else {
                s.strstart += s.match_length;
                s.match_length = 0;
                s.ins_h = s.window[s.strstart as usize] as u32;
                s.ins_h = update_hash(s, s.ins_h, s.window[(s.strstart + 1) as usize]);
            }
        } else {
            /* No match, output a literal byte */
            bflush = tr_tally_lit(s, s.window[s.strstart as usize]);
            s.lookahead -= 1;
            s.strstart += 1;
        }
        if bflush {
            if let Some(st) = flush_block(s, io, false) {
                return st;
            }
        }
    }

    /* (loop exits via break when lookahead == 0) */
    s.insert = if s.strstart < MIN_MATCH - 1 {
        s.strstart
    } else {
        MIN_MATCH - 1
    };
    if flush == Z_FINISH {
        flush_block(s, io, true);
        return BlockState::FinishDone;
    }
    if s.sym_next != 0 {
        flush_block(s, io, false);
    }
    BlockState::BlockDone
}

/// `deflate_slow` (deflate.c) — the lazy-match path for levels 4..9.
#[allow(clippy::too_many_lines)]
fn deflate_slow(s: &mut DeflateState, io: &mut Io, flush: i32) -> BlockState {
    loop {
        if s.lookahead < MIN_LOOKAHEAD {
            fill_window(s, io);
            if s.lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH {
                return BlockState::NeedMore;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        /* Insert the string window[strstart .. strstart + 2] in the
         * dictionary, and set hash_head to the head of the hash chain: */
        let mut hash_head: u32 = 0;
        let mut bflush;
        if s.lookahead >= MIN_MATCH {
            s.ins_h = update_hash(s, s.ins_h, s.window[(s.strstart + MIN_MATCH - 1) as usize]);
            hash_head = s.head[s.ins_h as usize] as u32;
            s.prev[(s.strstart & s.w_mask) as usize] = hash_head as u16;
            s.head[s.ins_h as usize] = s.strstart as u16;
        }

        /* Find the longest match, discarding those <= prev_length. */
        s.prev_length = s.match_length;
        s.prev_match = s.match_start;
        s.match_length = MIN_MATCH - 1;

        if hash_head != 0
            && s.prev_length < s.max_lazy_match
            && s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD
        {
            s.match_length = longest_match(s, hash_head);

            if s.match_length <= 5
                && (s.strategy == Z_FILTERED
                    || (s.match_length == MIN_MATCH && s.strstart - s.match_start > TOO_FAR))
            {
                /* If prev_match is also MIN_MATCH, match_start is garbage
                 * but we will ignore the current match anyway. */
                s.match_length = MIN_MATCH - 1;
            }
        }
        /* If there was a match at the previous step and the current
         * match is not better, output the previous match: */
        if s.prev_length >= MIN_MATCH && s.match_length <= s.prev_length {
            let max_insert = s.strstart + s.lookahead - MIN_MATCH;
            /* Do not insert strings in hash table beyond this. */

            bflush = tr_tally_dist(s, s.strstart - 1 - s.prev_match, s.prev_length - MIN_MATCH);

            /* Insert in hash table all strings up to the end of the match. */
            s.lookahead -= s.prev_length - 1;
            s.prev_length -= 2;
            while s.prev_length != 0 {
                s.strstart += 1;
                if s.strstart <= max_insert {
                    s.ins_h =
                        update_hash(s, s.ins_h, s.window[(s.strstart + MIN_MATCH - 1) as usize]);
                    s.prev[(s.strstart & s.w_mask) as usize] = s.head[s.ins_h as usize];
                    s.head[s.ins_h as usize] = s.strstart as u16;
                }
                s.prev_length -= 1;
            }
            s.match_available = false;
            s.match_length = MIN_MATCH - 1;
            s.strstart += 1;

            if bflush {
                if let Some(st) = flush_block(s, io, false) {
                    return st;
                }
            }
        } else if s.match_available {
            /* If there was no match at the previous position, output a
             * single literal. */
            bflush = tr_tally_lit(s, s.window[(s.strstart - 1) as usize]);
            if bflush {
                let stored: Vec<u8> = if s.block_start >= 0 {
                    s.window[s.block_start as usize..].to_vec()
                } else {
                    Vec::new()
                };
                tr_flush_block(
                    s,
                    &stored,
                    (s.strstart as i64 - s.block_start) as u32,
                    false,
                );
                s.block_start = s.strstart as i64;
                flush_pending(s, io);
            }
            s.strstart += 1;
            s.lookahead -= 1;
            if io.avail_out == 0 {
                return BlockState::NeedMore;
            }
        } else {
            /* There is no previous match to compare with, wait for
             * the next step to decide. */
            s.match_available = true;
            s.strstart += 1;
            s.lookahead -= 1;
        }
    }

    if s.match_available {
        let _ = tr_tally_lit(s, s.window[(s.strstart - 1) as usize]);
        s.match_available = false;
    }
    s.insert = if s.strstart < MIN_MATCH - 1 {
        s.strstart
    } else {
        MIN_MATCH - 1
    };
    if flush == Z_FINISH {
        flush_block(s, io, true);
        return BlockState::FinishDone;
    }
    if s.sym_next != 0 {
        flush_block(s, io, false);
    }
    BlockState::BlockDone
}

/// `deflate_rle` (deflate.c) — run-length encoding (distance 1 only).
fn deflate_rle(s: &mut DeflateState, io: &mut Io, flush: i32) -> BlockState {
    loop {
        /* Make sure that we always have enough lookahead. */
        if s.lookahead <= MAX_MATCH {
            fill_window(s, io);
            if s.lookahead <= MAX_MATCH && flush == Z_NO_FLUSH {
                return BlockState::NeedMore;
            }
            if s.lookahead == 0 {
                break; /* flush the current block */
            }
        }

        /* See how many times the previous byte repeats */
        s.match_length = 0;
        let mut bflush;
        if s.lookahead >= MIN_MATCH && s.strstart > 0 {
            let mut scan = (s.strstart - 1) as usize;
            let prev = s.window[scan];
            scan += 1;
            if prev == s.window[scan] && prev == s.window[scan + 1] && prev == s.window[scan + 2] {
                let strend = s.strstart as usize + MAX_MATCH as usize;
                loop {
                    let a = &s.window[scan..];
                    let mut matched = 0usize;
                    while matched < 8 && (scan + matched) < strend {
                        if a[matched] != prev {
                            break;
                        }
                        matched += 1;
                    }
                    scan += matched;
                    if matched < 8 || scan >= strend {
                        break;
                    }
                }
                s.match_length = MAX_MATCH - (strend as u32 - scan as u32);
                if s.match_length > s.lookahead {
                    s.match_length = s.lookahead;
                }
            }
        }

        /* Emit match if have run of MIN_MATCH or longer, else emit literal */
        if s.match_length >= MIN_MATCH {
            bflush = tr_tally_dist(s, 1, s.match_length - MIN_MATCH);
            s.lookahead -= s.match_length;
            s.strstart += s.match_length;
            s.match_length = 0;
        } else {
            /* No match, output a literal byte */
            bflush = tr_tally_lit(s, s.window[s.strstart as usize]);
            s.lookahead -= 1;
            s.strstart += 1;
        }
        if bflush {
            if let Some(st) = flush_block(s, io, false) {
                return st;
            }
        }
    }

    /* (loop exits via break when lookahead == 0) */
    s.insert = 0;
    if flush == Z_FINISH {
        flush_block(s, io, true);
        return BlockState::FinishDone;
    }
    if s.sym_next != 0 {
        flush_block(s, io, false);
    }
    BlockState::BlockDone
}

/// `deflate_huff` (deflate.c) — Huffman-only (no matches).
fn deflate_huff(s: &mut DeflateState, io: &mut Io, flush: i32) -> BlockState {
    loop {
        /* Make sure that we have a literal to write. */
        if s.lookahead == 0 {
            fill_window(s, io);
            if s.lookahead == 0 {
                if flush == Z_NO_FLUSH {
                    return BlockState::NeedMore;
                }
                break; /* flush the current block */
            }
        }

        /* Output a literal byte */
        s.match_length = 0;
        let bflush = tr_tally_lit(s, s.window[s.strstart as usize]);
        s.lookahead -= 1;
        s.strstart += 1;
        if bflush {
            if let Some(st) = flush_block(s, io, false) {
                return st;
            }
        }
    }

    /* (loop exits via break when lookahead == 0) */
    s.insert = 0;
    if flush == Z_FINISH {
        flush_block(s, io, true);
        return BlockState::FinishDone;
    }
    if s.sym_next != 0 {
        flush_block(s, io, false);
    }
    BlockState::BlockDone
}

// ---------------------------------------------------------------------------
// deflateInit / deflateReset / lm_init
// ---------------------------------------------------------------------------

/// `deflateInit2_` — full initialization (deflate.c).
#[allow(clippy::too_many_lines)]
pub fn deflate_init2(
    strm: &mut ZStream,
    level: i32,
    method: i32,
    window_bits: i32,
    mem_level: i32,
    strategy: i32,
) -> i32 {
    let mut wrap = 1;

    if !matches!(strm.state, StreamState::None) {
        return Z_STREAM_ERROR;
    }
    // The C version-check (ZLIB_VERSION[0]) is always satisfied for the
    // pinned library; the stream_size check is an ABI guard not applicable
    // to the Rust API.

    strm.msg = None;
    let mut level = level;
    if level == Z_DEFAULT_COMPRESSION {
        level = 6;
    }
    let mut window_bits = window_bits;
    if window_bits < 0 {
        /* suppress zlib wrapper */
        wrap = 0;
        if window_bits < -15 {
            return Z_STREAM_ERROR;
        }
        window_bits = -window_bits;
    } else if window_bits > 15 {
        /* gzip wrapper */
        wrap = 2;
        window_bits -= 16;
    }
    if mem_level < 1
        || mem_level > 9
        || method != Z_DEFLATED
        || window_bits < 8
        || window_bits > 15
        || level < 0
        || level > 9
        || strategy < 0
        || strategy > Z_FIXED
        || (window_bits == 8 && wrap != 1)
    {
        return Z_STREAM_ERROR;
    }
    if window_bits == 8 {
        window_bits = 9; /* until 256-byte window bug fixed */
    }

    let mut s = DeflateState::new();
    s.status = INIT_STATE; /* to pass state test in deflateReset() */
    s.wrap = wrap;
    s.gzhead = None;
    s.w_bits = window_bits as u32;
    s.w_size = 1 << s.w_bits;
    s.w_mask = s.w_size - 1;

    s.hash_bits = (mem_level + 7) as u32;
    s.hash_size = 1 << s.hash_bits;
    s.hash_mask = s.hash_size - 1;
    s.hash_shift = (s.hash_bits + MIN_MATCH - 1) / MIN_MATCH;

    s.window = vec![0u8; (s.w_size * 2) as usize];
    s.prev = vec![0u16; s.w_size as usize];
    s.head = vec![0u16; s.hash_size as usize];

    s.high_water = 0;

    s.lit_bufsize = 1 << (mem_level + 6); /* 16K elements by default */

    s.pending_buf = vec![0u8; (s.lit_bufsize * 4) as usize];
    s.sym_buf = vec![0u8; (s.lit_bufsize * 3) as usize];
    s.sym_end = (s.lit_bufsize - 1) * 3;

    s.level = level;
    s.strategy = strategy;
    s.method = method as u8;

    strm.state = StreamState::Deflate(Box::new(s));
    deflate_reset(strm)
}

/// `deflateInit_` — default parameters.
pub fn deflate_init(strm: &mut ZStream, level: i32) -> i32 {
    deflate_init2(
        strm,
        level,
        Z_DEFLATED,
        MAX_WBITS as i32,
        DEF_MEM_LEVEL as i32,
        Z_DEFAULT_STRATEGY,
    )
}

/// `deflateResetKeep` (deflate.c).
pub fn deflate_reset_keep(strm: &mut ZStream) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    strm.total_in = 0;
    strm.total_out = 0;
    strm.msg = None;
    strm.data_type = Z_UNKNOWN;

    let s = match &mut strm.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.pending = 0;
    s.pending_out = 0;
    s.params_flush.clear(); /* stashed params-flush bytes belong to the old stream */

    if s.wrap < 0 {
        s.wrap = -s.wrap; /* was made negative by deflate(..., Z_FINISH); */
    }
    s.status = if s.wrap == 2 { GZIP_STATE } else { INIT_STATE };
    strm.adler = if s.wrap == 2 {
        checksum::crc32(0, &[])
    } else {
        checksum::adler32(0, &[])
    };
    s.last_flush = -2;

    tr_init(s);

    Z_OK
}

/// `lm_init` — initialize the "longest match" routines (deflate.c).
fn lm_init(s: &mut DeflateState) {
    s.window_size = 2 * s.w_size as u64;

    clear_hash(s);

    /* Set the default configuration parameters: */
    let cfg = &CONFIGURATION_TABLE[s.level as usize];
    s.max_lazy_match = cfg.max_lazy;
    s.good_match = cfg.good_length;
    s.nice_match = cfg.nice_length as i32;
    s.max_chain_length = cfg.max_chain;

    s.strstart = 0;
    s.block_start = 0;
    s.lookahead = 0;
    s.insert = 0;
    s.match_length = MIN_MATCH - 1;
    s.prev_length = MIN_MATCH - 1;
    s.match_available = false;
    s.ins_h = 0;
}

/// `deflateReset` (deflate.c).
pub fn deflate_reset(strm: &mut ZStream) -> i32 {
    let ret = deflate_reset_keep(strm);
    if ret == Z_OK {
        if let StreamState::Deflate(s) = &mut strm.state {
            lm_init(s);
        }
    }
    ret
}

/// `deflateSetDictionary` (deflate.c).
#[allow(clippy::too_many_lines)]
pub fn deflate_set_dictionary(strm: &mut ZStream, dictionary: &[u8]) -> i32 {
    if !deflate_state_check(strm) || dictionary.is_empty() {
        return Z_STREAM_ERROR;
    }
    let wrap;
    {
        let s = match &mut strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        wrap = s.wrap;
        if wrap == 2 || (wrap == 1 && s.status != INIT_STATE) || s.lookahead != 0 {
            return Z_STREAM_ERROR;
        }

        /* when using zlib wrappers, compute Adler-32 for provided dictionary */
        if wrap == 1 {
            strm.adler = checksum::adler32(strm.adler, dictionary);
        }
        s.wrap = 0; /* avoid computing Adler-32 in read_buf */
    }

    /* if dictionary would fill window, just replace the history */
    let mut dict = dictionary;
    let mut dl = dictionary.len() as u32;
    let w_size = {
        let s = match &mut strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        s.w_size
    };
    if dl >= w_size {
        let s = match &mut strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        if wrap == 0 {
            /* already empty otherwise */
            clear_hash(s);
            s.strstart = 0;
            s.block_start = 0;
            s.insert = 0;
        }
        let skip = dict.len() - w_size as usize;
        dict = &dict[skip..];
        dl = w_size;
    }

    /* insert dictionary into window and hash */
    {
        let s = match &mut strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        let mut dict_io = Io {
            next_in: dict,
            in_pos: 0,
            avail_in: dl,
            total_in: 0,
            next_out: &mut [],
            out_pos: 0,
            avail_out: 0,
            total_out: 0,
            adler: strm.adler,
            data_type: strm.data_type,
            msg: strm.msg,
            wrap: 0,
            status: s.status,
        };
        fill_window(s, &mut dict_io);
        while s.lookahead >= MIN_MATCH {
            let mut str = s.strstart;
            let mut n = s.lookahead - (MIN_MATCH - 1);
            while n != 0 {
                s.ins_h = update_hash(s, s.ins_h, s.window[(str + MIN_MATCH - 1) as usize]);
                s.prev[(str & s.w_mask) as usize] = s.head[s.ins_h as usize];
                s.head[s.ins_h as usize] = str as u16;
                str += 1;
                n -= 1;
            }
            s.strstart = str;
            s.lookahead = MIN_MATCH - 1;
            fill_window(s, &mut dict_io);
        }
        s.strstart += s.lookahead;
        s.block_start = s.strstart as i64;
        s.insert = s.lookahead;
        s.lookahead = 0;
        s.match_length = MIN_MATCH - 1;
        s.prev_length = MIN_MATCH - 1;
        s.match_available = false;
        s.wrap = wrap;
    }
    Z_OK
}

/// `deflateGetDictionary` (deflate.c).
pub fn deflate_get_dictionary(strm: &ZStream) -> (i32, Vec<u8>) {
    if !deflate_state_check(strm) {
        return (Z_STREAM_ERROR, Vec::new());
    }
    let s = match &strm.state {
        StreamState::Deflate(s) => s,
        _ => return (Z_STREAM_ERROR, Vec::new()),
    };
    let mut len = s.strstart + s.lookahead;
    if len > s.w_size {
        len = s.w_size;
    }
    let mut dict = Vec::new();
    if len != 0 {
        let start = (s.strstart + s.lookahead - len) as usize;
        dict = s.window[start..start + len as usize].to_vec();
    }
    (Z_OK, dict)
}

/// `deflateSetHeader` (deflate.c).
pub fn deflate_set_header(strm: &mut ZStream, head: GzHeader) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if s.wrap != 2 {
        return Z_STREAM_ERROR;
    }
    s.gzhead = Some(head);
    Z_OK
}

/// `deflatePending` (deflate.c).
pub fn deflate_pending(strm: &ZStream) -> (i32, u32, u32) {
    if !deflate_state_check(strm) {
        return (Z_STREAM_ERROR, 0, 0);
    }
    let s = match &strm.state {
        StreamState::Deflate(s) => s,
        _ => return (Z_STREAM_ERROR, 0, 0),
    };
    (Z_OK, s.pending, s.bi_valid)
}

/// `deflatePrime` (deflate.c).
pub fn deflate_prime(strm: &mut ZStream, bits: i32, value: i32) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if bits < 0 || bits > 16 {
        return Z_BUF_ERROR;
    }
    let mut bits = bits;
    let mut value = value;
    while bits != 0 {
        let mut put = 16 - s.bi_valid as i32;
        if put > bits {
            put = bits;
        }
        s.bi_buf |= ((value & ((1 << put) - 1)) << s.bi_valid) as u16;
        s.bi_valid += put as u32;
        super::trees::tr_flush_bits(s);
        value >>= put;
        bits -= put;
    }
    Z_OK
}

/// `deflateParams` (deflate.c).
#[allow(clippy::too_many_lines)]
pub fn deflate_params(strm: &mut ZStream, level: i32, strategy: i32) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let mut level = level;
    if level == Z_DEFAULT_COMPRESSION {
        level = 6;
    }
    if level < 0 || level > 9 || strategy < 0 || strategy > Z_FIXED {
        return Z_STREAM_ERROR;
    }

    let old_func = {
        let s = match &strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        CONFIGURATION_TABLE[s.level as usize].func
    };

    let needs_flush = {
        let s = match &strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        (strategy != s.strategy || old_func != CONFIGURATION_TABLE[level as usize].func)
            && s.last_flush != -2
    };

    if needs_flush {
        /* Flush the last buffer (deflate.c: deflate(strm, Z_BLOCK)).  The C
         * writes the flushed block into the caller's next_out; the Rust API
         * has no caller buffer here, so the produced bytes are stashed in
         * `params_flush` and emitted at the start of the next deflate call. */
        let before = strm.total_out;
        let mut scratch = vec![0u8; 64 * 1024 + 1024];
        let err = deflate_call_internal(strm, &[], &mut scratch, Z_BLOCK);
        if err == Z_STREAM_ERROR {
            return err;
        }
        let produced = (strm.total_out - before) as usize;
        /* the C advances total_out here because it wrote into the caller's
         * next_out; the Rust has no caller buffer, so the bytes are stashed
         * and emitted at the start of the next deflate call -- the caller
         * slices that call at the PRE-flush total_out, so restore it */
        strm.total_out = before;
        let s = match &mut strm.state {
            StreamState::Deflate(s) => s,
            _ => return Z_STREAM_ERROR,
        };
        s.params_flush.extend_from_slice(&scratch[..produced]);
    }

    let s = match &mut strm.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    if s.level != level {
        if s.level == 0 && s.matches != 0 {
            if s.matches == 1 {
                slide_hash(s);
            } else {
                clear_hash(s);
            }
            s.matches = 0;
        }
        s.level = level;
        let cfg = &CONFIGURATION_TABLE[level as usize];
        s.max_lazy_match = cfg.max_lazy;
        s.good_match = cfg.good_length;
        s.nice_match = cfg.nice_length as i32;
        s.max_chain_length = cfg.max_chain;
    }
    s.strategy = strategy;
    Z_OK
}

/// `deflateTune` (deflate.c).
pub fn deflate_tune(
    strm: &mut ZStream,
    good_length: i32,
    max_lazy: i32,
    nice_length: i32,
    max_chain: i32,
) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let s = match &mut strm.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    s.good_match = good_length as u32;
    s.max_lazy_match = max_lazy as u32;
    s.nice_match = nice_length;
    s.max_chain_length = max_chain as u32;
    Z_OK
}

/// `deflateSetStrategy` — the zlib.h macro `deflateParams(strm,
/// Z_DEFAULT_COMPRESSION, strategy)`.
pub fn deflate_set_strategy(strm: &mut ZStream, strategy: i32) -> i32 {
    deflate_params(strm, Z_DEFAULT_COMPRESSION, strategy)
}

/// `deflateBound` (deflate.c).
pub fn deflate_bound(strm: &ZStream, source_len: u64) -> u64 {
    /* upper bound for fixed blocks with 9-bit literals and length 255 */
    let fixedlen = source_len + (source_len >> 3) + (source_len >> 8) + (source_len >> 9) + 4;

    /* upper bound for stored blocks with length 127 (memLevel == 1) */
    let storelen = source_len + (source_len >> 5) + (source_len >> 7) + (source_len >> 11) + 7;

    /* if can't get parameters, return larger bound plus a zlib wrapper */
    let s = match &strm.state {
        StreamState::Deflate(s) => s,
        _ => {
            return if fixedlen > storelen {
                fixedlen
            } else {
                storelen
            } + 6
        }
    };

    /* compute wrapper length */
    let wraplen: u64 = match s.wrap {
        0 => 0,                                       /* raw deflate */
        1 => 6 + if s.strstart != 0 { 4 } else { 0 }, /* zlib wrapper */
        2 => {
            /* gzip wrapper */
            let mut wl: u64 = 18;
            if let Some(gzhead) = &s.gzhead {
                if gzhead.extra.is_some() {
                    wl += 2 + gzhead.extra_len as u64;
                }
                if let Some(name) = &gzhead.name {
                    wl += name.len() as u64 + 1;
                }
                if let Some(comment) = &gzhead.comment {
                    wl += comment.len() as u64 + 1;
                }
                if gzhead.hcrc {
                    wl += 2;
                }
            }
            wl
        }
        _ => 6,
    };

    /* if not default parameters, return one of the conservative bounds */
    if s.w_bits != 15 || s.hash_bits != 8 + 7 {
        return (if s.w_bits <= s.hash_bits && s.level != 0 {
            fixedlen
        } else {
            storelen
        }) + wraplen;
    }

    /* default settings: return tight bound for that case */
    source_len + (source_len >> 12) + (source_len >> 14) + (source_len >> 25) + 13 - 6 + wraplen
}

/// `deflateEnd` (deflate.c).
pub fn deflate_end(strm: &mut ZStream) -> i32 {
    if !deflate_state_check(strm) {
        return Z_STREAM_ERROR;
    }
    let status = match &strm.state {
        StreamState::Deflate(s) => s.status,
        _ => return Z_STREAM_ERROR,
    };
    strm.state = StreamState::None;
    if status == BUSY_STATE {
        Z_DATA_ERROR
    } else {
        Z_OK
    }
}

/// `deflateCopy` (deflate.c) — duplicate the stream state.
pub fn deflate_copy(dest: &mut ZStream, source: &ZStream) -> i32 {
    let ss = match &source.state {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };
    dest.avail_in = source.avail_in;
    dest.total_in = source.total_in;
    dest.avail_out = source.avail_out;
    dest.total_out = source.total_out;
    dest.msg = source.msg;
    dest.data_type = source.data_type;
    dest.adler = source.adler;
    let mut ds = DeflateState::new();
    ds.status = ss.status;
    ds.pending_buf = ss.pending_buf.clone();
    ds.pending = ss.pending;
    ds.pending_out = ss.pending_out;
    ds.wrap = ss.wrap;
    ds.gzhead = ss.gzhead.clone();
    ds.gzindex = ss.gzindex;
    ds.method = ss.method;
    ds.last_flush = ss.last_flush;
    ds.w_size = ss.w_size;
    ds.w_bits = ss.w_bits;
    ds.w_mask = ss.w_mask;
    ds.window = ss.window.clone();
    ds.window_size = ss.window_size;
    ds.prev = ss.prev.clone();
    ds.head = ss.head.clone();
    ds.ins_h = ss.ins_h;
    ds.hash_size = ss.hash_size;
    ds.hash_bits = ss.hash_bits;
    ds.hash_mask = ss.hash_mask;
    ds.hash_shift = ss.hash_shift;
    ds.block_start = ss.block_start;
    ds.match_length = ss.match_length;
    ds.prev_match = ss.prev_match;
    ds.match_available = ss.match_available;
    ds.strstart = ss.strstart;
    ds.match_start = ss.match_start;
    ds.lookahead = ss.lookahead;
    ds.prev_length = ss.prev_length;
    ds.max_chain_length = ss.max_chain_length;
    ds.max_lazy_match = ss.max_lazy_match;
    ds.level = ss.level;
    ds.strategy = ss.strategy;
    ds.good_match = ss.good_match;
    ds.nice_match = ss.nice_match;
    ds.dyn_ltree = ss.dyn_ltree.clone();
    ds.dyn_dtree = ss.dyn_dtree.clone();
    ds.bl_tree = ss.bl_tree.clone();
    ds.bl_count = ss.bl_count;
    ds.heap = ss.heap.clone();
    ds.heap_len = ss.heap_len;
    ds.heap_max = ss.heap_max;
    ds.depth = ss.depth.clone();
    ds.sym_buf = ss.sym_buf.clone();
    ds.lit_bufsize = ss.lit_bufsize;
    ds.sym_next = ss.sym_next;
    ds.sym_end = ss.sym_end;
    ds.opt_len = ss.opt_len;
    ds.static_len = ss.static_len;
    ds.matches = ss.matches;
    ds.insert = ss.insert;
    ds.bi_buf = ss.bi_buf;
    ds.bi_valid = ss.bi_valid;
    ds.high_water = ss.high_water;
    ds.l_max_code = ss.l_max_code;
    ds.d_max_code = ss.d_max_code;
    ds.strm_data_type = ss.strm_data_type;
    ds.params_flush = ss.params_flush.clone();
    dest.state = StreamState::Deflate(Box::new(ds));
    Z_OK
}

// ---------------------------------------------------------------------------
// deflate() — the main entry point
// ---------------------------------------------------------------------------

/// Copy the per-call IO results back into the stream.
fn sync_io(strm: &mut ZStream, io: &Io) {
    strm.avail_in = io.avail_in;
    strm.total_in = io.total_in;
    strm.avail_out = io.avail_out;
    strm.total_out = io.total_out;
    strm.adler = io.adler;
    strm.data_type = io.data_type;
    strm.msg = io.msg;
    /* advance the buffer cursors (the C's next_in/next_out pointers) */
    strm.next_in_pos += io.in_pos;
    strm.next_out_pos += io.out_pos;
}

/// The core deflate driver.  `input` is the available input for this call
/// (the caller re-passes only the unconsumed remainder), `output` the
/// available output space.  Uses the caller-set `avail_in`/`avail_out`.
#[allow(clippy::too_many_lines)]
pub(crate) fn deflate_call_internal(
    strm: &mut ZStream,
    input: &[u8],
    output: &mut [u8],
    flush: i32,
) -> i32 {
    if !deflate_state_check(strm) || flush > Z_BLOCK || flush < 0 {
        return Z_STREAM_ERROR;
    }
    let (status, wrap) = match &strm.state {
        StreamState::Deflate(s) => (s.status, s.wrap),
        _ => return Z_STREAM_ERROR,
    };

    if (strm.avail_in != 0 && input.is_empty()) || (status == FINISH_STATE && flush != Z_FINISH) {
        strm.msg = Some(super::err_msg(Z_STREAM_ERROR));
        return Z_STREAM_ERROR;
    }
    if output.is_empty() {
        strm.msg = Some(super::err_msg(Z_BUF_ERROR));
        return Z_BUF_ERROR;
    }

    // Pull the state out so we can mutate it freely (mirrors inflate).
    let mut state = match std::mem::replace(&mut strm.state, StreamState::None) {
        StreamState::Deflate(s) => s,
        _ => return Z_STREAM_ERROR,
    };

    let old_flush = {
        let old = state.last_flush;
        state.last_flush = flush;
        old
    };

    let mut io = Io {
        next_in: input,
        in_pos: 0,
        avail_in: strm.avail_in,
        total_in: strm.total_in,
        next_out: output,
        out_pos: 0,
        avail_out: strm.avail_out,
        total_out: strm.total_out,
        adler: strm.adler,
        data_type: strm.data_type,
        msg: strm.msg,
        wrap,
        status,
    };

    // Restore the state into the stream and return a value.  The state's
    // `status` field is mutated in place during the call (INIT_STATE ->
    // BUSY_STATE -> FINISH_STATE) and must persist across calls exactly
    // like the C's `s->status`; io.status is only the entry snapshot.
    macro_rules! deflate_ret {
        ($v:expr) => {{
            sync_io(strm, &io);
            strm.state = StreamState::Deflate(state);
            return $v;
        }};
    }

    /* Emit any bytes stashed by a deflateParams Z_BLOCK flush (the C wrote
     * them into the caller's next_out during the params call; here they are
     * emitted at the start of the next deflate call instead). */
    if !state.params_flush.is_empty() {
        let take = state.params_flush.len().min(io.avail_out as usize);
        io.next_out[io.out_pos..io.out_pos + take].copy_from_slice(&state.params_flush[..take]);
        io.out_pos += take;
        io.total_out += take as u64;
        io.avail_out -= take as u32;
        if take == state.params_flush.len() {
            state.params_flush.clear();
        } else {
            state.params_flush.drain(..take);
        }
        if io.avail_out == 0 {
            state.last_flush = -1;
            deflate_ret!(Z_OK);
        }
    }

    /* Flush as much pending output as possible */
    if state.pending != 0 {
        flush_pending(&mut state, &mut io);
        if io.avail_out == 0 {
            /* Since avail_out is 0, deflate will be called again with
             * more output space, but possibly with both pending and
             * avail_in equal to zero. There won't be anything to do,
             * but this is not an error situation so make sure we
             * return OK instead of BUF_ERROR at next call of deflate: */
            state.last_flush = -1;
            deflate_ret!(Z_OK);
        }
    /* Make sure there is something to do and avoid duplicate consecutive
     * flushes. For repeated and useless calls with Z_FINISH, we keep
     * returning Z_STREAM_END instead of Z_BUF_ERROR. */
    } else if io.avail_in == 0 && rank(flush) <= rank(old_flush) && flush != Z_FINISH {
        strm.msg = Some(super::err_msg(Z_BUF_ERROR));
        strm.state = StreamState::Deflate(state); /* restore the pulled state */
        return Z_BUF_ERROR;
    }

    /* User must not provide more input after the first FINISH: */
    if state.status == FINISH_STATE && io.avail_in != 0 {
        strm.msg = Some(super::err_msg(Z_BUF_ERROR));
        strm.state = StreamState::Deflate(state); /* restore the pulled state */
        return Z_BUF_ERROR;
    }

    /* Write the header */
    if state.status == INIT_STATE && state.wrap == 0 {
        state.status = BUSY_STATE;
    }
    if state.status == INIT_STATE {
        /* zlib header */
        let mut header: u32 = ((Z_DEFLATED as u32 + ((state.w_bits - 8) << 4)) << 8);
        let level_flags: u32;
        if state.strategy >= Z_HUFFMAN_ONLY || state.level < 2 {
            level_flags = 0;
        } else if state.level < 6 {
            level_flags = 1;
        } else if state.level == 6 {
            level_flags = 2;
        } else {
            level_flags = 3;
        }
        header |= level_flags << 6;
        if state.strstart != 0 {
            header |= PRESET_DICT;
        }
        header += 31 - (header % 31);

        put_short_msb(&mut state, header);

        /* Save the adler32 of the preset dictionary: */
        if state.strstart != 0 {
            put_short_msb(&mut state, (io.adler >> 16) as u32);
            put_short_msb(&mut state, (io.adler & 0xffff) as u32);
        }
        io.adler = checksum::adler32(0, &[]);
        state.status = BUSY_STATE;

        /* Compression must start with an empty pending buffer */
        flush_pending(&mut state, &mut io);
        if state.pending != 0 {
            state.last_flush = -1;
            deflate_ret!(Z_OK);
        }
    }
    if state.status == GZIP_STATE {
        /* gzip header */
        io.adler = checksum::crc32(0, &[]);
        put_byte(&mut state, 31);
        put_byte(&mut state, 139);
        put_byte(&mut state, 8);
        if state.gzhead.is_none() {
            put_byte(&mut state, 0);
            put_byte(&mut state, 0);
            put_byte(&mut state, 0);
            put_byte(&mut state, 0);
            put_byte(&mut state, 0);
            let xfl = if state.level == 9 {
                2
            } else if state.strategy >= Z_HUFFMAN_ONLY || state.level < 2 {
                4
            } else {
                0
            };
            put_byte(&mut state, xfl);
            put_byte(&mut state, OS_CODE);
            state.status = BUSY_STATE;

            /* Compression must start with an empty pending buffer */
            flush_pending(&mut state, &mut io);
            if state.pending != 0 {
                state.last_flush = -1;
                deflate_ret!(Z_OK);
            }
        } else {
            let head = state.gzhead.as_ref().unwrap().clone();
            put_byte(
                &mut state,
                (if head.text { 1 } else { 0 })
                    + (if head.hcrc { 2 } else { 0 })
                    + (if head.extra.is_some() { 4 } else { 0 })
                    + (if head.name.is_some() { 8 } else { 0 })
                    + (if head.comment.is_some() { 16 } else { 0 }),
            );
            put_byte(&mut state, (head.time & 0xff) as u8);
            put_byte(&mut state, ((head.time >> 8) & 0xff) as u8);
            put_byte(&mut state, ((head.time >> 16) & 0xff) as u8);
            put_byte(&mut state, ((head.time >> 24) & 0xff) as u8);
            let xfl = if state.level == 9 {
                2
            } else if state.strategy >= Z_HUFFMAN_ONLY || state.level < 2 {
                4
            } else {
                0
            };
            put_byte(&mut state, xfl);
            put_byte(&mut state, (head.os & 0xff) as u8);
            if head.extra.is_some() {
                put_byte(&mut state, (head.extra_len & 0xff) as u8);
                put_byte(&mut state, ((head.extra_len >> 8) & 0xff) as u8);
            }
            if head.hcrc {
                io.adler = checksum::crc32(io.adler, &state.pending_buf[..state.pending as usize]);
            }
            state.gzindex = 0;
            state.status = EXTRA_STATE;
        }
    }
    if state.status == EXTRA_STATE {
        if let Some(extra) = state.gzhead.as_ref().and_then(|h| h.extra.clone()) {
            let mut beg = state.pending; /* start of bytes to update crc */
            let mut left = (state.gzhead.as_ref().unwrap().extra_len & 0xffff) - state.gzindex;
            while state.pending + left > state.pending_buf.len() as u32 {
                let copy = state.pending_buf.len() as u32 - state.pending;
                let src = state.gzindex as usize;
                let dst = state.pending as usize;
                state.pending_buf[dst..dst + copy as usize]
                    .copy_from_slice(&extra[src..src + copy as usize]);
                state.pending = state.pending_buf.len() as u32;
                if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                    io.adler = checksum::crc32(
                        io.adler,
                        &state.pending_buf[beg as usize..state.pending as usize],
                    );
                }
                state.gzindex += copy;
                flush_pending(&mut state, &mut io);
                if state.pending != 0 {
                    state.last_flush = -1;
                    deflate_ret!(Z_OK);
                }
                beg = 0;
                left -= copy;
            }
            let src = state.gzindex as usize;
            let dst = state.pending as usize;
            let take = left as usize;
            state.pending_buf[dst..dst + take].copy_from_slice(&extra[src..src + take]);
            state.pending += left;
            if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                io.adler = checksum::crc32(
                    io.adler,
                    &state.pending_buf[beg as usize..state.pending as usize],
                );
            }
            state.gzindex = 0;
        }
        state.status = NAME_STATE;
    }
    if state.status == NAME_STATE {
        if let Some(name) = state.gzhead.as_ref().and_then(|h| h.name.clone()) {
            let mut beg = state.pending;
            let mut val: i32;
            loop {
                if state.pending == state.pending_buf.len() as u32 {
                    if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                        io.adler = checksum::crc32(
                            io.adler,
                            &state.pending_buf[beg as usize..state.pending as usize],
                        );
                    }
                    flush_pending(&mut state, &mut io);
                    if state.pending != 0 {
                        state.last_flush = -1;
                        deflate_ret!(Z_OK);
                    }
                    beg = 0;
                }
                let idx = state.gzindex as usize;
                val = if idx < name.len() {
                    name[idx] as i32
                } else {
                    0
                };
                state.gzindex += 1;
                put_byte(&mut state, val as u8);
                if val == 0 {
                    break;
                }
            }
            if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                io.adler = checksum::crc32(
                    io.adler,
                    &state.pending_buf[beg as usize..state.pending as usize],
                );
            }
            state.gzindex = 0;
        }
        state.status = COMMENT_STATE;
    }
    if state.status == COMMENT_STATE {
        if let Some(comment) = state.gzhead.as_ref().and_then(|h| h.comment.clone()) {
            let mut beg = state.pending;
            let mut val: i32;
            loop {
                if state.pending == state.pending_buf.len() as u32 {
                    if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                        io.adler = checksum::crc32(
                            io.adler,
                            &state.pending_buf[beg as usize..state.pending as usize],
                        );
                    }
                    flush_pending(&mut state, &mut io);
                    if state.pending != 0 {
                        state.last_flush = -1;
                        deflate_ret!(Z_OK);
                    }
                    beg = 0;
                }
                let idx = state.gzindex as usize;
                val = if idx < comment.len() {
                    comment[idx] as i32
                } else {
                    0
                };
                state.gzindex += 1;
                put_byte(&mut state, val as u8);
                if val == 0 {
                    break;
                }
            }
            if state.gzhead.as_ref().unwrap().hcrc && state.pending > beg {
                io.adler = checksum::crc32(
                    io.adler,
                    &state.pending_buf[beg as usize..state.pending as usize],
                );
            }
        }
        state.status = HCRC_STATE;
    }
    if state.status == HCRC_STATE {
        if state.gzhead.as_ref().is_some_and(|h| h.hcrc) {
            if state.pending + 2 > state.pending_buf.len() as u32 {
                flush_pending(&mut state, &mut io);
                if state.pending != 0 {
                    state.last_flush = -1;
                    deflate_ret!(Z_OK);
                }
            }
            put_byte(&mut state, (io.adler & 0xff) as u8);
            put_byte(&mut state, ((io.adler >> 8) & 0xff) as u8);
            io.adler = checksum::crc32(0, &[]);
        }
        state.status = BUSY_STATE;

        /* Compression must start with an empty pending buffer */
        flush_pending(&mut state, &mut io);
        if state.pending != 0 {
            state.last_flush = -1;
            deflate_ret!(Z_OK);
        }
    }

    /* Start a new block or continue the current one. */
    if io.avail_in != 0
        || state.lookahead != 0
        || (flush != Z_NO_FLUSH && state.status != FINISH_STATE)
    {
        let bstate = if state.level == 0 {
            deflate_stored(&mut state, &mut io, flush)
        } else if state.strategy == Z_HUFFMAN_ONLY {
            deflate_huff(&mut state, &mut io, flush)
        } else if state.strategy == Z_RLE {
            deflate_rle(&mut state, &mut io, flush)
        } else {
            match CONFIGURATION_TABLE[state.level as usize].func {
                CompressFunc::Stored => deflate_stored(&mut state, &mut io, flush),
                CompressFunc::Fast => deflate_fast(&mut state, &mut io, flush),
                CompressFunc::Slow => deflate_slow(&mut state, &mut io, flush),
                CompressFunc::Rle => deflate_rle(&mut state, &mut io, flush),
                CompressFunc::Huff => deflate_huff(&mut state, &mut io, flush),
            }
        };

        if bstate == BlockState::FinishStarted || bstate == BlockState::FinishDone {
            state.status = FINISH_STATE;
        }
        if bstate == BlockState::NeedMore || bstate == BlockState::FinishStarted {
            if io.avail_out == 0 {
                state.last_flush = -1; /* avoid BUF_ERROR next call, see above */
            }
            deflate_ret!(Z_OK);
        }
        if bstate == BlockState::BlockDone {
            if flush == Z_PARTIAL_FLUSH {
                tr_align(&mut state);
            } else if flush != Z_BLOCK {
                /* FULL_FLUSH or SYNC_FLUSH */
                tr_stored_block(&mut state, &[], 0, false);
                /* For a full flush, this empty block will be recognized
                 * as a special marker by inflate_sync(). */
                if flush == Z_FULL_FLUSH {
                    clear_hash(&mut state); /* forget history */
                    if state.lookahead == 0 {
                        state.strstart = 0;
                        state.block_start = 0;
                        state.insert = 0;
                    }
                }
            }
            flush_pending(&mut state, &mut io);
            if io.avail_out == 0 {
                state.last_flush = -1; /* avoid BUF_ERROR at next call */
                deflate_ret!(Z_OK);
            }
        }
    }

    if flush != Z_FINISH {
        deflate_ret!(Z_OK);
    }
    if state.wrap <= 0 {
        deflate_ret!(Z_STREAM_END);
    }

    /* Write the trailer */
    if state.wrap == 2 {
        put_byte(&mut state, (io.adler & 0xff) as u8);
        put_byte(&mut state, ((io.adler >> 8) & 0xff) as u8);
        put_byte(&mut state, ((io.adler >> 16) & 0xff) as u8);
        put_byte(&mut state, ((io.adler >> 24) & 0xff) as u8);
        put_byte(&mut state, (io.total_in & 0xff) as u8);
        put_byte(&mut state, ((io.total_in >> 8) & 0xff) as u8);
        put_byte(&mut state, ((io.total_in >> 16) & 0xff) as u8);
        put_byte(&mut state, ((io.total_in >> 24) & 0xff) as u8);
    } else {
        put_short_msb(&mut state, (io.adler >> 16) as u32);
        put_short_msb(&mut state, (io.adler & 0xffff) as u32);
    }
    flush_pending(&mut state, &mut io);
    /* If avail_out is zero, the application will call deflate again
     * to flush the rest. */
    if state.wrap > 0 {
        state.wrap = -state.wrap; /* write the trailer only once! */
    }
    let r = if state.pending != 0 {
        Z_OK
    } else {
        Z_STREAM_END
    };
    deflate_ret!(r);
}

/// `deflate(strm, flush)` — the public entry.  `input`/`output` are the
/// per-call buffers; `strm.avail_in`/`strm.avail_out` are set from them.
pub fn deflate(strm: &mut ZStream, input: &[u8], output: &mut [u8], flush: i32) -> i32 {
    strm.avail_in = input.len() as u32;
    strm.avail_out = output.len() as u32;
    deflate_call_internal(strm, input, output, flush)
}

// ---------------------------------------------------------------------------
// compress.c / uncompr.c
// ---------------------------------------------------------------------------

/// `compress2` (compress.c).
pub fn compress2(dest: &mut [u8], source: &[u8], level: i32) -> (i32, u64) {
    let mut strm = ZStream::default();
    let err = deflate_init(&mut strm, level);
    if err != Z_OK {
        return (err, 0);
    }
    let max = u32::MAX;
    let mut left = dest.len() as u64;
    let mut source_len = source.len() as u64;
    let mut consumed = 0usize;
    let mut err = Z_OK;
    strm.avail_out = 0;
    strm.avail_in = 0;
    loop {
        if strm.avail_out == 0 {
            strm.avail_out = if left > max as u64 { max } else { left as u32 };
            left -= strm.avail_out as u64;
        }
        if strm.avail_in == 0 {
            strm.avail_in = if source_len > max as u64 {
                max
            } else {
                source_len as u32
            };
            source_len -= strm.avail_in as u64;
        }
        let inp = &source[consumed..consumed + strm.avail_in as usize];
        let outp =
            &mut dest[strm.total_out as usize..strm.total_out as usize + strm.avail_out as usize];
        err = deflate_call_internal(
            &mut strm,
            inp,
            outp,
            if source_len != 0 {
                Z_NO_FLUSH
            } else {
                Z_FINISH
            },
        );
        consumed = source.len() - strm.avail_in as usize;
        if err != Z_OK {
            break;
        }
    }
    let total_out = strm.total_out;
    deflate_end(&mut strm);
    if err == Z_STREAM_END {
        (Z_OK, total_out)
    } else {
        (err, total_out)
    }
}

/// `compress` — compress2 at Z_DEFAULT_COMPRESSION.
pub fn compress(dest: &mut [u8], source: &[u8]) -> (i32, u64) {
    compress2(dest, source, Z_DEFAULT_COMPRESSION)
}

/// `compressBound` (compress.c).
#[must_use]
pub fn compress_bound(source_len: u64) -> u64 {
    source_len + (source_len >> 12) + (source_len >> 14) + (source_len >> 25) + 13
}

/// `uncompress2` (uncompr.c).
pub fn uncompress2(dest: &mut [u8], source: &[u8]) -> (i32, u64, u64) {
    let mut strm = ZStream::default();
    let mut dest_len = dest.len() as u64;
    let mut source_len = source.len() as u64;
    let max = u32::MAX;
    let mut len = source_len;
    let mut left: u64;
    let use_sink = dest_len == 0;
    if !use_sink {
        left = dest_len;
        dest_len = 0;
    } else {
        left = 1;
    }

    let err = crate::compat::zlib::inflate::inflate_init(&mut strm);
    if err != Z_OK {
        return (err, 0, 0);
    }

    strm.avail_out = 0;
    strm.avail_in = 0;
    let mut err = Z_OK;
    let mut src_consumed = 0usize;
    loop {
        if strm.avail_out == 0 {
            strm.avail_out = if left > max as u64 { max } else { left as u32 };
            left -= strm.avail_out as u64;
        }
        if strm.avail_in == 0 {
            strm.avail_in = if len > max as u64 { max } else { len as u32 };
            len -= strm.avail_in as u64;
        }
        let inp = &source[src_consumed..src_consumed + strm.avail_in as usize];
        let ret = if use_sink {
            let mut sink = [0u8; 1];
            err = crate::compat::zlib::inflate::inflate_call_internal(
                &mut strm, inp, &mut sink, Z_NO_FLUSH,
            );
            err
        } else {
            let start = strm.total_out as usize;
            let outp = &mut dest[start..start + strm.avail_out as usize];
            err = crate::compat::zlib::inflate::inflate_call_internal(
                &mut strm, inp, outp, Z_NO_FLUSH,
            );
            err
        };
        src_consumed = source.len() - strm.avail_in as usize;
        if ret != Z_OK {
            break;
        }
    }

    source_len -= len + strm.avail_in as u64;
    let consumed = source_len;
    let produced = strm.total_out;
    if !use_sink {
        dest_len = strm.total_out;
    } else if strm.total_out != 0 && err == Z_BUF_ERROR {
        left = 1;
    }
    let final_err = if err == Z_STREAM_END {
        Z_OK
    } else if err == Z_NEED_DICT {
        Z_DATA_ERROR
    } else if err == Z_BUF_ERROR && left + strm.avail_out as u64 != 0 {
        Z_DATA_ERROR
    } else {
        err
    };
    crate::compat::zlib::inflate::inflate_end(&mut strm);
    (final_err, produced, consumed)
}

/// `uncompress` — uncompress2 with full source consumption.
pub fn uncompress(dest: &mut [u8], source: &[u8]) -> (i32, u64) {
    let (err, produced, _consumed) = uncompress2(dest, source);
    (err, produced)
}
