//! gzlib.c + gzread.c + gzwrite.c + gzclose.c — the gz* file API
//! (conservation port).
//!
//! gzopen/gzbuffer/gzrewind/gzseek/gztell/gzoffset, gzread/gzgetc/gzgets/
//! gzungetc, gzwrite/gzputc/gzputs/gzflush/gzsetparams, gzeof/gzdirect/
//! gzerror/gzclearerr, gzclose_r/gzclose_w/gzclose — with the exact
//! buffering (GZBUFSIZE default, the double-sized input buffer for reading
//! and the double-sized input / sized output buffers for writing), the
//! LOOK/COPY/GZIP modes, the seek/skip machinery, the error conventions
//! (Z_ERRNO, Z_MEM_ERROR "out of memory", Z_BUF_ERROR "unexpected end of
//! file", Z_STREAM_ERROR mode misuse, Z_DATA_ERROR), and the gzgetc fast
//! path.
//!
//! All fd operations terminate in `platform::linux` (addendum §2):
//! open_mode/read_fd/write_fd/lseek/close.

use super::deflate::{deflate_end, deflate_init2, deflate_params, deflate_reset, ZStream};
use super::inflate::{inflate_end, inflate_init2};
use crate::compat::zlib::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED,
    Z_ERRNO, Z_FILTERED, Z_FINISH, Z_FIXED, Z_HUFFMAN_ONLY, Z_MEM_ERROR, Z_NEED_DICT, Z_NO_FLUSH,
    Z_OK, Z_RLE, Z_STREAM_END, Z_STREAM_ERROR,
};
use crate::platform::linux as lx;
use std::ffi::CString;

const GZBUFSIZE: u32 = 8192;
const DEF_MEM_LEVEL: i32 = 8;
const MAX_WBITS: i32 = 15;

const GZ_NONE: i32 = 0;
const GZ_READ: i32 = 7247;
const GZ_WRITE: i32 = 31153;
const GZ_APPEND: i32 = 1;

const LOOK: i32 = 0;
const COPY: i32 = 1;
const GZIP: i32 = 2;

/// The gz* state (gzguts.h `gz_state`).
pub struct GzState {
    /* exposed contents for gzgetc */
    pub have: u32,
    pub next: usize, /* cursor into out */
    pub pos: i64,    /* position in uncompressed data */
    /* used for both reading and writing */
    pub mode: i32,
    pub fd: i32,
    pub path: String,
    pub size: u32, /* buffer size, zero if not allocated yet */
    pub want: u32, /* requested buffer size */
    pub in_: Vec<u8>,
    pub out: Vec<u8>,
    pub direct: i32, /* 0 if processing gzip, 1 if transparent */
    /* just for reading */
    pub how: i32,
    pub start: i64,
    pub eof: bool,
    pub past: bool,
    /* just for writing */
    pub level: i32,
    pub strategy: i32,
    pub reset: bool, /* true if a reset is pending after a Z_FINISH */
    /* seek request */
    pub skip: i64,
    pub seek: bool,
    /* error information */
    pub err: i32,
    pub msg: Option<String>,
    /* zlib stream */
    pub strm: ZStream,
}

impl GzState {
    fn new() -> Self {
        GzState {
            have: 0,
            next: 0,
            pos: 0,
            mode: GZ_NONE,
            fd: -1,
            path: String::new(),
            size: 0,
            want: GZBUFSIZE,
            in_: Vec::new(),
            out: Vec::new(),
            direct: 0,
            how: LOOK,
            start: 0,
            eof: false,
            past: false,
            level: Z_DEFAULT_COMPRESSION,
            strategy: Z_DEFAULT_STRATEGY,
            reset: false,
            skip: 0,
            seek: false,
            err: Z_OK,
            msg: None,
            strm: ZStream::default(),
        }
    }
}

fn gz_intmax() -> i64 {
    i32::MAX as i64
}

/// `GT_OFF(x)` — true if x > maximum z_off64_t value representable.
fn gt_off(x: u64) -> bool {
    x > gz_intmax() as u64
}

/// `gz_error` (gzlib.c) — set the error state.
fn gz_error(state: &mut GzState, err: i32, msg: Option<&str>) {
    /* free previously allocated message and clear */
    state.msg = None;

    /* if fatal, set have to 0 so that the gzgetc() fast path fails */
    if err != Z_OK && err != Z_BUF_ERROR {
        state.have = 0;
    }

    /* set error code, and if no message, then done */
    state.err = err;
    let Some(msg) = msg else {
        return;
    };

    /* for an out of memory error, return literal string when requested */
    if err == Z_MEM_ERROR {
        return;
    }

    /* construct error message with path */
    state.msg = Some(format!("{}: {}", state.path, msg));
}

/// `gz_reset` (gzlib.c).
fn gz_reset(state: &mut GzState) {
    state.have = 0;
    if state.mode == GZ_READ {
        state.eof = false;
        state.past = false;
        state.how = LOOK;
    } else {
        state.reset = false;
    }
    state.seek = false;
    gz_error(state, Z_OK, None);
    state.pos = 0;
    state.strm.avail_in = 0;
}

/// `gz_open` (gzlib.c) — open a gzip file by name or fd.
fn gz_open_fd(path: &str, fd: i32, mode: &str) -> Option<GzState> {
    let mut state = GzState::new();
    state.want = GZBUFSIZE;

    /* interpret mode */
    state.mode = GZ_NONE;
    state.level = Z_DEFAULT_COMPRESSION;
    state.strategy = Z_DEFAULT_STRATEGY;
    state.direct = 0;
    for c in mode.chars() {
        if c.is_ascii_digit() {
            state.level = c as i32 - '0' as i32;
        } else {
            match c {
                'r' => state.mode = GZ_READ,
                'w' => state.mode = GZ_WRITE,
                'a' => state.mode = GZ_APPEND,
                '+' => return None, /* can't read and write at the same time */
                'b' => {}           /* ignore */
                'f' => state.strategy = Z_FILTERED,
                'h' => state.strategy = Z_HUFFMAN_ONLY,
                'R' => state.strategy = Z_RLE,
                'F' => state.strategy = Z_FIXED,
                'T' => state.direct = 1,
                _ => {}
            }
        }
    }

    /* must provide an "r", "w", or "a" */
    if state.mode == GZ_NONE {
        return None;
    }

    /* can't force transparent read */
    if state.mode == GZ_READ {
        if state.direct != 0 {
            return None;
        }
        state.direct = 1; /* for empty file */
    }

    /* save the path name for error messages */
    state.path = path.to_string();

    /* compute the flags for open() */
    let oflag = if state.mode == GZ_READ {
        libc::O_RDONLY
    } else {
        libc::O_WRONLY
            | libc::O_CREAT
            | if state.mode == GZ_WRITE {
                libc::O_TRUNC
            } else {
                libc::O_APPEND
            }
    };

    let cpath = CString::new(path).ok()?;
    state.fd = if fd > -1 {
        fd
    } else {
        lx::open_mode(&cpath, oflag, 0o666).ok()?
    };
    if state.mode == GZ_APPEND {
        let _ = lx::lseek(state.fd, 0, libc::SEEK_END); /* so gzoffset() is correct */
        state.mode = GZ_WRITE; /* simplify later checks */
    }

    /* save the current position for rewinding (only if reading) */
    if state.mode == GZ_READ {
        state.start = lx::lseek(state.fd, 0, libc::SEEK_CUR).unwrap_or(0);
    }

    /* initialize stream */
    gz_reset(&mut state);

    Some(state)
}

/// `gzopen(path, mode)`.
pub fn gz_open(path: &str, mode: &str) -> Option<GzState> {
    gz_open_fd(path, -1, mode)
}

/// `gzdopen(fd, mode)`.
pub fn gzdopen(fd: i32, mode: &str) -> Option<GzState> {
    if fd == -1 {
        return None;
    }
    gz_open_fd(&format!("<fd:{fd}>"), fd, mode)
}

/// `gzbuffer` (gzlib.c).
pub fn gz_buffer(state: Option<&mut GzState>, size: u32) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return -1;
    }
    if state.size != 0 {
        return -1;
    }
    if (size << 1) < size {
        return -1; /* need to be able to double it */
    }
    let mut size = size;
    if size < 8 {
        size = 8; /* needed to behave well with flushing */
    }
    state.want = size;
    0
}

/// `gzrewind` (gzlib.c).
pub fn gz_rewind(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ || (state.err != Z_OK && state.err != Z_BUF_ERROR) {
        return -1;
    }
    if lx::lseek(state.fd, state.start, libc::SEEK_SET).is_err() {
        return -1;
    }
    gz_reset(state);
    0
}

/// `gzseek64` (gzlib.c).
pub fn gz_seek64(state: Option<&mut GzState>, mut offset: i64, whence: i32) -> i64 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return -1;
    }
    if state.err != Z_OK && state.err != Z_BUF_ERROR {
        return -1;
    }
    if whence != libc::SEEK_SET && whence != libc::SEEK_CUR {
        return -1;
    }

    /* normalize offset to a SEEK_CUR specification */
    if whence == libc::SEEK_SET {
        offset -= state.pos;
    } else if state.seek {
        offset += state.skip;
    }
    state.seek = false;

    /* if within raw area while reading, just go there */
    if state.mode == GZ_READ && state.how == COPY && state.pos + offset >= 0 {
        let ret = lx::lseek(state.fd, offset - state.have as i64, libc::SEEK_CUR);
        if ret.is_err() {
            return -1;
        }
        state.have = 0;
        state.eof = false;
        state.past = false;
        state.seek = false;
        gz_error(state, Z_OK, None);
        state.strm.avail_in = 0;
        state.pos += offset;
        return state.pos;
    }

    /* calculate skip amount, rewinding if needed for back seek when reading */
    if offset < 0 {
        if state.mode != GZ_READ {
            return -1;
        }
        offset += state.pos;
        if offset < 0 {
            return -1;
        }
        if gz_rewind(Some(state)) == -1 {
            return -1;
        }
    }

    /* if reading, skip what's in output buffer (one less gzgetc() check) */
    if state.mode == GZ_READ {
        let n = if gt_off(state.have as u64) || state.have as i64 > offset {
            offset as u32
        } else {
            state.have
        };
        state.have -= n;
        state.next += n as usize;
        state.pos += n as i64;
        offset -= n as i64;
    }

    /* request skip (if not zero) */
    if offset != 0 {
        state.seek = true;
        state.skip = offset;
    }
    state.pos + offset
}

/// `gzseek` (gzlib.c).
pub fn gz_seek(state: Option<&mut GzState>, offset: i64, whence: i32) -> i64 {
    gz_seek64(state, offset, whence)
}

/// `gztell64` (gzlib.c).
pub fn gz_tell64(state: Option<&GzState>) -> i64 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return -1;
    }
    state.pos + if state.seek { state.skip } else { 0 }
}

/// `gztell` (gzlib.c).
pub fn gz_tell(state: Option<&GzState>) -> i64 {
    gz_tell64(state)
}

/// `gzoffset64` (gzlib.c).
pub fn gz_offset64(state: Option<&GzState>) -> i64 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return -1;
    }
    let offset = match lx::lseek(state.fd, 0, libc::SEEK_CUR) {
        Ok(o) => o,
        Err(_) => return -1,
    };
    if state.mode == GZ_READ {
        offset - state.strm.avail_in as i64 /* don't count buffered input */
    } else {
        offset
    }
}

/// `gzoffset` (gzlib.c).
pub fn gz_offset(state: Option<&GzState>) -> i64 {
    gz_offset64(state)
}

/// `gzeof` (gzlib.c).
pub fn gz_eof(state: Option<&GzState>) -> i32 {
    let Some(state) = state else {
        return 0;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return 0;
    }
    if state.mode == GZ_READ && state.past {
        1
    } else {
        0
    }
}

/// `gzerror` (gzlib.c): returns (errnum, message).
pub fn gz_error_string(state: Option<&GzState>) -> (i32, String) {
    let Some(state) = state else {
        return (0, String::new());
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return (0, String::new());
    }
    let msg = if state.err == Z_MEM_ERROR {
        "out of memory".to_string()
    } else {
        state.msg.clone().unwrap_or_default()
    };
    (state.err, msg)
}

/// `gzclearerr` (gzlib.c).
pub fn gz_clearerr(state: Option<&mut GzState>) {
    let Some(state) = state else {
        return;
    };
    if state.mode != GZ_READ && state.mode != GZ_WRITE {
        return;
    }
    if state.mode == GZ_READ {
        state.eof = false;
        state.past = false;
    }
    gz_error(state, Z_OK, None);
}

// ---------------------------------------------------------------------------
// gzread.c
// ---------------------------------------------------------------------------

/// `gz_load` — read from fd into buf, looping on short reads.  Returns
/// Err(()) on a read error (the caller sets the error state).
fn gz_load(fd: i32, buf: &mut [u8]) -> Result<u32, ()> {
    let max: usize = (u32::MAX as usize >> 2) + 1;
    let mut have = 0usize;
    let mut ret = 1i64;
    loop {
        let mut get = buf.len() - have;
        if get > max {
            get = max;
        }
        match lx::read_fd(fd, &mut buf[have..have + get]) {
            Ok(n) if n > 0 => {
                have += n;
                ret = n as i64;
            }
            Ok(_) => {
                ret = 0;
                break;
            }
            Err(_) => return Err(()),
        }
        if have >= buf.len() {
            break;
        }
    }
    Ok(have as u32)
}

/// `gz_avail` — load the input buffer, moving leftover input to the front.
fn gz_avail(state: &mut GzState) -> Result<(), ()> {
    if state.err != Z_OK && state.err != Z_BUF_ERROR {
        return Err(());
    }
    if !state.eof {
        if state.strm.avail_in != 0 {
            /* copy what's there to the start */
            let n = state.strm.avail_in as usize;
            let start = state.strm.next_in_pos;
            state.in_.copy_within(start..start + n, 0);
            state.strm.next_in_pos = 0;
        }
        let start = state.strm.avail_in as usize;
        let avail = state.strm.avail_in;
        let fd = state.fd;
        let got = match gz_load(fd, &mut state.in_[start..]) {
            Ok(g) => g,
            Err(()) => {
                gz_error(state, Z_ERRNO, Some("file error"));
                return Err(());
            }
        };
        if got == 0 {
            state.eof = true;
        }
        state.strm.avail_in = avail + got;
        state.strm.next_in_pos = 0;
    }
    Ok(())
}

/// `gz_look` — look for a gzip header, set up for inflate or copy.
fn gz_look(state: &mut GzState) -> Result<(), ()> {
    /* allocate read buffers and inflate memory */
    if state.size == 0 {
        state.in_ = vec![0u8; state.want as usize];
        state.out = vec![0u8; (state.want << 1) as usize];
        if state.in_.is_empty() || state.out.is_empty() {
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
        state.size = state.want;

        if inflate_init2(&mut state.strm, 15 + 16) != Z_OK {
            /* gunzip */
            state.size = 0;
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
    }

    /* get at least the magic bytes in the input buffer */
    if state.strm.avail_in < 2 {
        gz_avail(state)?;
        if state.strm.avail_in == 0 {
            return Ok(());
        }
    }

    /* look for gzip magic bytes -- if there, do gzip decoding */
    let base = state.strm.next_in_pos;
    if state.strm.avail_in > 1 && state.in_[base] == 31 && state.in_[base + 1] == 139 {
        super::inflate::inflate_reset(&mut state.strm);
        state.how = GZIP;
        state.direct = 0;
        return Ok(());
    }

    /* no gzip header -- if we were decoding gzip before, then this is trailing
     * garbage.  Ignore the trailing garbage and finish. */
    if state.direct == 0 {
        state.strm.avail_in = 0;
        state.eof = true;
        state.have = 0;
        return Ok(());
    }

    /* doing raw i/o, copy any leftover input to output */
    state.next = 0;
    let n = state.strm.avail_in as usize;
    state.out[..n].copy_from_slice(&state.in_[..n]);
    state.have = state.strm.avail_in;
    state.strm.avail_in = 0;
    state.how = COPY;
    state.direct = 1;
    Ok(())
}

/// `gz_decomp` — decompress into the state output buffer.
fn gz_decomp(state: &mut GzState) -> Result<(), ()> {
    let mut ret = Z_OK;
    let had = state.strm.avail_out;
    loop {
        if state.strm.avail_in == 0 && gz_avail(state).is_err() {
            return Err(());
        }
        if state.strm.avail_in == 0 {
            gz_error(state, Z_BUF_ERROR, Some("unexpected end of file"));
            break;
        }
        let inp = &state.in_
            [state.strm.next_in_pos..state.strm.next_in_pos + state.strm.avail_in as usize];
        let outp = &mut state.out
            [state.strm.next_out_pos..state.strm.next_out_pos + state.strm.avail_out as usize];
        ret = super::inflate::inflate_call_internal(&mut state.strm, inp, outp, Z_NO_FLUSH);
        if ret == Z_STREAM_ERROR || ret == Z_NEED_DICT {
            gz_error(
                state,
                Z_STREAM_ERROR,
                Some("internal error: inflate stream corrupt"),
            );
            return Err(());
        }
        if ret == Z_MEM_ERROR {
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
        if ret == Z_DATA_ERROR {
            let m = state
                .strm
                .msg
                .map_or_else(|| "compressed data error".to_string(), |m| m.to_string());
            gz_error(state, Z_DATA_ERROR, Some(&m));
            return Err(());
        }
        if state.strm.avail_out == 0 || ret == Z_STREAM_END {
            break;
        }
    }
    state.have = had - state.strm.avail_out;
    state.next = state.strm.next_out_pos - state.have as usize;
    if ret == Z_STREAM_END {
        state.how = LOOK;
    }
    Ok(())
}

/// `gz_fetch` — get data into the output buffer.
fn gz_fetch(state: &mut GzState) -> Result<(), ()> {
    loop {
        match state.how {
            LOOK => {
                gz_look(state)?;
                if state.how == LOOK {
                    return Ok(());
                }
            }
            COPY => {
                let cap = (state.size << 1) as usize;
                let fd = state.fd;
                let got = match gz_load(fd, &mut state.out[..cap]) {
                    Ok(g) => g,
                    Err(()) => {
                        gz_error(state, Z_ERRNO, Some("file error"));
                        return Err(());
                    }
                };
                if got == 0 {
                    state.eof = true;
                }
                state.have = got;
                state.next = 0;
                return Ok(());
            }
            GZIP => {
                state.strm.avail_out = state.size << 1;
                state.strm.next_out_pos = 0;
                gz_decomp(state)?;
            }
            _ => {}
        }
        if state.have != 0 {
            return Ok(());
        }
        if state.eof && state.strm.avail_in == 0 {
            return Ok(());
        }
    }
}

/// `gz_skip` — skip len uncompressed bytes.
fn gz_skip(state: &mut GzState, mut len: i64) -> Result<(), ()> {
    while len != 0 {
        if state.have != 0 {
            let n = if gt_off(state.have as u64) || state.have as i64 > len {
                len as u32
            } else {
                state.have
            };
            state.have -= n;
            state.next += n as usize;
            state.pos += n as i64;
            len -= n as i64;
        } else if state.eof && state.strm.avail_in == 0 {
            break;
        } else {
            gz_fetch(state)?;
        }
    }
    Ok(())
}

/// `gz_read` — read up to len bytes into buf (gzread.c gz_read).
fn gz_read_internal(state: &mut GzState, buf: &mut [u8], len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    /* process a skip request */
    if state.seek {
        state.seek = false;
        if gz_skip(state, state.skip).is_err() {
            return 0;
        }
    }

    let mut got = 0usize;
    let mut remaining = len;
    let mut buf_pos = 0usize;
    while remaining != 0 {
        let mut n: usize = u32::MAX as usize;
        if n > remaining {
            n = remaining;
        }

        /* first just try copying data from the output buffer */
        if state.have != 0 {
            if (state.have as usize) < n {
                n = state.have as usize;
            }
            buf[buf_pos..buf_pos + n].copy_from_slice(&state.out[state.next..state.next + n]);
            state.next += n;
            state.have -= n as u32;
        } else if state.eof && state.strm.avail_in == 0 {
            state.past = true; /* tried to read past end */
            break;
        } else if state.how == LOOK || n < (state.size << 1) as usize {
            /* get more output, looking for header if required */
            if gz_fetch(state).is_err() {
                return 0;
            }
            continue;
        } else if state.how == COPY {
            /* read directly into user buffer */
            if gz_load_into(state, &mut buf[buf_pos..buf_pos + n], &mut n).is_err() {
                return 0;
            }
        } else {
            /* state->how == GZIP: decompress directly into user buffer */
            if gz_decomp_into(state, &mut buf[buf_pos..buf_pos + n]).is_err() {
                return 0;
            }
            n = state.have as usize;
            state.have = 0;
        }

        remaining -= n;
        buf_pos += n;
        got += n;
        state.pos += n as i64;
    }
    got
}

/// Direct COPY read into the user buffer (gzread.c large-len path).
fn gz_load_into(state: &mut GzState, buf: &mut [u8], n: &mut usize) -> Result<(), ()> {
    let fd = state.fd;
    match gz_load(fd, buf) {
        Ok(g) => {
            if g == 0 {
                state.eof = true;
            }
            *n = g as usize;
            Ok(())
        }
        Err(()) => {
            gz_error(state, Z_ERRNO, Some("file error"));
            Err(())
        }
    }
}

/// Direct GZIP decompress into the user buffer.
fn gz_decomp_into(state: &mut GzState, buf: &mut [u8]) -> Result<(), ()> {
    let mut ret = Z_OK;
    let mut out_avail = buf.len() as u32;
    let mut pos = 0usize;
    loop {
        if state.strm.avail_in == 0 && gz_avail(state).is_err() {
            return Err(());
        }
        if state.strm.avail_in == 0 {
            gz_error(state, Z_BUF_ERROR, Some("unexpected end of file"));
            break;
        }
        let in_start = state.strm.next_in_pos;
        let inp = &state.in_[in_start..in_start + state.strm.avail_in as usize];
        let out_slice = &mut buf[pos..pos + out_avail as usize];
        state.strm.avail_out = out_avail;
        state.strm.next_out_pos = pos;
        ret = super::inflate::inflate_call_internal(&mut state.strm, inp, out_slice, Z_NO_FLUSH);
        out_avail = state.strm.avail_out;
        pos = state.strm.next_out_pos;
        if ret == Z_STREAM_ERROR || ret == Z_NEED_DICT {
            gz_error(
                state,
                Z_STREAM_ERROR,
                Some("internal error: inflate stream corrupt"),
            );
            return Err(());
        }
        if ret == Z_MEM_ERROR {
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
        if ret == Z_DATA_ERROR {
            let m = state
                .strm
                .msg
                .map_or_else(|| "compressed data error".to_string(), |m| m.to_string());
            gz_error(state, Z_DATA_ERROR, Some(&m));
            return Err(());
        }
        if out_avail == 0 || ret == Z_STREAM_END {
            break;
        }
    }
    state.have = pos as u32;
    state.next = pos;
    if ret == Z_STREAM_END {
        state.how = LOOK;
    }
    Ok(())
}

/// `gzread` (gzread.c).
pub fn gz_read(state: Option<&mut GzState>, buf: &mut [u8]) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ || (state.err != Z_OK && state.err != Z_BUF_ERROR) {
        return -1;
    }
    let len = buf.len();
    if len > i32::MAX as usize {
        gz_error(
            state,
            Z_STREAM_ERROR,
            Some("request does not fit in an int"),
        );
        return -1;
    }
    let got = gz_read_internal(state, buf, len);
    if got == 0 && state.err != Z_OK && state.err != Z_BUF_ERROR {
        return -1;
    }
    got as i32
}

/// `gzgetc` (gzread.c).
pub fn gz_getc(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_READ || (state.err != Z_OK && state.err != Z_BUF_ERROR) {
        return -1;
    }
    if state.have != 0 {
        state.have -= 1;
        state.pos += 1;
        let b = state.out[state.next];
        state.next += 1;
        return b as i32;
    }
    let mut one = [0u8; 1];
    if gz_read_internal(state, &mut one, 1) < 1 {
        -1
    } else {
        one[0] as i32
    }
}

/// `gzungetc` (gzread.c).
pub fn gz_ungetc(state: Option<&mut GzState>, c: i32) -> i32 {
    let Some(state) = state else {
        return -1;
    };

    /* in case this was just opened, set up the input buffer */
    if state.mode == GZ_READ && state.how == LOOK && state.have == 0 {
        let _ = gz_look(state);
    }

    if state.mode != GZ_READ || (state.err != Z_OK && state.err != Z_BUF_ERROR) {
        return -1;
    }

    /* process a skip request */
    if state.seek {
        state.seek = false;
        if gz_skip(state, state.skip).is_err() {
            return -1;
        }
    }

    /* can't push EOF */
    if c < 0 {
        return -1;
    }

    /* if output buffer empty, put byte at end (allows more pushing) */
    if state.have == 0 {
        state.have = 1;
        state.next = (state.size << 1) as usize - 1;
        state.out[state.next] = c as u8;
        state.pos -= 1;
        state.past = false;
        return c;
    }

    /* if no room, give up (must have already done a gzungetc()) */
    if state.have == (state.size << 1) {
        gz_error(state, Z_DATA_ERROR, Some("out of room to push characters"));
        return -1;
    }

    /* slide output data if needed and insert byte before existing data */
    if state.next == 0 {
        let n = state.have as usize;
        let dest = (state.size << 1) as usize;
        for i in (0..n).rev() {
            state.out[dest - n + i] = state.out[i];
        }
        state.next = dest - n;
    }
    state.have += 1;
    state.next -= 1;
    state.out[state.next] = c as u8;
    state.pos -= 1;
    state.past = false;
    c
}

/// `gzgets` (gzread.c).
pub fn gz_gets(state: Option<&mut GzState>, buf: &mut [u8]) -> Option<usize> {
    let Some(state) = state else {
        return None;
    };
    if buf.is_empty() {
        return None;
    }
    if state.mode != GZ_READ || (state.err != Z_OK && state.err != Z_BUF_ERROR) {
        return None;
    }

    /* process a skip request */
    if state.seek {
        state.seek = false;
        if gz_skip(state, state.skip).is_err() {
            return None;
        }
    }

    let mut left = buf.len() - 1;
    let mut out_pos = 0usize;
    let mut eol: Option<usize> = None;
    if left != 0 {
        loop {
            if state.have == 0 && gz_fetch(state).is_err() {
                return None;
            }
            if state.have == 0 {
                state.past = true;
                break;
            }
            let mut n = if state.have as usize > left {
                left
            } else {
                state.have as usize
            };
            let mut eol_local = None;
            for i in 0..n {
                if state.out[state.next + i] == b'\n' {
                    eol_local = Some(i);
                    break;
                }
            }
            if let Some(e) = eol_local {
                n = e + 1;
                eol = Some(n);
            }
            buf[out_pos..out_pos + n].copy_from_slice(&state.out[state.next..state.next + n]);
            state.have -= n as u32;
            state.next += n;
            state.pos += n as i64;
            left -= n;
            out_pos += n;
            if left == 0 || eol.is_some() {
                break;
            }
        }
    }

    if out_pos == 0 {
        return None;
    }
    buf[out_pos] = 0;
    Some(out_pos)
}

/// `gzdirect` (gzread.c).
pub fn gz_direct(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return 0;
    };
    if state.mode == GZ_READ && state.how == LOOK && state.have == 0 {
        let _ = gz_look(state);
    }
    state.direct
}

/// `gzclose_r` (gzread.c).
pub fn gz_close_r(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode != GZ_READ {
        return Z_STREAM_ERROR;
    }
    if state.size != 0 {
        let _ = inflate_end(&mut state.strm);
    }
    let err = if state.err == Z_BUF_ERROR {
        Z_BUF_ERROR
    } else {
        Z_OK
    };
    gz_error(state, Z_OK, None);
    let fd = state.fd;
    lx::close(fd);
    err
}

// ---------------------------------------------------------------------------
// gzwrite.c
// ---------------------------------------------------------------------------

/// `gz_init` — initialize state for writing.
fn gz_init(state: &mut GzState) -> Result<(), ()> {
    /* allocate input buffer (double size for gzprintf) */
    state.in_ = vec![0u8; (state.want << 1) as usize];
    if state.in_.is_empty() {
        gz_error(state, Z_MEM_ERROR, Some("out of memory"));
        return Err(());
    }

    /* only need output buffer and deflate state if compressing */
    if state.direct == 0 {
        state.out = vec![0u8; state.want as usize];
        if state.out.is_empty() {
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
        let ret = deflate_init2(
            &mut state.strm,
            state.level,
            Z_DEFLATED,
            MAX_WBITS + 16,
            DEF_MEM_LEVEL,
            state.strategy,
        );
        if ret != Z_OK {
            gz_error(state, Z_MEM_ERROR, Some("out of memory"));
            return Err(());
        }
        state.strm.next_in_pos = 0;
    }

    state.size = state.want;

    if state.direct == 0 {
        state.strm.avail_out = state.size;
        state.strm.next_out_pos = 0;
        state.next = state.strm.next_out_pos;
    }
    Ok(())
}

/// `gz_comp` — compress whatever is at avail_in and write to the file.
fn gz_comp(state: &mut GzState, flush: i32) -> Result<(), ()> {
    let max: usize = (u32::MAX as usize >> 2) + 1;

    if state.size == 0 && gz_init(state).is_err() {
        return Err(());
    }

    /* write directly if requested */
    if state.direct != 0 {
        while state.strm.avail_in != 0 {
            let put = if state.strm.avail_in as usize > max {
                max
            } else {
                state.strm.avail_in as usize
            };
            let start = state.strm.next_in_pos;
            match lx::write_fd(state.fd, &state.in_[start..start + put]) {
                Ok(w) => {
                    state.strm.next_in_pos += w;
                    state.strm.avail_in -= w as u32;
                }
                Err(_) => {
                    gz_error(state, Z_ERRNO, Some("file error"));
                    return Err(());
                }
            }
        }
        return Ok(());
    }

    /* check for a pending reset */
    if state.reset {
        if state.strm.avail_in == 0 {
            return Ok(());
        }
        let _ = deflate_reset(&mut state.strm);
        state.reset = false;
    }

    let mut ret = Z_OK;
    loop {
        /* write out current buffer contents if full, or if flushing */
        if state.strm.avail_out == 0
            || (flush != Z_NO_FLUSH && (flush != Z_FINISH || ret == Z_STREAM_END))
        {
            while state.strm.next_out_pos > state.next {
                let put = if state.strm.next_out_pos - state.next > max {
                    max
                } else {
                    state.strm.next_out_pos - state.next
                };
                match lx::write_fd(state.fd, &state.out[state.next..state.next + put]) {
                    Ok(w) => state.next += w,
                    Err(_) => {
                        gz_error(state, Z_ERRNO, Some("file error"));
                        return Err(());
                    }
                }
            }
            if state.strm.avail_out == 0 {
                state.strm.avail_out = state.size;
                state.strm.next_out_pos = 0;
                state.next = 0;
            }
        }

        /* compress */
        let have = state.strm.avail_out;
        let inp = &state.in_
            [state.strm.next_in_pos..state.strm.next_in_pos + state.strm.avail_in as usize];
        let outp = &mut state.out
            [state.strm.next_out_pos..state.strm.next_out_pos + state.strm.avail_out as usize];
        ret = super::deflate::deflate_call_internal(&mut state.strm, inp, outp, flush);
        if ret == Z_STREAM_ERROR {
            gz_error(
                state,
                Z_STREAM_ERROR,
                Some("internal error: deflate stream corrupt"),
            );
            return Err(());
        }
        if state.strm.avail_out < have {
            // produced output; loop again to write it out
        } else {
            break;
        }
    }

    /* if that completed a deflate stream, allow another to start */
    if flush == Z_FINISH {
        state.reset = true;
    }

    Ok(())
}

/// `gz_zero` — compress len zeros to output.
fn gz_zero(state: &mut GzState, mut len: i64) -> Result<(), ()> {
    if state.strm.avail_in != 0 && gz_comp(state, Z_NO_FLUSH).is_err() {
        return Err(());
    }
    let mut first = true;
    while len != 0 {
        let n = if gt_off(state.size as u64) || state.size as i64 > len {
            len as u32
        } else {
            state.size
        };
        if first {
            state.in_[..n as usize].fill(0);
            first = false;
        }
        state.strm.avail_in = n;
        state.strm.next_in_pos = 0;
        state.pos += n as i64;
        if gz_comp(state, Z_NO_FLUSH).is_err() {
            return Err(());
        }
        len -= n as i64;
    }
    Ok(())
}

/// `gz_write` — write len bytes from buf (gzwrite.c gz_write).
fn gz_write_internal(state: &mut GzState, buf: &[u8], len: usize) -> usize {
    let put = len;
    if len == 0 {
        return 0;
    }
    if state.size == 0 && gz_init(state).is_err() {
        return 0;
    }
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            return 0;
        }
    }

    let mut remaining = len;
    let mut buf_pos = 0usize;
    if remaining < state.size as usize {
        /* copy to input buffer, compress when full */
        loop {
            if state.strm.avail_in == 0 {
                state.strm.next_in_pos = 0;
            }
            let have = state.strm.next_in_pos + state.strm.avail_in as usize;
            let mut copy = state.size as usize - have;
            if copy > remaining {
                copy = remaining;
            }
            state.in_[have..have + copy].copy_from_slice(&buf[buf_pos..buf_pos + copy]);
            state.strm.avail_in += copy as u32;
            state.pos += copy as i64;
            buf_pos += copy;
            remaining -= copy;
            if remaining != 0 && gz_comp(state, Z_NO_FLUSH).is_err() {
                return 0;
            }
            if remaining == 0 {
                break;
            }
        }
    } else {
        /* consume whatever's left in the input buffer */
        if state.strm.avail_in != 0 && gz_comp(state, Z_NO_FLUSH).is_err() {
            return 0;
        }
        /* directly compress user buffer to file */
        state.strm.next_in_pos = 0;
        loop {
            let mut n: usize = u32::MAX as usize;
            if n > remaining {
                n = remaining;
            }
            state.strm.avail_in = n as u32;
            state.pos += n as i64;
            // the deflate state reads from in_, so copy the chunk there
            state.in_[..n].copy_from_slice(&buf[buf_pos..buf_pos + n]);
            state.strm.next_in_pos = 0;
            if gz_comp(state, Z_NO_FLUSH).is_err() {
                return 0;
            }
            buf_pos += n;
            remaining -= n;
            if remaining == 0 {
                break;
            }
        }
    }
    put
}

/// `gzwrite` (gzwrite.c).
pub fn gz_write(state: Option<&mut GzState>, buf: &[u8]) -> i32 {
    let Some(state) = state else {
        return 0;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK {
        return 0;
    }
    let len = buf.len();
    if len > i32::MAX as usize {
        gz_error(
            state,
            Z_DATA_ERROR,
            Some("requested length does not fit in int"),
        );
        return 0;
    }
    gz_write_internal(state, buf, len) as i32
}

/// `gzputc` (gzwrite.c).
pub fn gz_putc(state: Option<&mut GzState>, c: i32) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK {
        return -1;
    }
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            return -1;
        }
    }
    if state.size != 0 {
        if state.strm.avail_in == 0 {
            state.strm.next_in_pos = 0;
        }
        let have = state.strm.next_in_pos + state.strm.avail_in as usize;
        if have < state.in_.len() {
            state.in_[have] = c as u8;
            state.strm.avail_in += 1;
            state.pos += 1;
            return c & 0xff;
        }
    }
    let one = [c as u8];
    if gz_write_internal(state, &one, 1) != 1 {
        return -1;
    }
    c & 0xff
}

/// `gzputs` (gzwrite.c).
pub fn gz_puts(state: Option<&mut GzState>, s: &str) -> i32 {
    let Some(state) = state else {
        return -1;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK {
        return -1;
    }
    let len = s.len();
    if len > i32::MAX as usize {
        gz_error(
            state,
            Z_STREAM_ERROR,
            Some("string length does not fit in int"),
        );
        return -1;
    }
    let put = gz_write_internal(state, s.as_bytes(), len);
    if put < len {
        -1
    } else {
        len as i32
    }
}

// ---------------------------------------------------------------------------
// gzprintf (gzwrite.c gzvprintf) — glibc-vsnprintf-compatible formatter
// ---------------------------------------------------------------------------

/// One vararg for `gz_printf` (the C variadic argument list).  C promotions
/// are applied by the caller: `char`/`short`/`int` -> `I`, `float` -> `D`,
/// `size_t`/`unsigned` -> `U`, `char *` -> `S`, `void *` -> `P`.
#[derive(Debug, Clone)]
pub enum GzPrintfArg {
    /// signed integer argument (int/long/long long/ptrdiff_t/intmax_t)
    I(i64),
    /// unsigned integer argument (unsigned/long/unsigned long long/size_t)
    U(u64),
    /// double argument (float is promoted to double)
    D(f64),
    /// `%s` string argument
    S(String),
    /// `%p` pointer argument, rendered deterministically (no real addresses)
    P(usize),
}

#[derive(Default)]
struct FmtSpec {
    left: bool,
    zero: bool,
    plus: bool,
    space: bool,
    alt: bool,
    width: Option<usize>,
    prec: Option<usize>,
    len: u8, // 0 none, 1 h, 2 hh, 3 l, 4 ll, 5 z, 6 t, 7 j
}

/// glibc `printf` output for one conversion, matching the observable byte
/// surface of the glibc used in the oracle containers (bookworm).
fn fmt_char(c: u8, spec: &FmtSpec) -> String {
    let mut s = String::new();
    s.push(c as char);
    let w = spec.width.unwrap_or(0);
    if s.len() < w {
        let pad = if spec.zero && !spec.left { "0" } else { " " };
        let n = w - s.len();
        if spec.left {
            s.push_str(&pad.repeat(n));
        } else {
            s = format!("{}{}", pad.repeat(n), s);
        }
    }
    s
}

fn fmt_str(s: &str, spec: &FmtSpec) -> String {
    let v = match spec.prec {
        Some(p) if p < s.len() => &s[..p],
        _ => s,
    };
    let w = spec.width.unwrap_or(0);
    if v.len() >= w {
        return v.to_string();
    }
    let n = w - v.len();
    if spec.left {
        format!("{}{}", v, " ".repeat(n))
    } else {
        format!("{}{}", " ".repeat(n), v)
    }
}

fn fmt_int(value: i64, spec: &FmtSpec) -> String {
    let negative = value < 0;
    let sign = if negative {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let mag = value.unsigned_abs();
    let mut digits = if mag == 0 {
        String::new()
    } else {
        format!("{mag}")
    };
    if let Some(p) = spec.prec {
        while digits.len() < p {
            digits.insert(0, '0');
        }
    }
    // precision 0 and value 0 -> empty digits
    if spec.prec == Some(0) && mag == 0 {
        digits.clear();
    }
    let body = format!("{sign}{digits}");
    let w = spec.width.unwrap_or(0);
    if body.len() >= w {
        return body;
    }
    let n = w - body.len();
    if spec.left {
        format!("{body}{}", " ".repeat(n))
    } else if spec.zero && spec.prec.is_none() {
        // zeros go between the sign and the digits
        format!("{sign}{}{digits}", "0".repeat(n))
    } else {
        format!("{}{body}", " ".repeat(n))
    }
}

fn fmt_uint(value: u64, base: u32, upper: bool, spec: &FmtSpec) -> String {
    let mut digits = if value == 0 {
        String::new()
    } else if base == 16 {
        format!("{value:x}")
    } else if base == 8 {
        format!("{value:o}")
    } else {
        format!("{value}")
    };
    if upper {
        digits = digits.to_uppercase();
    }
    if let Some(p) = spec.prec {
        while digits.len() < p {
            digits.insert(0, '0');
        }
    }
    if spec.prec == Some(0) && value == 0 {
        digits.clear();
    }
    // alternate form
    let mut prefix = String::new();
    if spec.alt {
        match base {
            8 => {
                if !digits.starts_with('0') {
                    prefix.push('0');
                }
            }
            16 if value != 0 => {
                prefix.push_str(if upper { "0X" } else { "0x" });
            }
            _ => {}
        }
    }
    let body = format!("{prefix}{digits}");
    let w = spec.width.unwrap_or(0);
    if body.len() >= w {
        return body;
    }
    let n = w - body.len();
    if spec.left {
        format!("{body}{}", " ".repeat(n))
    } else if spec.zero && spec.prec.is_none() {
        // zeros go after the prefix (glibc %#08x -> 0x00001a)
        format!("{prefix}{}{digits}", "0".repeat(n))
    } else {
        format!("{}{body}", " ".repeat(n))
    }
}

fn fmt_ptr(v: usize, spec: &FmtSpec) -> String {
    if v == 0 {
        // glibc renders NULL as "(nil)"
        let s = "(nil)".to_string();
        let w = spec.width.unwrap_or(0);
        if s.len() >= w {
            return s;
        }
        let n = w - s.len();
        if spec.left {
            format!("{s}{}", " ".repeat(n))
        } else {
            format!("{}{s}", " ".repeat(n))
        }
    } else {
        let hex = format!("{v:x}");
        let w = spec.width.unwrap_or(0);
        if spec.zero && !spec.left && w > hex.len() + 2 {
            let n = w - hex.len() - 2;
            format!("0x{}{hex}", "0".repeat(n))
        } else {
            let s = format!("0x{hex}");
            if s.len() >= w {
                return s;
            }
            let n = w - s.len();
            if spec.left {
                format!("{s}{}", " ".repeat(n))
            } else {
                format!("{}{s}", " ".repeat(n))
            }
        }
    }
}

/// Format a float per C `%e`/`%f`/`%g` (glibc rounding; bookworm).
fn fmt_float(v: f64, conv: u8, spec: &FmtSpec) -> String {
    let upper = conv == b'E' || conv == b'F' || conv == b'G';
    let base = if conv == b'e' || conv == b'E' {
        b'e'
    } else if conv == b'f' || conv == b'F' {
        b'f'
    } else {
        b'g'
    };
    let prec = spec.prec.unwrap_or(6);
    let negative = v.is_sign_negative();
    let sign = if negative {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let a = v.abs();

    let body = if a.is_nan() {
        if upper { "NAN" } else { "nan" }.to_string()
    } else if a.is_infinite() {
        if upper { "INF" } else { "inf" }.to_string()
    } else {
        match base {
            b'e' => {
                // d.ddd e±XX (exponent sign always, at least two digits)
                let s = format!("{a:.prec$e}");
                let (mant, exp) = s.split_once('e').unwrap();
                let x: i64 = exp.parse().unwrap();
                let mut m = mant.to_string();
                if prec == 0 && spec.alt && !m.contains('.') {
                    m.push('.');
                }
                format!(
                    "{m}{}{}{}",
                    if upper { "E" } else { "e" },
                    if x < 0 { '-' } else { '+' },
                    format!("{:02}", x.abs())
                )
            }
            b'f' => {
                let mut s = format!("{a:.prec$}");
                if prec == 0 && spec.alt && !s.contains('.') {
                    s.push('.');
                }
                s
            }
            _ => {
                // %g: P = precision (0 -> 1); exponent of the rounded value
                let p = if prec == 0 { 1 } else { prec };
                let s = format!("{a:.p$e}", p = p - 1);
                let (mant, exp) = s.split_once('e').unwrap();
                let x: i64 = exp.parse().unwrap();
                let mut digits: Vec<u8> = mant.bytes().filter(|&b| b != b'.').collect();
                if x < -4 || x >= p as i64 {
                    // %e style with the rounded mantissa, zeros stripped
                    while !spec.alt && digits.len() > 1 && *digits.last().unwrap() == b'0' {
                        digits.pop();
                    }
                    let mut m = String::new();
                    m.push(digits[0] as char);
                    if digits.len() > 1 {
                        m.push('.');
                        m.push_str(&String::from_utf8_lossy(&digits[1..]));
                    }
                    format!(
                        "{m}{}{}{}",
                        if upper { "E" } else { "e" },
                        if x < 0 { '-' } else { '+' },
                        format!("{:02}", x.abs())
                    )
                } else {
                    // %f style with p-1-x decimals, zeros stripped
                    let dec = (p as i64 - 1 - x) as usize;
                    while !spec.alt && digits.len() > 1 && *digits.last().unwrap() == b'0' {
                        digits.pop();
                    }
                    if x < 0 {
                        let mut m = String::from("0.");
                        for _ in 0..(-x - 1) {
                            m.push('0');
                        }
                        m.push_str(&String::from_utf8_lossy(&digits));
                        m
                    } else {
                        let int_len = (x + 1) as usize;
                        let mut m = String::new();
                        if int_len >= digits.len() {
                            m.push_str(&String::from_utf8_lossy(&digits));
                            for _ in digits.len()..int_len {
                                m.push('0');
                            }
                        } else {
                            m.push_str(&String::from_utf8_lossy(&digits[..int_len]));
                            m.push('.');
                            m.push_str(&String::from_utf8_lossy(&digits[int_len..]));
                        }
                        let _ = dec;
                        m
                    }
                }
            }
        }
    };

    let w = spec.width.unwrap_or(0);
    let full = format!("{sign}{body}");
    if full.len() >= w {
        return full;
    }
    let n = w - full.len();
    if spec.left {
        format!("{full}{}", " ".repeat(n))
    } else if spec.zero && a.is_finite() {
        // zeros go between the sign and the mantissa
        format!("{sign}{}{body}", "0".repeat(n))
    } else {
        format!("{}{full}", " ".repeat(n))
    }
}

/// Format a glibc-printf-format string against `args`.  Returns the bytes
/// vsnprintf would have produced (or an error for a malformed/unsupported
/// spec).  Only the conversions the ecosystem observes are implemented;
/// unknown conversions are passed through literally like glibc.
fn printf_format(format: &str, args: &[GzPrintfArg]) -> Result<String, ()> {
    let b = format.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    let mut ai = 0usize;
    let mut take = |ai: &mut usize, args: &[GzPrintfArg]| -> Result<GzPrintfArg, ()> {
        let a = args.get(*ai).cloned().ok_or(())?;
        *ai += 1;
        Ok(a)
    };
    while i < b.len() {
        let c = b[i];
        if c != b'%' {
            out.push(c as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push('%');
            break;
        }
        if b[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }
        let mut spec = FmtSpec::default();
        loop {
            if i >= b.len() {
                break;
            }
            match b[i] {
                b'-' => {
                    spec.left = true;
                    i += 1;
                }
                b'+' => {
                    spec.plus = true;
                    i += 1;
                }
                b' ' => {
                    spec.space = true;
                    i += 1;
                }
                b'0' => {
                    spec.zero = true;
                    i += 1;
                }
                b'#' => {
                    spec.alt = true;
                    i += 1;
                }
                _ => break,
            }
        }
        if i >= b.len() {
            out.push('%');
            break;
        }
        // width
        if b[i] == b'*' {
            i += 1;
            let GzPrintfArg::I(w) = take(&mut ai, args)? else {
                return Err(());
            };
            if w < 0 {
                spec.left = true;
                spec.width = Some(w.unsigned_abs() as usize);
            } else {
                spec.width = Some(w as usize);
            }
        } else if b[i].is_ascii_digit() {
            let mut w = 0usize;
            while i < b.len() && b[i].is_ascii_digit() {
                w = w.saturating_mul(10).saturating_add((b[i] - b'0') as usize);
                i += 1;
            }
            spec.width = Some(w);
        }
        if i >= b.len() {
            out.push('%');
            break;
        }
        // precision
        if b[i] == b'.' {
            i += 1;
            if i >= b.len() {
                out.push('%');
                break;
            }
            if b[i] == b'*' {
                i += 1;
                let GzPrintfArg::I(p) = take(&mut ai, args)? else {
                    return Err(());
                };
                spec.prec = if p >= 0 { Some(p as usize) } else { None };
            } else {
                let mut p = 0usize;
                while i < b.len() && b[i].is_ascii_digit() {
                    p = p.saturating_mul(10).saturating_add((b[i] - b'0') as usize);
                    i += 1;
                }
                spec.prec = Some(p);
            }
        }
        if i >= b.len() {
            out.push('%');
            break;
        }
        // length modifier
        match b[i] {
            b'l' => {
                i += 1;
                if i < b.len() && b[i] == b'l' {
                    spec.len = 4;
                    i += 1;
                } else {
                    spec.len = 3;
                }
            }
            b'h' => {
                i += 1;
                if i < b.len() && b[i] == b'h' {
                    spec.len = 2;
                    i += 1;
                } else {
                    spec.len = 1;
                }
            }
            b'z' => {
                spec.len = 5;
                i += 1;
            }
            b't' => {
                spec.len = 6;
                i += 1;
            }
            b'j' => {
                spec.len = 7;
                i += 1;
            }
            _ => {}
        }
        if i >= b.len() {
            out.push('%');
            break;
        }
        let conv = b[i];
        i += 1;
        let piece = match conv {
            b'c' => {
                let GzPrintfArg::I(v) = take(&mut ai, args)? else {
                    return Err(());
                };
                fmt_char((v & 0xff) as u8, &spec)
            }
            b's' => {
                let GzPrintfArg::S(v) = take(&mut ai, args)? else {
                    return Err(());
                };
                fmt_str(&v, &spec)
            }
            b'd' | b'i' => {
                let GzPrintfArg::I(v) = take(&mut ai, args)? else {
                    return Err(());
                };
                let v = match spec.len {
                    1 => (v as i16) as i64,
                    2 => (v as i8) as i64,
                    _ => v,
                };
                fmt_int(v, &spec)
            }
            b'u' | b'o' | b'x' | b'X' => {
                let a = take(&mut ai, args)?;
                let v = match a {
                    GzPrintfArg::U(v) => v,
                    GzPrintfArg::I(v) => v as u64,
                    _ => return Err(()),
                };
                let v = match spec.len {
                    1 => v as u16 as u64,
                    2 => v as u8 as u64,
                    _ => v,
                };
                fmt_uint(
                    v,
                    if conv == b'o' {
                        8
                    } else if conv == b'x' || conv == b'X' {
                        16
                    } else {
                        10
                    },
                    conv == b'X',
                    &spec,
                )
            }
            b'p' => {
                let GzPrintfArg::P(v) = take(&mut ai, args)? else {
                    return Err(());
                };
                fmt_ptr(v, &spec)
            }
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => {
                let GzPrintfArg::D(v) = take(&mut ai, args)? else {
                    return Err(());
                };
                fmt_float(v, conv, &spec)
            }
            _ => {
                // glibc prints unknown conversions literally
                format!("%{}", conv as char)
            }
        };
        out.push_str(&piece);
    }
    Ok(out)
}

/// `gzprintf` (gzwrite.c gzvprintf) — format `format` with `args` and write
/// the result to the gzip stream, returning the number of bytes written
/// (0 if the result does not fit the internal buffer, Z_STREAM_ERROR on
/// mode/state errors), exactly like the C.
pub fn gz_printf(state: Option<&mut GzState>, format: &str, args: &[GzPrintfArg]) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK {
        return Z_STREAM_ERROR;
    }
    if state.size == 0 && gz_init(state).is_err() {
        return state.err;
    }
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            return state.err;
        }
    }
    if state.strm.avail_in == 0 {
        state.strm.next_in_pos = 0;
    }
    let have = state.strm.next_in_pos + state.strm.avail_in as usize;
    let size = state.size as usize;

    let Ok(s) = printf_format(format, args) else {
        return 0;
    };
    let len = s.len();
    if len == 0 || len >= size {
        return 0;
    }
    state.in_[have..have + len].copy_from_slice(s.as_bytes());
    state.strm.avail_in += len as u32;
    state.pos += len as i64;
    if state.strm.avail_in >= state.size {
        let left = state.strm.avail_in - state.size;
        state.strm.avail_in = state.size;
        if gz_comp(state, Z_NO_FLUSH).is_err() {
            return state.err;
        }
        state.in_.copy_within(size..size + left as usize, 0);
        state.strm.next_in_pos = 0;
        state.strm.avail_in = left;
    }
    len as i32
}

/// `gzflush` (gzwrite.c).
pub fn gz_flush(state: Option<&mut GzState>, flush: i32) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK {
        return Z_STREAM_ERROR;
    }
    if flush < 0 || flush > Z_FINISH {
        return Z_STREAM_ERROR;
    }
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            return state.err;
        }
    }
    let _ = gz_comp(state, flush);
    state.err
}

/// `gzsetparams` (gzwrite.c).
pub fn gz_setparams(state: Option<&mut GzState>, level: i32, strategy: i32) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode != GZ_WRITE || state.err != Z_OK || state.direct != 0 {
        return Z_STREAM_ERROR;
    }
    if level == state.level && strategy == state.strategy {
        return Z_OK;
    }
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            return state.err;
        }
    }
    if state.size != 0 {
        if state.strm.avail_in != 0 && gz_comp(state, Z_BLOCK).is_err() {
            return state.err;
        }
        let _ = deflate_params(&mut state.strm, level, strategy);
    }
    state.level = level;
    state.strategy = strategy;
    Z_OK
}

/// `gzclose_w` (gzwrite.c).
pub fn gz_close_w(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode != GZ_WRITE {
        return Z_STREAM_ERROR;
    }
    let mut ret = Z_OK;
    if state.seek {
        state.seek = false;
        if gz_zero(state, state.skip).is_err() {
            ret = state.err;
        }
    }
    if gz_comp(state, Z_FINISH).is_err() {
        ret = state.err;
    }
    if state.size != 0 && state.direct == 0 {
        let _ = deflate_end(&mut state.strm);
    }
    gz_error(state, Z_OK, None);
    let fd = state.fd;
    lx::close(fd);
    ret
}

/// `gzclose` (gzclose.c).
pub fn gz_close(state: Option<&mut GzState>) -> i32 {
    let Some(state) = state else {
        return Z_STREAM_ERROR;
    };
    if state.mode == GZ_READ {
        gz_close_r(Some(state))
    } else {
        gz_close_w(Some(state))
    }
}
