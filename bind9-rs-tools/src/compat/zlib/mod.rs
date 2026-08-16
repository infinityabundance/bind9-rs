//! `compat::zlib` — zlib 1.3.1 conservation (§34).
//!
//! Native-Rust custodian implementation of the zlib compression library,
//! not a wrapper around a Rust compression crate:
//!
//! - the full deflate encoder (deflate.c + trees.c): the LZ77 hash-chain
//!   matcher with lazy evaluation, the per-level configuration table, stored/
//!   fixed/dynamic block selection with the exact opt_len/static_len
//!   accounting, the Huffman tree construction (gen_codes, build_tree,
//!   scan_tree/send_tree, the bl_tree repeat codes), the bit-level emitter
//!   (bi_buf/bi_valid, send_bits, bi_flush, bi_windup), and byte-exact
//!   output for every level/strategy/flush combination;
//! - the inflate decoder (inflate.c + inftrees.c + inffast.c): the full
//!   state machine with zlib/gzip/raw/auto wrappers, header parsing incl.
//!   FNAME/FCOMMENT/FEXTRA/FHCRC, the code-table builder, the fixed and
//!   dynamic decoding paths, inflateSync/inflatePrime/inflateCopy/inflateMark,
//!   and the exact error taxonomy and message strings;
//! - the one-shot API (compress/compress2/uncompress/uncompress2 and
//!   compressBound);
//! - the checksums (adler32 incl. the NMAX=5552 deferral and combine
//!   formula; crc32 with the byte-wise core and the GF(2) combine operator);
//! - the gz* file layer (gzlib/gzread/gzwrite/gzclose): gzopen/gzdopen,
//!   gzread/gzgetc/gzgets/gzungetc, gzwrite/gzputc/gzputs/gzprintf,
//!   gzseek/gztell/gzoffset/gzrewind, gzflush/gzsetparams, gzerror/
//!   gzclearerr, gzclose_r/gzclose_w, with the exact buffering, error and
//!   return conventions (fd operations terminate in `platform::linux`,
//!   addendum §2);
//! - the utility surface: zlibVersion, ZLIB_VERSION, zlibCompileFlags,
//!   zError/z_errmsg.
//!
//! Every function maps to the pinned C source:
//! `bind9-rs-tools/forensics/sources/zlib-1.3.1.tar.gz` (workspace root).
//! Courts: ZLIB-* (C zlib oracle ↔ this module, byte-exact stdout).

pub mod checksum;
pub mod deflate;
pub mod gz;
pub mod inflate;
pub mod inftrees;
mod trees;

pub use checksum::{adler32, adler32_combine, adler32_z, crc32, crc32_combine};
pub use deflate::{
    compress, compress2, compress_bound, deflate, deflate_bound, deflate_copy, deflate_end,
    deflate_get_dictionary, deflate_init, deflate_init2, deflate_params, deflate_pending,
    deflate_prime, deflate_reset, deflate_reset_keep, deflate_set_dictionary, deflate_set_header,
    deflate_set_strategy, deflate_tune, uncompress, uncompress2, GzHeader, ZStream,
};
pub use gz::{
    gz_buffer, gz_clearerr, gz_close, gz_close_r, gz_close_w, gz_direct, gz_eof, gz_error_string,
    gz_flush, gz_getc, gz_gets, gz_offset, gz_open, gz_printf, gz_putc, gz_puts, gz_read,
    gz_rewind, gz_seek, gz_setparams, gz_tell, gz_ungetc, gz_write, gzdopen, GzPrintfArg,
};
pub use inflate::{
    inflate, inflate_copy, inflate_end, inflate_get_dictionary, inflate_get_header, inflate_init,
    inflate_init2, inflate_mark, inflate_prime, inflate_reset, inflate_reset2, inflate_reset_keep,
    inflate_set_dictionary, inflate_sync, inflate_sync_point, inflate_validate,
};

// ---------------------------------------------------------------------------
// Constants (zlib.h, zconf.h)
// ---------------------------------------------------------------------------

pub const ZLIB_VERSION: &str = "1.3.1";
pub const ZLIB_VERNUM: u32 = 0x1310;

pub const Z_NO_FLUSH: i32 = 0;
pub const Z_PARTIAL_FLUSH: i32 = 1;
pub const Z_SYNC_FLUSH: i32 = 2;
pub const Z_FULL_FLUSH: i32 = 3;
pub const Z_FINISH: i32 = 4;
pub const Z_BLOCK: i32 = 5;
pub const Z_TREES: i32 = 6;

pub const Z_OK: i32 = 0;
pub const Z_STREAM_END: i32 = 1;
pub const Z_NEED_DICT: i32 = 2;
pub const Z_ERRNO: i32 = -1;
pub const Z_STREAM_ERROR: i32 = -2;
pub const Z_DATA_ERROR: i32 = -3;
pub const Z_MEM_ERROR: i32 = -4;
pub const Z_BUF_ERROR: i32 = -5;
pub const Z_VERSION_ERROR: i32 = -6;

pub const Z_NO_COMPRESSION: i32 = 0;
pub const Z_BEST_SPEED: i32 = 1;
pub const Z_BEST_COMPRESSION: i32 = 9;
pub const Z_DEFAULT_COMPRESSION: i32 = -1;

pub const Z_FILTERED: i32 = 1;
pub const Z_HUFFMAN_ONLY: i32 = 2;
pub const Z_RLE: i32 = 3;
pub const Z_FIXED: i32 = 4;
pub const Z_DEFAULT_STRATEGY: i32 = 0;

pub const Z_BINARY: i32 = 0;
pub const Z_TEXT: i32 = 1;
pub const Z_ASCII: i32 = Z_TEXT;
pub const Z_UNKNOWN: i32 = 2;

pub const Z_DEFLATED: i32 = 8;

pub const MAX_WBITS: i32 = 15;
pub const MAX_MEM_LEVEL: i32 = 9;

/// `zlibVersion()` — the pinned library version string.
#[must_use]
pub const fn zlib_version() -> &'static str {
    ZLIB_VERSION
}

/// `zlibCompileFlags()` — the uLong bit flags describing the build.
/// The Linux bookworm build: uInt/uLong/voidpf/z_off_t are all 4/8/8/8
/// bytes => flags 1 + (2<<2) + (2<<4) + (2<<6); STDC/vsnprintf present and
/// returning int (no HAS_vsnprintf_void) => no 1<<25/1<<26 bits.
#[must_use]
pub const fn zlib_compile_flags() -> u32 {
    let mut flags: u32 = 0;
    // sizeof(uInt) == 4
    flags += 1;
    // sizeof(uLong) == 8
    flags += 2 << 2;
    // sizeof(voidpf) == 8
    flags += 2 << 4;
    // sizeof(z_off_t) == 8
    flags += 2 << 6;
    flags
}

/// `z_errmsg[]` indexed by `2 - err` (zutil.c).
pub static Z_ERRMSG: [&str; 10] = [
    "need dictionary",      /* Z_NEED_DICT       2  */
    "stream end",           /* Z_STREAM_END      1  */
    "",                     /* Z_OK              0  */
    "file error",           /* Z_ERRNO         (-1) */
    "stream error",         /* Z_STREAM_ERROR  (-2) */
    "data error",           /* Z_DATA_ERROR    (-3) */
    "insufficient memory",  /* Z_MEM_ERROR     (-4) */
    "buffer error",         /* Z_BUF_ERROR     (-5) */
    "incompatible version", /* Z_VERSION_ERROR (-6) */
    "",
];

/// `ERR_MSG(err)` — z_errmsg[2 - err] clamped to the table (zutil.h).
#[must_use]
pub fn err_msg(err: i32) -> &'static str {
    if err < -6 || err > 2 {
        Z_ERRMSG[9]
    } else {
        Z_ERRMSG[(2 - err) as usize]
    }
}

/// `zError(err)` — error string for the one-shot API errors.
#[must_use]
pub fn z_error(err: i32) -> &'static str {
    err_msg(err)
}
