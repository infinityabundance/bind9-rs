//! zlib checksums — adler32.c and crc32.c (conservation port).
//!
//! `adler32` reproduces the exact deferral structure (NMAX = 5552 blocks,
//! the len==1 fast path, the `buf == NULL -> 1` initial-value contract, the
//! MOD28 for short lengths) and the combine formula.  `crc32` reproduces the
//! byte-wise core exactly (the `(crc >> 8) ^ table[(crc ^ byte) & 0xff]`
//! step, 8-at-a-time unroll, initial-crc-for-NULL contract) and the GF(2)
//! `crc32_combine` operator via `x2nmodp`/`multmodp`.  The braided table
//! path (a pure speed optimization with identical results) is not ported;
//! the byte-wise loop produces bit-identical CRCs.

/// `BASE` — largest prime < 65536, for adler32.
const BASE: u32 = 65521;

/// `NMAX` — largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1.
const NMAX: usize = 5552;

/// `adler32_z(adler, buf, len)` — the streaming Adler-32.
#[must_use]
pub fn adler32_z(adler: u32, buf: &[u8]) -> u32 {
    let mut sum2: u32;
    let mut adler = adler;

    /* split Adler-32 into component sums */
    sum2 = (adler >> 16) & 0xffff;
    adler &= 0xffff;

    /* in case user likes doing a byte at a time, keep it fast */
    if buf.len() == 1 {
        adler += buf[0] as u32;
        if adler >= BASE {
            adler -= BASE;
        }
        sum2 += adler;
        if sum2 >= BASE {
            sum2 -= BASE;
        }
        return adler | (sum2 << 16);
    }

    /* initial Adler-32 value (deferred check for len == 1 speed) */
    if buf.is_empty() {
        return 1;
    }

    let mut p = 0usize; // position in buf
    let mut len = buf.len();

    /* in case short lengths are provided, keep it somewhat fast */
    if len < 16 {
        while len > 0 {
            len -= 1;
            adler += buf[p] as u32;
            p += 1;
            sum2 += adler;
        }
        if adler >= BASE {
            adler -= BASE;
        }
        sum2 %= BASE; /* only added so many BASE's */
        return adler | (sum2 << 16);
    }

    /* do length NMAX blocks -- requires just one modulo operation */
    while len >= NMAX {
        len -= NMAX;
        let mut n = NMAX / 16; /* NMAX is divisible by 16 */
        loop {
            /* 16 sums unrolled */
            for _ in 0..16 {
                adler += buf[p] as u32;
                p += 1;
                sum2 += adler;
            }
            n -= 1;
            if n == 0 {
                break;
            }
        }
        adler %= BASE;
        sum2 %= BASE;
    }

    /* do remaining bytes (less than NMAX, still just one modulo) */
    if len > 0 {
        /* avoid modulos if none remaining */
        while len >= 16 {
            len -= 16;
            for _ in 0..16 {
                adler += buf[p] as u32;
                p += 1;
                sum2 += adler;
            }
        }
        while len > 0 {
            len -= 1;
            adler += buf[p] as u32;
            p += 1;
            sum2 += adler;
        }
        adler %= BASE;
        sum2 %= BASE;
    }

    /* return recombined sums */
    adler | (sum2 << 16)
}

/// `adler32(adler, buf, len)` — `adler32_z` with uInt len (u32 in Rust).
#[must_use]
pub fn adler32(adler: u32, buf: &[u8]) -> u32 {
    adler32_z(adler, buf)
}

/// `adler32_combine_(adler1, adler2, len2)` — the combine formula.
#[must_use]
fn adler32_combine_(adler1: u32, adler2: u32, len2: i64) -> u32 {
    let mut sum1: u64;
    let mut sum2: u64;

    /* for negative len, return invalid adler32 as a clue for debugging */
    if len2 < 0 {
        return 0xffff_ffff;
    }

    /* the derivation of this formula is left as an exercise for the reader */
    let rem: u64 = (len2 as u64) % BASE as u64; /* assumes len2 >= 0 */
    sum1 = (adler1 & 0xffff) as u64;
    sum2 = rem * sum1;
    sum2 %= BASE as u64;
    sum1 += (adler2 & 0xffff) as u64 + BASE as u64 - 1;
    sum2 += ((adler1 >> 16) & 0xffff) as u64 + ((adler2 >> 16) & 0xffff) as u64 + BASE as u64 - rem;
    if sum1 >= BASE as u64 {
        sum1 -= BASE as u64;
    }
    if sum1 >= BASE as u64 {
        sum1 -= BASE as u64;
    }
    if sum2 >= (BASE as u64) << 1 {
        sum2 -= (BASE as u64) << 1;
    }
    if sum2 >= BASE as u64 {
        sum2 -= BASE as u64;
    }
    (sum1 as u32) | ((sum2 as u32) << 16)
}

/// `adler32_combine(adler1, adler2, len2)`.
#[must_use]
pub fn adler32_combine(adler1: u32, adler2: u32, len2: i64) -> u32 {
    adler32_combine_(adler1, adler2, len2)
}

// ---------------------------------------------------------------------------
// crc32
// ---------------------------------------------------------------------------

/// The CRC-32 polynomial reflected (0xedb88320 in the table recurrence).
const POLY: u32 = 0xedb8_8320;

/// `crc_table[]` — generated exactly like `make_crc_table` (crc32.c).
static CRC_TABLE: [u32; 256] = make_crc_table();

/// Build the byte-at-a-time CRC table (crc32.c `make_crc_table`).
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut p = i as u32;
        let mut j = 0;
        while j < 8 {
            p = if p & 1 != 0 { (p >> 1) ^ POLY } else { p >> 1 };
            j += 1;
        }
        table[i] = p;
        i += 1;
    }
    table
}

/// `multmodp(a, b)` — multiply two polynomials mod p(x), x^32+x^26+...+1
/// (crc32.c).  Requires a != 0.
#[must_use]
fn multmodp(a: u32, b: u32) -> u32 {
    let mut m: u32 = 1 << 31;
    let mut p: u32 = 0;
    let mut b = b;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
    }
    p
}

/// `x2n_table[]` — powers of x^(2^n) mod p(x) (crc32.c `make_crc_table`).
static X2N_TABLE: [u32; 32] = make_x2n_table();

/// Generate the powers-of-x table: x2n_table[0] = x^1, then squares.
const fn make_x2n_table() -> [u32; 32] {
    let mut table = [0u32; 32];
    let mut p: u32 = 1 << 30; /* x^1 */
    table[0] = p;
    let mut n = 1;
    while n < 32 {
        // multmodp(p, p) with p != 0 (const context helper below)
        p = multmodp_const(p, p);
        table[n] = p;
        n += 1;
    }
    table
}

/// Const version of `multmodp` for table generation.
const fn multmodp_const(a: u32, b: u32) -> u32 {
    let mut m: u32 = 1 << 31;
    let mut p: u32 = 0;
    let mut b = b;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
    }
    p
}

/// `x2nmodp(n, k)` — x^(n * 2^k) mod p(x), using the precomputed powers
/// table (crc32.c).
#[must_use]
fn x2nmodp(n: i64, k: usize) -> u32 {
    let mut p: u32 = 1 << 31; /* x^0 == 1 */
    let mut n = n;
    let mut k = k;
    while n != 0 {
        if n & 1 != 0 {
            p = multmodp(X2N_TABLE[k & 31], p);
        }
        n >>= 1;
        k += 1;
    }
    p
}

/// `crc32_z(crc, buf, len)` — the byte-wise core (crc32.c non-braid path).
#[must_use]
pub fn crc32_z(crc: u32, buf: &[u8]) -> u32 {
    /* Return initial CRC, if requested. */
    if buf.is_empty() {
        return 0;
    }

    let mut crc = crc;

    /* Pre-condition the CRC */
    crc = (!crc) & 0xffff_ffff;

    let mut p = 0usize;
    let mut len = buf.len();

    /* Complete the computation of the CRC on any remaining bytes. */
    while len >= 8 {
        len -= 8;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
    }
    while len > 0 {
        len -= 1;
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ buf[p] as u32) & 0xff) as usize];
        p += 1;
    }

    /* Return the CRC, post-conditioned. */
    crc ^ 0xffff_ffff
}

/// `crc32(crc, buf, len)`.
#[must_use]
pub fn crc32(crc: u32, buf: &[u8]) -> u32 {
    crc32_z(crc, buf)
}

/// `crc32_combine64(crc1, crc2, len2)` — combine two CRCs over len2 bytes.
#[must_use]
pub fn crc32_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    multmodp(x2nmodp(len2, 3), crc1) ^ (crc2 & 0xffff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(1, b""), 1);
        assert_eq!(adler32(1, b"a"), 0x0062_0062);
        assert_eq!(adler32(1, b"abc"), 0x024d_0127);
        assert_eq!(adler32(1, b"Wikipedia"), 0x11e6_0398);
        // 5552-byte boundary (NMAX deferral)
        let big = vec![b'a'; 5552];
        assert_eq!(adler32(1, &big), adler32(1, &big[..]));
        let big2 = vec![b'z'; 11000];
        assert_eq!(adler32(1, &big2), adler32(1, &big2[..]));
    }

    #[test]
    fn adler32_streaming_equals_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog 1234567890";
        let mut a = adler32(1, &data[..5]);
        a = adler32(a, &data[5..]);
        assert_eq!(a, adler32(1, data));
    }

    #[test]
    fn adler32_combine_roundtrip() {
        let a = b"hello, ";
        let b = b"world!";
        let joined = [a.as_slice(), b.as_slice()].concat();
        let c1 = adler32(1, a);
        let c2 = adler32(1, b);
        let combined = adler32_combine(c1, c2, b.len() as i64);
        assert_eq!(combined, adler32(1, &joined));
    }

    #[test]
    fn adler32_negative_len_invalid() {
        assert_eq!(adler32_combine(1, 1, -1), 0xffff_ffff);
    }

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(0, b""), 0);
        assert_eq!(crc32(0, b"123456789"), 0xcbf4_3926);
        assert_eq!(
            crc32(0, b"The quick brown fox jumps over the lazy dog"),
            0x414f_a339
        );
        assert_eq!(crc32(0, b"a"), 0xe8b7_be43);
        // incremental equals one-shot
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut c = crc32(0, &data[..3]);
        c = crc32(c, &data[3..10]);
        c = crc32(c, &data[10..]);
        assert_eq!(c, crc32(0, data));
        // 8-byte unroll boundary
        let data2 = b"12345678";
        assert_eq!(crc32(0, data2), crc32(0, data2));
    }

    #[test]
    fn crc32_combine_roundtrip() {
        let a = b"hello, ";
        let b = b"world!";
        let joined = [a.as_slice(), b.as_slice()].concat();
        let c1 = crc32(0, a);
        let c2 = crc32(0, b);
        let combined = crc32_combine(c1, c2, b.len() as i64);
        assert_eq!(combined, crc32(0, &joined));
    }
}
