//! inftrees.c — build decoding tables for canonical Huffman codes
//! (conservation port).
//!
//! `inflate_table` reproduces the exact table layout (root + sub-tables with
//! `code { op, bits, val }` entries), the code-length validation (over- and
//! under-subscription), the symbol sorting via the work array, the
//! backwards code increment, and the ENOUGH space checks.  The resulting
//! tables drive both the fixed and dynamic decode paths in `inflate`.

/// A decoding table entry (`code` in inftrees.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Code {
    pub op: u8,
    pub bits: u8,
    pub val: u16,
}

pub const MAXBITS: usize = 15;

pub const ENOUGH_LENS: usize = 852;
pub const ENOUGH_DISTS: usize = 592;
pub const ENOUGH: usize = ENOUGH_LENS + ENOUGH_DISTS;

/// codetype: CODES, LENS, DISTS.
#[derive(Clone, Copy, PartialEq)]
pub enum CodeType {
    Codes,
    Lens,
    Dists,
}

/// The length-code base/extra tables (inftrees.c).
const LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];
const LEXT: [u16; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 16, 203, 77,
];
const DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];
const DEXT: [u16; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26,
    27, 27, 28, 28, 29, 29, 64, 64,
];

/// `inflate_table` — build a set of decoding tables.
///
/// `lens` holds `codes` code lengths; `table` is advanced past the used
/// entries (stored into `codes` by the caller, which keeps a cursor); `bits`
/// in/out is the root table size; `work` is scratch (at least `codes` u16s).
/// Returns 0 on success, -1 on invalid code, 1 if ENOUGH is not enough.
#[allow(clippy::too_many_lines)]
pub fn inflate_table(
    typ: CodeType,
    lens: &[u16],
    codes: usize,
    table: &mut Vec<Code>,
    next: &mut usize,
    bits: &mut u32,
    work: &mut [u16],
) -> i32 {
    let mut count = [0u16; MAXBITS + 1];
    let mut offs = [0u16; MAXBITS + 1];
    let mut len;
    let mut sym;
    let mut min;
    let mut max;
    let mut root;
    let mut curr;
    let mut drop;
    let mut left;
    let mut used;
    let mut huff;
    let mut incr;
    let mut fill;
    let mut low;
    let mut mask;
    let mut here = Code::default();
    let mut next_idx; /* index into table Vec */
    let mut base: &[u16];
    let mut extra: &[u16];
    let mut match_;

    /* accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) */
    for c in count.iter_mut() {
        *c = 0;
    }
    for sym2 in 0..codes {
        count[lens[sym2] as usize] += 1;
    }

    /* bound code lengths, force root to be within code lengths */
    root = *bits;
    max = MAXBITS as u32;
    while max >= 1 && count[max as usize] == 0 {
        max -= 1;
    }
    if root > max {
        root = max;
    }
    if max == 0 {
        /* no symbols to code at all */
        here.op = 64; /* invalid code marker */
        here.bits = 1;
        here.val = 0;
        (*table)[*next] = here;
        *next += 1;
        (*table)[*next] = here;
        *next += 1;
        *bits = 1;
        return 0; /* no symbols, but wait for decoding to report error */
    }
    min = 1;
    while min < max && count[min as usize] == 0 {
        min += 1;
    }
    if root < min {
        root = min;
    }

    /* check for an over-subscribed or incomplete set of lengths */
    left = 1;
    for len2 in 1..=MAXBITS {
        left <<= 1;
        left -= count[len2] as i32;
        if left < 0 {
            return -1; /* over-subscribed */
        }
    }
    if left > 0 && (typ == CodeType::Codes || max != 1) {
        return -1; /* incomplete set */
    }

    /* generate offsets into symbol table for each length for sorting */
    offs[1] = 0;
    for len2 in 1..MAXBITS {
        offs[len2 + 1] = offs[len2] + count[len2];
    }

    /* sort symbols by length, by symbol order within each length */
    for sym2 in 0..codes {
        if lens[sym2] != 0 {
            work[offs[lens[sym2] as usize] as usize] = sym2 as u16;
            offs[lens[sym2] as usize] += 1;
        }
    }

    /* set up for code type */
    match typ {
        CodeType::Codes => {
            base = &[];
            extra = &[];
            match_ = 20;
        }
        CodeType::Lens => {
            base = &LBASE;
            extra = &LEXT;
            match_ = 257;
        }
        CodeType::Dists => {
            base = &DBASE;
            extra = &DEXT;
            match_ = 0;
        }
    }

    /* initialize state for loop */
    huff = 0; /* starting code */
    sym = 0; /* starting code symbol */
    len = min; /* starting code length */
    let base_idx = *next; /* the caller's table base (root table start) */
    next_idx = *next; /* current table entry index */
    curr = root; /* current table index bits */
    drop = 0; /* current bits to drop from code for index */
    low = u32::MAX; /* trigger new sub-table when len > root */
    used = 1u32 << root; /* use root table entries */
    mask = used - 1; /* mask for comparing low */

    /* check available table space */
    if (typ == CodeType::Lens && used > ENOUGH_LENS as u32)
        || (typ == CodeType::Dists && used > ENOUGH_DISTS as u32)
    {
        return 1;
    }

    /* process all codes and make table entries */
    loop {
        /* create table entry */
        here.bits = (len - drop) as u8;
        if (work[sym as usize] as u32) + 1 < match_ {
            here.op = 0;
            here.val = work[sym as usize];
        } else if work[sym as usize] as u32 >= match_ {
            here.op = extra[(work[sym as usize] - match_ as u16) as usize] as u8;
            here.val = base[(work[sym as usize] - match_ as u16) as usize];
        } else {
            here.op = (32 + 64) as u8; /* end of block */
            here.val = 0;
        }

        /* replicate for those indices with low len bits equal to huff */
        incr = 1u32 << (len - drop);
        fill = 1u32 << curr;
        let min_save = fill; /* save offset to next table */
        loop {
            fill -= incr;
            let idx = ((huff >> drop) + fill) as usize;
            table[next_idx + idx] = here;
            if fill == 0 {
                break;
            }
        }

        /* backwards increment the len-bit code huff */
        incr = 1u32 << (len - 1);
        while huff & incr != 0 {
            incr >>= 1;
        }
        if incr != 0 {
            huff &= incr - 1;
            huff += incr;
        } else {
            huff = 0;
        }

        /* go to next symbol, update count, len */
        sym += 1;
        count[len as usize] -= 1;
        if count[len as usize] == 0 {
            if len == max {
                break;
            }
            len = lens[work[sym as usize] as usize] as u32;
        }

        /* create new sub-table if needed */
        if len > root && (huff & mask) != low {
            /* if first time, transition to sub-tables */
            if drop == 0 {
                drop = root;
            }

            /* increment past last table */
            next_idx += min_save as usize; /* here min is 1 << curr */

            /* determine length of next table */
            curr = len - drop;
            left = 1i32 << curr;
            while (curr + drop) < max as u32 {
                left -= count[(curr + drop) as usize] as i32;
                if left <= 0 {
                    break;
                }
                curr += 1;
                left <<= 1;
            }

            /* check for enough space */
            used += 1u32 << curr;
            if (typ == CodeType::Lens && used > ENOUGH_LENS as u32)
                || (typ == CodeType::Dists && used > ENOUGH_DISTS as u32)
            {
                return 1;
            }

            /* point entry in root table to sub-table */
            low = huff & mask;
            table[base_idx + low as usize].op = curr as u8;
            table[base_idx + low as usize].bits = root as u8;
            table[base_idx + low as usize].val = (next_idx - base_idx) as u16;
        }
    }

    /* fill in remaining table entry if code is incomplete (guaranteed to have
    at most one remaining entry, since if the code is incomplete, the
    maximum code length that was allowed to get this far is one bit) */
    if huff != 0 {
        here.op = 64; /* invalid code marker */
        here.bits = (len - drop) as u8;
        here.val = 0;
        table[next_idx + huff as usize] = here;
    }

    /* set return parameters */
    *next += used as usize;
    *bits = root;
    0
}
