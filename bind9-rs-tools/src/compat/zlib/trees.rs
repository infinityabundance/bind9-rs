//! trees.c — Huffman tree construction and bit-level block emission
//! (conservation port).
//!
//! Byte-exactness of the deflate encoder depends on this module: the static
//! literal/distance trees (with the exact bit-reversed codes), the dynamic
//! tree construction (heap, gen_bitlen with the overflow adjustment,
//! gen_codes), the bit-length repeat encoding (scan_tree/send_tree with the
//! max_count/min_count state machine), the block-type selection accounting
//! (opt_len/static_len), and the bi_buf/bi_valid bit writer.

use super::deflate::DeflateState;

// ---------------------------------------------------------------------------
// Constants (trees.c)
// ---------------------------------------------------------------------------

pub const LENGTH_CODES: usize = 29;
pub const LITERALS: usize = 256;
pub const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
pub const D_CODES: usize = 30;
pub const BL_CODES: usize = 19;
pub const HEAP_SIZE: usize = 2 * L_CODES + 1;
pub const MAX_BITS: usize = 15;
pub const MAX_BL_BITS: usize = 7;
pub const END_BLOCK: usize = 256;
pub const REP_3_6: usize = 16;
pub const REPZ_3_10: usize = 17;
pub const REPZ_11_138: usize = 18;
pub const DIST_CODE_LEN: usize = 512;

pub const STORED_BLOCK: u32 = 0;
pub const STATIC_TREES: u32 = 1;
pub const DYN_TREES: u32 = 2;

/// extra bits for each length code (trees.c).
pub const EXTRA_LBITS: [u32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// extra bits for each distance code.
pub const EXTRA_DBITS: [u32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// extra bits for each bit length code.
pub const EXTRA_BLBITS: [u32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

/// the order bit lengths are sent in (decreasing probability).
pub const BL_ORDER: [usize; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ---------------------------------------------------------------------------
// Static trees (generated once, exactly like tr_static_init)
// ---------------------------------------------------------------------------

pub struct CtData {
    pub freq: u32, /* frequency count or bit string */
    pub code: u32,
    pub dad: u32,
    pub len: u32,
}

impl CtData {
    pub const fn new() -> Self {
        CtData {
            freq: 0,
            code: 0,
            dad: 0,
            len: 0,
        }
    }
}

impl Clone for CtData {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for CtData {}

/// The static literal tree and distance tree (trees.h / tr_static_init).
pub struct StaticTrees {
    pub ltree: [CtData; L_CODES + 2],
    pub dtree: [CtData; D_CODES],
}

/// `_length_code[MAX_MATCH-MIN_MATCH+1]` — normalized length to length code.
pub struct LengthCodeTable {
    pub length_code: [u8; 256],
    pub dist_code: [u8; DIST_CODE_LEN],
    pub base_length: [u32; LENGTH_CODES],
    pub base_dist: [u32; D_CODES],
}

/// Reverse the first len bits of a code (trees.c bi_reverse).
fn bi_reverse(code: u32, len: u32) -> u32 {
    let mut res: u32 = 0;
    let mut code = code;
    let mut len = len;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

/// Build the static trees and lookup tables (tr_static_init).
fn build_static_tables() -> (StaticTrees, LengthCodeTable) {
    let mut ltree = [CtData::new(); L_CODES + 2];
    let mut dtree = [CtData::new(); D_CODES];
    let mut length_code = [0u8; 256];
    let mut dist_code = [0u8; DIST_CODE_LEN];
    let mut base_length = [0u32; LENGTH_CODES];
    let mut base_dist = [0u32; D_CODES];

    /* Initialize the mapping length (0..255) -> length code (0..28) */
    let mut length = 0usize;
    let mut code = 0usize;
    while code < LENGTH_CODES - 1 {
        base_length[code] = length as u32;
        let mut n = 0usize;
        while n < (1 << EXTRA_LBITS[code]) {
            length_code[length] = code as u8;
            length += 1;
            n += 1;
        }
        code += 1;
    }
    debug_assert!(length == 256, "tr_static_init: length != 256");
    /* length 255 (match length 258): use code 284+5 bits (best encoding) */
    length_code[length - 1] = code as u8;

    /* Initialize the mapping dist (0..32K) -> dist code (0..29) */
    let mut dist = 0usize;
    code = 0;
    while code < 16 {
        base_dist[code] = dist as u32;
        let mut n = 0usize;
        while n < (1 << EXTRA_DBITS[code]) {
            dist_code[dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    debug_assert!(dist == 256, "tr_static_init: dist != 256");
    dist >>= 7; /* from now on, all distances are divided by 128 */
    while code < D_CODES {
        base_dist[code] = (dist << 7) as u32;
        let mut n = 0usize;
        while n < (1 << (EXTRA_DBITS[code] - 7)) {
            dist_code[256 + dist] = code as u8;
            dist += 1;
            n += 1;
        }
        code += 1;
    }
    debug_assert!(dist == 256, "tr_static_init: 256 + dist != 512");

    /* Construct the codes of the static literal tree */
    let mut bl_count = [0u32; MAX_BITS + 1];
    let mut n = 0usize;
    while n <= 143 {
        ltree[n].len = 8;
        bl_count[8] += 1;
        n += 1;
    }
    while n <= 255 {
        ltree[n].len = 9;
        bl_count[9] += 1;
        n += 1;
    }
    while n <= 279 {
        ltree[n].len = 7;
        bl_count[7] += 1;
        n += 1;
    }
    while n <= 287 {
        ltree[n].len = 8;
        bl_count[8] += 1;
        n += 1;
    }
    /* Codes 286 and 287 do not exist, but must be included for a canonical
     * tree (longest code all ones) */
    gen_codes(&mut ltree, L_CODES + 1, &bl_count);

    /* The static distance tree is trivial: */
    for n in 0..D_CODES {
        dtree[n].len = 5;
        dtree[n].code = bi_reverse(n as u32, 5);
    }

    (
        StaticTrees { ltree, dtree },
        LengthCodeTable {
            length_code,
            dist_code,
            base_length,
            base_dist,
        },
    )
}

/// Once-initialized static tables.
pub struct StaticTables {
    pub trees: StaticTrees,
    pub codes: LengthCodeTable,
}

static STATIC_TABLES: std::sync::OnceLock<StaticTables> = std::sync::OnceLock::new();

/// Get the once-built static tables.
pub fn static_tables() -> &'static StaticTables {
    STATIC_TABLES.get_or_init(|| {
        let (trees, codes) = build_static_tables();
        StaticTables { trees, codes }
    })
}

/// `d_code(dist)` — distance to distance code (deflate.h).
pub fn d_code(dist: u32) -> usize {
    if dist < 256 {
        static_tables().codes.dist_code[dist as usize] as usize
    } else {
        static_tables().codes.dist_code[256 + ((dist >> 7) as usize)] as usize
    }
}

/// `_tr_init` — (trees.c): init block + bit buffer.
pub fn tr_init(s: &mut DeflateState) {
    let _ = static_tables(); // ensure tables exist
    s.bi_buf = 0;
    s.bi_valid = 0;
    init_block(s);
}

/// `init_block` — zero frequencies, seed END_BLOCK.
pub fn init_block(s: &mut DeflateState) {
    for n in 0..L_CODES {
        s.dyn_ltree[n].freq = 0;
    }
    for n in 0..D_CODES {
        s.dyn_dtree[n].freq = 0;
    }
    for n in 0..BL_CODES {
        s.bl_tree[n].freq = 0;
    }
    s.dyn_ltree[END_BLOCK].freq = 1;
    s.opt_len = 0;
    s.static_len = 0;
    s.sym_next = 0;
    s.matches = 0;
}

/// `put_byte` (deflate.h) — append a byte to the pending buffer.
pub fn put_byte(s: &mut DeflateState, c: u8) {
    let idx = s.pending as usize;
    s.pending_buf[idx] = c;
    s.pending += 1;
}

/// `put_short` (trees.c) — short LSB first into pending.
pub fn put_short(s: &mut DeflateState, w: u32) {
    put_byte(s, (w & 0xff) as u8);
    put_byte(s, ((w >> 8) & 0xff) as u8);
}

/// `put_short_u16` — the same for a u16 value.
pub fn put_short_u16(s: &mut DeflateState, w: u16) {
    put_short(s, w as u32);
}

/// `bi_flush` — flush the bit buffer, keeping at most 7 bits.
fn bi_flush(s: &mut DeflateState) {
    if s.bi_valid == 16 {
        put_short_u16(s, s.bi_buf);
        s.bi_buf = 0;
        s.bi_valid = 0;
    } else if s.bi_valid >= 8 {
        put_byte(s, (s.bi_buf & 0xff) as u8);
        s.bi_buf >>= 8;
        s.bi_valid -= 8;
    }
}

/// `bi_windup` — flush the bit buffer and align on a byte boundary.
fn bi_windup(s: &mut DeflateState) {
    if s.bi_valid > 8 {
        put_short_u16(s, s.bi_buf);
    } else if s.bi_valid > 0 {
        put_byte(s, (s.bi_buf & 0xff) as u8);
    }
    s.bi_buf = 0;
    s.bi_valid = 0;
}

/// `send_bits(s, value, length)` — the macro form (non-debug).  All bi_buf
/// arithmetic truncates to 16 bits exactly like the C `ush` fields; note the
/// C casts `(ush)val` *before* the `>> (Buf_size - bi_valid)` shift, so the
/// value is truncated first.
pub fn send_bits(s: &mut DeflateState, value: u32, length: u32) {
    let len = length as i32;
    if s.bi_valid as i32 > 16 - len {
        let val = value & 0xffff;
        s.bi_buf |= ((val << s.bi_valid) & 0xffff) as u16;
        put_short_u16(s, s.bi_buf);
        s.bi_buf = ((val >> (16 - s.bi_valid)) & 0xffff) as u16;
        s.bi_valid = (s.bi_valid as i32 + len - 16) as u32;
    } else {
        s.bi_buf |= (((value & 0xffff) << s.bi_valid) & 0xffff) as u16;
        s.bi_valid += len as u32;
    }
}

/// `send_code(s, c, tree)` — send a code of the given tree.
pub fn send_code(s: &mut DeflateState, c: usize, tree: &[CtData]) {
    send_bits(s, tree[c].code, tree[c].len);
}

/// `gen_codes` — generate codes from bit counts (trees.c).
fn gen_codes(tree: &mut [CtData], max_code: usize, bl_count: &[u32]) {
    let mut next_code = [0u32; MAX_BITS + 1];
    let mut code: u32 = 0;
    let mut bits: usize;

    /* The distribution counts are first used to generate the code values
     * without bit reversal. */
    bits = 1;
    while bits <= MAX_BITS {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
        bits += 1;
    }
    /* Check that the bit counts in bl_count are consistent. The last code
     * must be all ones.  The C guards this with Assert() which is compiled
     * out without DEBUG; the forced-two-codes hack in build_tree violates
     * the equality for tiny inputs, so no runtime check here (mirroring the
     * release build). */
    let _ = code + bl_count[MAX_BITS] - 1 == (1 << MAX_BITS) - 1;

    let mut n = 0usize;
    while n <= max_code {
        let len = tree[n].len;
        if len != 0 {
            tree[n].code = bi_reverse(next_code[len as usize], len);
            next_code[len as usize] += 1;
        }
        n += 1;
    }
}

/// `pqdownheap` — restore the heap property (trees.c).
fn pqdownheap(s: &mut DeflateState, tree: &[CtData], k0: usize) {
    let mut k = k0;
    let v = s.heap[k];
    let mut j = k << 1; /* left son of k */
    while j <= s.heap_len {
        /* Set j to the smallest of the two sons: */
        if j < s.heap_len && smaller(tree, s.heap[j + 1], s.heap[j], &s.depth) {
            j += 1;
        }
        /* Exit if v is smaller than both sons */
        if smaller(tree, v, s.heap[j], &s.depth) {
            break;
        }
        /* Exchange v with the smallest son */
        s.heap[k] = s.heap[j];
        k = j;
        /* And continue down the tree, setting j to the left son of k */
        j <<= 1;
    }
    s.heap[k] = v;
}

/// `smaller` — compare two nodes, depth as tie breaker.
fn smaller(tree: &[CtData], n: usize, m: usize, depth: &[u8]) -> bool {
    tree[n].freq < tree[m].freq || (tree[n].freq == tree[m].freq && depth[n] <= depth[m])
}

/// `pqremove` — remove the smallest element from the heap.
fn pqremove(s: &mut DeflateState, tree: &[CtData]) -> usize {
    let top = s.heap[1];
    s.heap[1] = s.heap[s.heap_len];
    s.heap_len -= 1;
    pqdownheap(s, tree, 1);
    top
}

/// `gen_bitlen` — compute optimal bit lengths and update opt_len/static_len.
#[allow(clippy::too_many_lines)]
fn gen_bitlen(
    s: &mut DeflateState,
    tree: &mut [CtData],
    max_code: usize,
    stree: Option<&[CtData]>,
    extra: &[u32],
    base: usize,
    max_length: u32,
) {
    let mut overflow: i64 = 0;

    for bits in 0..=MAX_BITS {
        s.bl_count[bits] = 0;
    }

    /* In a first pass, compute the optimal bit lengths (which may overflow in
     * the case of the bit length tree). */
    tree[s.heap[s.heap_max]].len = 0; /* root of the heap */

    let mut h = s.heap_max + 1;
    while h < HEAP_SIZE {
        let n = s.heap[h];
        let mut bits = tree[tree[n as usize].dad as usize].len + 1;
        if bits > max_length {
            bits = max_length;
            overflow += 1;
        }
        tree[n as usize].len = bits;
        /* We overwrite tree[n].Dad which is no longer needed */

        if (n as usize) > max_code {
            h += 1;
            continue; /* not a leaf node */
        }

        s.bl_count[bits as usize] += 1;
        let mut xbits = 0;
        if (n as usize) >= base {
            xbits = extra[(n as usize) - base];
        }
        let f = tree[n as usize].freq;
        /* opt_len/static_len accumulate with unsigned wrap like the C's ulg
         * fields (the "at least two codes" hack in build_tree subtracts from
         * 0; the sums wrap back to the true cost). */
        s.opt_len = s.opt_len.wrapping_add((f as u64) * ((bits + xbits) as u64));
        if let Some(st) = stree {
            s.static_len = s
                .static_len
                .wrapping_add((f as u64) * ((st[n as usize].len + xbits) as u64));
        }
        h += 1;
    }
    if overflow == 0 {
        return;
    }

    /* bit length overflow: adjust bl_count */
    loop {
        let mut bits = max_length - 1;
        while s.bl_count[bits as usize] == 0 {
            bits -= 1;
        }
        s.bl_count[bits as usize] -= 1; /* move one leaf down the tree */
        s.bl_count[(bits + 1) as usize] += 2; /* move one overflow item as its brother */
        s.bl_count[max_length as usize] -= 1;
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }

    /* Now recompute all bit lengths, scanning in increasing frequency. */
    let mut h = HEAP_SIZE;
    let mut bits = max_length;
    while bits != 0 {
        let mut n = s.bl_count[bits as usize];
        while n != 0 {
            h -= 1;
            let m = s.heap[h];
            if (m as usize) > max_code {
                continue; /* the C skips n-- here too */
            }
            if tree[m as usize].len != bits {
                s.opt_len = s.opt_len.wrapping_add(
                    ((bits as u64) - (tree[m as usize].len as u64))
                        * (tree[m as usize].freq as u64),
                );
                tree[m as usize].len = bits;
            }
            n -= 1;
        }
        bits -= 1;
    }
}

/// `build_tree` — construct one Huffman tree (trees.c).
fn build_tree(
    s: &mut DeflateState,
    tree: &mut [CtData],
    stree: Option<&[CtData]>,
    elems: usize,
    extra: &[u32],
    base: usize,
    max_length: u32,
) -> usize {
    let mut max_code: i64 = -1; /* largest code with non zero frequency */
    let mut node: usize; /* new node being created */

    /* Construct the initial heap, with least frequent element in heap[1]. */
    s.heap_len = 0;
    s.heap_max = HEAP_SIZE;

    for n in 0..elems {
        if tree[n].freq != 0 {
            s.heap_len += 1;
            s.heap[s.heap_len] = n;
            max_code = n as i64;
            s.depth[n] = 0;
        } else {
            tree[n].len = 0;
        }
    }

    /* The pkzip format requires that at least one distance code exists, and
     * that at least one bit should be sent even if there is only one possible
     * code. So to avoid special checks later on we force at least two codes
     * of non zero frequency. */
    while s.heap_len < 2 {
        s.heap_len += 1;
        max_code = if max_code < 2 { max_code + 1 } else { 0 };
        node = max_code as usize;
        s.heap[s.heap_len] = node;
        tree[node].freq = 1;
        s.depth[node] = 0;
        s.opt_len = s.opt_len.wrapping_sub(1);
        if let Some(st) = stree {
            s.static_len = s.static_len.wrapping_sub(st[node].len as u64);
        }
        /* node is 0 or 1 so it does not have extra bits */
    }
    let max_code = max_code as usize;

    /* The elements heap[heap_len/2 + 1 .. heap_len] are leaves of the tree,
     * establish sub-heaps of increasing lengths: */
    let mut n = s.heap_len / 2;
    while n >= 1 {
        pqdownheap(s, tree, n);
        if n == 1 {
            break;
        }
        n -= 1;
    }

    /* Construct the Huffman tree by repeatedly combining the least two
     * frequent nodes. */
    node = elems; /* next internal node of the tree */
    loop {
        let n2 = pqremove(s, tree); /* n = node of least frequency */
        let m = s.heap[1]; /* m = node of next least frequency */

        s.heap_max -= 1;
        s.heap[s.heap_max] = n2; /* keep the nodes sorted by frequency */
        s.heap_max -= 1;
        s.heap[s.heap_max] = m;

        /* Create a new node father of n and m */
        tree[node].freq = tree[n2].freq + tree[m].freq;
        s.depth[node] = if s.depth[n2] >= s.depth[m] {
            s.depth[n2] + 1
        } else {
            s.depth[m] + 1
        };
        tree[n2].dad = node as u32;
        tree[m].dad = node as u32;

        /* and insert the new node in the heap */
        s.heap[1] = node;
        node += 1;
        pqdownheap(s, tree, 1);

        if s.heap_len < 2 {
            break;
        }
    }

    s.heap_max -= 1;
    s.heap[s.heap_max] = s.heap[1];

    /* At this point, the fields freq and dad are set. We can now generate the
     * bit lengths. */
    gen_bitlen(s, tree, max_code, stree, extra, base, max_length);

    /* The field len is now set, we can generate the bit codes */
    gen_codes(tree, max_code, &s.bl_count);

    max_code
}

/// `scan_tree` — determine bit length code frequencies (trees.c).
fn scan_tree(s: &mut DeflateState, tree: &mut [CtData], max_code: usize) {
    let mut prevlen = -1i64; /* last emitted length */
    let mut curlen: i64; /* length of current code */
    let mut nextlen = tree[0].len as i64; /* length of next code */
    let mut count = 0i64; /* repeat count of the current code */
    let mut max_count: i64 = 7; /* max repeat count */
    let mut min_count: i64 = 4; /* min repeat count */

    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }
    tree[max_code + 1].len = 0xffff; /* guard */

    let mut n = 0usize;
    while n <= max_code {
        curlen = nextlen;
        nextlen = tree[n + 1].len as i64;
        count += 1;
        if count < max_count && curlen == nextlen {
            n += 1;
            continue;
        } else if count < min_count {
            s.bl_tree[curlen as usize].freq += count as u32;
        } else if curlen != 0 {
            if curlen != prevlen {
                s.bl_tree[curlen as usize].freq += 1;
            }
            s.bl_tree[REP_3_6].freq += 1;
        } else if count <= 10 {
            s.bl_tree[REPZ_3_10].freq += 1;
        } else {
            s.bl_tree[REPZ_11_138].freq += 1;
        }
        count = 0;
        prevlen = curlen;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
        n += 1;
    }
}

/// `send_tree` — send a tree in compressed form using bl_tree codes.
fn send_tree(s: &mut DeflateState, tree: &[CtData], max_code: usize) {
    // NOTE: this function mutates s (bit buffer) while reading s.bl_tree; the
    // caller passes the bl_tree slice explicitly via a split borrow.
    let bl_tree = std::mem::take(&mut s.bl_tree);
    send_tree_inner(s, tree, max_code, &bl_tree);
    s.bl_tree = bl_tree;
}

fn send_tree_inner(s: &mut DeflateState, tree: &[CtData], max_code: usize, bl_tree: &[CtData]) {
    let mut prevlen = -1i64; /* last emitted length */
    let mut curlen: i64; /* length of current code */
    let mut nextlen = tree[0].len as i64; /* length of next code */
    let mut count = 0i64; /* repeat count of the current code */
    let mut max_count: i64 = 7; /* max repeat count */
    let mut min_count: i64 = 4; /* min repeat count */

    /* tree[max_code + 1].Len = -1; */
    /* guard already set */
    if nextlen == 0 {
        max_count = 138;
        min_count = 3;
    }

    let mut n = 0usize;
    while n <= max_code {
        curlen = nextlen;
        nextlen = tree[n + 1].len as i64;
        count += 1;
        if count < max_count && curlen == nextlen {
            n += 1;
            continue;
        } else if count < min_count {
            while count != 0 {
                send_code(s, curlen as usize, bl_tree);
                count -= 1;
            }
        } else if curlen != 0 {
            if curlen != prevlen {
                send_code(s, curlen as usize, bl_tree);
                count -= 1;
            }
            debug_assert!((3..=6).contains(&count), " 3_6?");
            send_code(s, REP_3_6, bl_tree);
            send_bits(s, (count - 3) as u32, 2);
        } else if count <= 10 {
            send_code(s, REPZ_3_10, bl_tree);
            send_bits(s, (count - 3) as u32, 3);
        } else {
            send_code(s, REPZ_11_138, bl_tree);
            send_bits(s, (count - 11) as u32, 7);
        }
        count = 0;
        prevlen = curlen;
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        } else if curlen == nextlen {
            max_count = 6;
            min_count = 3;
        } else {
            max_count = 7;
            min_count = 4;
        }
        n += 1;
    }
}

/// `build_bl_tree` — build the bit length tree; return max_blindex.
fn build_bl_tree(s: &mut DeflateState) -> usize {
    let l_max = s.l_max_code;
    let d_max = s.d_max_code;

    /* Determine the bit length frequencies for literal and distance trees */
    let mut ltree = std::mem::take(&mut s.dyn_ltree);
    scan_tree(s, &mut ltree, l_max);
    s.dyn_ltree = ltree;
    let mut dtree = std::mem::take(&mut s.dyn_dtree);
    scan_tree(s, &mut dtree, d_max);
    s.dyn_dtree = dtree;

    /* Build the bit length tree: */
    let mut blt = std::mem::take(&mut s.bl_tree);
    build_tree(
        s,
        &mut blt,
        None,
        BL_CODES,
        &EXTRA_BLBITS,
        0,
        MAX_BL_BITS as u32,
    );
    s.bl_tree = blt;
    /* opt_len now includes the length of the tree representations, except the
     * lengths of the bit lengths codes and the 5 + 5 + 4 bits for the counts.
     */

    /* Determine the number of bit length codes to send. The pkzip format
     * requires that at least 4 bit length codes be sent. */
    let mut max_blindex = BL_CODES - 1;
    while max_blindex >= 3 {
        if s.bl_tree[BL_ORDER[max_blindex]].len != 0 {
            break;
        }
        max_blindex -= 1;
    }
    /* Update opt_len to include the bit length tree and counts */
    s.opt_len += 3 * ((max_blindex + 1) as u64) + 5 + 5 + 4;

    max_blindex
}

/// `send_all_trees` — send the dynamic block header (trees.c).
fn send_all_trees(s: &mut DeflateState, lcodes: usize, dcodes: usize, blcodes: usize) {
    debug_assert!(
        lcodes >= 257 && dcodes >= 1 && blcodes >= 4,
        "not enough codes"
    );
    debug_assert!(
        lcodes <= L_CODES && dcodes <= D_CODES && blcodes <= BL_CODES,
        "too many codes"
    );

    send_bits(s, (lcodes - 257) as u32, 5); /* not +255 as stated in appnote.txt */
    send_bits(s, (dcodes - 1) as u32, 5);
    send_bits(s, (blcodes - 4) as u32, 4); /* not -3 as stated in appnote.txt */
    for rank in 0..blcodes {
        send_bits(s, s.bl_tree[BL_ORDER[rank]].len, 3);
    }

    let mut ltree = std::mem::take(&mut s.dyn_ltree);
    send_tree(s, &ltree, lcodes - 1); /* literal tree */
    s.dyn_ltree = ltree;
    let mut dtree = std::mem::take(&mut s.dyn_dtree);
    send_tree(s, &dtree, dcodes - 1); /* distance tree */
    s.dyn_dtree = dtree;
}

/// `compress_block` — send block data compressed with given trees (trees.c).
fn compress_block(s: &mut DeflateState, ltree: &[CtData], dtree: &[CtData]) {
    let mut sx = 0usize; /* running index in symbol buffer */

    if s.sym_next != 0 {
        loop {
            let dist = s.sym_buf[sx] as u32 | ((s.sym_buf[sx + 1] as u32) << 8);
            let lc = s.sym_buf[sx + 2] as usize;
            sx += 3;
            if dist == 0 {
                send_code(s, lc, ltree); /* send a literal byte */
            } else {
                /* Here, lc is the match length - MIN_MATCH */
                let tabs = static_tables();
                let mut code = tabs.codes.length_code[lc] as usize;
                send_code(s, code + LITERALS + 1, ltree); /* send length code */
                let mut extra = EXTRA_LBITS[code];
                if extra != 0 {
                    let mut lc2 = lc as i64 - tabs.codes.base_length[code] as i64;
                    send_bits(s, lc2 as u32, extra); /* send the extra length bits */
                }
                let mut dist2 = dist; /* dist is now the match distance - 1 */
                dist2 -= 1;
                code = d_code(dist2);
                debug_assert!(code < D_CODES, "bad d_code");

                send_code(s, code, dtree); /* send the distance code */
                extra = EXTRA_DBITS[code];
                if extra != 0 {
                    let d = dist2 - tabs.codes.base_dist[code];
                    send_bits(s, d, extra); /* send the extra distance bits */
                }
            } /* literal or match pair ? */

            if (sx as u32) >= s.sym_next {
                break;
            }
        }
    }

    send_code(s, END_BLOCK, ltree);
}

/// `detect_data_type` — TEXT/BINARY detection (trees.c).
fn detect_data_type(s: &DeflateState) -> i32 {
    /* block_mask is the bit mask of block-listed bytes
     * 0xf3ffc07f = binary 11110011111111111100000001111111 */
    let mut block_mask: u64 = 0xf3ff_c07f;

    /* Check for non-textual ("block-listed") bytes. */
    let mut n = 0usize;
    while n <= 31 {
        if block_mask & 1 != 0 && s.dyn_ltree[n].freq != 0 {
            return crate::compat::zlib::Z_BINARY;
        }
        block_mask >>= 1;
        n += 1;
    }

    /* Check for textual ("allow-listed") bytes. */
    if s.dyn_ltree[9].freq != 0 || s.dyn_ltree[10].freq != 0 || s.dyn_ltree[13].freq != 0 {
        return crate::compat::zlib::Z_TEXT;
    }
    for n in 32..LITERALS {
        if s.dyn_ltree[n].freq != 0 {
            return crate::compat::zlib::Z_TEXT;
        }
    }

    /* There are no "block-listed" or "allow-listed" bytes:
     * this stream either is empty or has tolerated ("gray-listed") bytes only. */
    crate::compat::zlib::Z_BINARY
}

/// `_tr_flush_block` — determine the best encoding and write the block
/// (trees.c).  `buf` and `stored_len` describe the raw window bytes when a
/// stored block is an option.
#[allow(clippy::too_many_lines)]
pub fn tr_flush_block(s: &mut DeflateState, stored: &[u8], stored_len: u32, last: bool) {
    let mut opt_lenb;
    let mut static_lenb;
    let mut max_blindex = 0usize; /* index of last bit length code of non zero freq */

    /* Build the Huffman trees unless a stored block is forced */
    if s.level > 0 {
        /* Check if the file is binary or text */
        if s.strm_data_type == crate::compat::zlib::Z_UNKNOWN {
            s.strm_data_type = detect_data_type(s);
        }

        /* Construct the literal and distance trees */
        let mut ltree = std::mem::take(&mut s.dyn_ltree);
        s.l_max_code = build_tree(
            s,
            &mut ltree,
            Some(&static_tables().trees.ltree),
            L_CODES,
            &EXTRA_LBITS,
            LITERALS + 1,
            MAX_BITS as u32,
        );
        s.dyn_ltree = ltree;

        let mut dtree = std::mem::take(&mut s.dyn_dtree);
        s.d_max_code = build_tree(
            s,
            &mut dtree,
            Some(&static_tables().trees.dtree),
            D_CODES,
            &EXTRA_DBITS,
            0,
            MAX_BITS as u32,
        );
        s.dyn_dtree = dtree;
        /* At this point, opt_len and static_len are the total bit lengths of
         * the compressed block data, excluding the tree representations. */

        /* Build the bit length tree for the above two trees, and get the index
         * in bl_order of the last bit length code to send. */
        max_blindex = build_bl_tree(s);

        /* Determine the best encoding. Compute the block lengths in bytes. */
        opt_lenb = ((s.opt_len.wrapping_add(10)) >> 3) as u32;
        static_lenb = ((s.static_len.wrapping_add(10)) >> 3) as u32;

        if static_lenb <= opt_lenb || s.strategy == crate::compat::zlib::Z_FIXED {
            opt_lenb = static_lenb;
        }
    } else {
        debug_assert!(!stored.is_empty() || stored_len == 0, "lost buf");
        opt_lenb = stored_len + 5; /* force a stored block */
        static_lenb = stored_len + 5;
    }

    let use_stored = stored_len + 4 <= opt_lenb && !stored.is_empty();
    if use_stored {
        /* The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE. */
        tr_stored_block(s, stored, stored_len, last);
    } else if static_lenb == opt_lenb {
        send_bits(s, (STATIC_TREES << 1) + (last as u32), 3);
        compress_block(
            s,
            &static_tables().trees.ltree,
            &static_tables().trees.dtree,
        );
    } else {
        send_bits(s, (DYN_TREES << 1) + (last as u32), 3);
        send_all_trees(s, s.l_max_code + 1, s.d_max_code + 1, max_blindex + 1);
        let mut ltree = std::mem::take(&mut s.dyn_ltree);
        let mut dtree = std::mem::take(&mut s.dyn_dtree);
        compress_block(s, &ltree, &dtree);
        s.dyn_ltree = ltree;
        s.dyn_dtree = dtree;
    }

    init_block(s);

    if last {
        bi_windup(s);
    }
}

/// `_tr_stored_block` — send a stored block (trees.c).
pub fn tr_stored_block(s: &mut DeflateState, buf: &[u8], stored_len: u32, last: bool) {
    send_bits(s, (STORED_BLOCK << 1) + (last as u32), 3); /* send block type */
    bi_windup(s); /* align on byte boundary */
    put_short(s, stored_len);
    put_short(s, !stored_len);
    if stored_len != 0 {
        let start = s.pending as usize;
        let end = start + stored_len as usize;
        s.pending_buf[start..end].copy_from_slice(&buf[..stored_len as usize]);
    }
    s.pending += stored_len;
}

/// `_tr_flush_bits` — flush bits in the bit buffer (leaves at most 7 bits).
pub fn tr_flush_bits(s: &mut DeflateState) {
    bi_flush(s);
}

/// `_tr_align` — send one empty static block (trees.c).
pub fn tr_align(s: &mut DeflateState) {
    send_bits(s, STATIC_TREES << 1, 3);
    send_code(s, END_BLOCK, &static_tables().trees.ltree);
    bi_flush(s);
}

/// `_tr_tally_lit` — tally a literal (deflate.h inline).
pub fn tr_tally_lit(s: &mut DeflateState, c: u8) -> bool {
    let idx = s.sym_next as usize;
    s.sym_buf[idx] = 0;
    s.sym_buf[idx + 1] = 0;
    s.sym_buf[idx + 2] = c;
    s.sym_next += 3;
    s.dyn_ltree[c as usize].freq += 1;
    s.sym_next == s.sym_end
}

/// `_tr_tally_dist` — tally a match (deflate.h inline).
pub fn tr_tally_dist(s: &mut DeflateState, distance: u32, length: u32) -> bool {
    let len = length as u8;
    let dist = distance as u16;
    let idx = s.sym_next as usize;
    s.sym_buf[idx] = dist as u8;
    s.sym_buf[idx + 1] = (dist >> 8) as u8;
    s.sym_buf[idx + 2] = len;
    s.sym_next += 3;
    let mut dist2 = distance;
    dist2 -= 1;
    let tabs = static_tables();
    s.dyn_ltree[tabs.codes.length_code[len as usize] as usize + LITERALS + 1].freq += 1;
    s.dyn_dtree[d_code(dist2)].freq += 1;
    s.matches += 1;
    s.sym_next == s.sym_end
}
