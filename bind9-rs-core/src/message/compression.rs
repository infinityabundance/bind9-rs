//! Message name compression — a byte-exact port of BIND's `dns_compress`
//! machinery (lib/dns/compress.c, 9.20.26), courted byte-for-byte by the
//! `RENDER-COMPRESS-*` courts.
//!
//! Why a *port* rather than an approximation (residual evidence: an earlier
//! HashMap-based design rendered `www.example.com.` after `example.com.` as
//! a pointer to the whole-name entry, while BIND emits `www` + a pointer to
//! the `example.com.` *suffix* recorded at its first occurrence):
//!
//! - BIND's table is a fixed-size robin-hood hash set of `(hash, coff)`
//!   pairs — 64 slots by default, 1024 with `DNS_COMPRESS_LARGE` — keyed by
//!   a 16-bit hash built one label at a time: DJB2 (`hash*33 + byte`)
//!   folded through `isc_hash_bits32(h, 16) = (h * ISC_HASH_GOLDENRATIO_32) >> 16`
//!   (lib/isc/include/isc/hash.h);
//! - suffix matches are *verified against the actual message bytes*
//!   (`match_suffix`), and insertion of the unmatched prefix continues from
//!   the search's probe position (`insert`/`insert_label`), displacing
//!   closer elements robin-hood style;
//! - the table stores only the **first** occurrence offset of each suffix
//!   and refuses new entries past 75% load or at offsets ≥ 0x4000.
//!
//! All three properties are externally observable in the rendered bytes —
//! which suffix is chosen, at which offset, and whether a later name still
//! compresses — which is why the court compares cumulative message hex
//! rather than just "did it compress".

// The hash set mirrors BIND's `struct dns_compress_slot` (uint16_t hash /
// coff) and `struct dns_compress` (uint16_t mask / count).  Every narrowing
// cast below is guarded by the exact check BIND performs before it (coff <
// 0x4000, mask ≤ 1023, old_coff < 0x4000, count ≤ 48/768), so truncation is
// intentional and cannot lose information; the allows are the documented
// port boundary, not a blanket waiver.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

use crate::name::{Name, MAX_LABELS};

/// Pointers can only address offsets below 2^14 (RFC 1035 §4.1.4); BIND
/// refuses to *insert* table entries at offsets ≥ this (`insert_label`).
pub const POINTER_MAX: usize = 0x4000;

/// BIND `HASH_INIT_DJB2` (lib/dns/compress.c).
const HASH_INIT_DJB2: u16 = 5381;

/// BIND `ISC_HASH_GOLDENRATIO_32` (lib/isc/include/isc/hash.h).  `hash_label`
/// folds the DJB2 accumulator to 16 bits with `(h * GOLDEN) >> 16`.
const GOLDEN_RATIO_32: u32 = 0x61C8_8647;

/// BIND `DNS_COMPRESS_SMALLBITS` (lib/dns/include/dns/compress.h): the
/// default 64-slot set.
const SMALL_SLOTS: usize = 1 << 6;

/// BIND `DNS_COMPRESS_LARGEBITS`: the 1024-slot set for messages expected
/// to contain many names — AXFR/IXFR responses (lib/ns/xfrout.c uses
/// `DNS_COMPRESS_CASE | DNS_COMPRESS_LARGE`) and update requests
/// (lib/dns/request.c).  The choice is observable: with 64 slots the 75%
/// load cap (48 entries) stops the table from accepting new names earlier.
const LARGE_SLOTS: usize = 1 << 10;

/// One hash-set slot (BIND `struct dns_compress_slot`).  `coff == 0` is the
/// empty sentinel; real compression offsets are never zero because the DNS
/// header occupies message offset 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Slot {
    hash: u16,
    coff: u16,
}

/// The robin-hood hash set (BIND's `cctx->set`/`mask`/`count`).
#[derive(Debug)]
struct Table {
    set: Vec<Slot>,
    mask: usize,
    count: u16,
}

impl Table {
    fn new(slots: usize) -> Self {
        Self {
            set: vec![Slot::default(); slots],
            mask: slots - 1,
            count: 0,
        }
    }

    /// BIND `probe_distance`: circular distance from the element's home
    /// slot (its stored hash) to `slot`, computed mod 2^k where the table
    /// has 2^k slots.  The wrap-around arithmetic is deliberate: `hash` is
    /// an arbitrary 16-bit value, `slot` is masked, and C's `(slot - hash)
    /// & mask` on a negative int yields exactly this mod-2^k result.
    #[inline]
    fn probe_distance(&self, slot: usize) -> usize {
        (slot.wrapping_sub(self.set[slot].hash as usize)) & self.mask
    }

    /// BIND `insert_label`: place `(hash, coff)` at probe distance `probe`
    /// from its home slot, robin-hood swapping with any closer element and
    /// continuing with the displaced one.
    ///
    /// Returns false — and records nothing — when the entry would have an
    /// invalid compression offset (≥ 0x4000) or when the set is over 75%
    /// full (BIND: `count > mask * 3 / 4`).
    fn insert_label(&mut self, coff: usize, mut hash: u16, mut probe: usize) -> bool {
        if coff >= POINTER_MAX || self.count > (self.mask as u16) * 3 / 4 {
            return false;
        }
        let mut coff = coff as u16;
        loop {
            let slot = (hash as usize + probe) & self.mask;
            if self.set[slot].coff == 0 {
                self.set[slot] = Slot { hash, coff };
                self.count += 1;
                return true;
            }
            // "he steals from the rich and gives to the poor": the new
            // element takes the slot, the displaced element continues from
            // the probe distance it had.
            let dist = self.probe_distance(slot);
            if probe > dist {
                probe = dist;
                std::mem::swap(&mut self.set[slot].hash, &mut hash);
                std::mem::swap(&mut self.set[slot].coff, &mut coff);
            }
            probe += 1;
        }
    }

    /// BIND `dns_compress_rollback`: remove every entry at offset ≥
    /// `offset`, sliding later elements of the affected probe sequences
    /// back over the hole (stopping at distance-zero elements).
    fn rollback(&mut self, offset: usize) {
        for slot in 0..=self.mask {
            if usize::from(self.set[slot].coff) < offset {
                continue;
            }
            let mut prev = slot;
            let mut next = (prev + 1) & self.mask;
            while self.set[next].coff != 0 && self.probe_distance(next) != 0 {
                self.set[prev] = self.set[next];
                prev = next;
                next = (prev + 1) & self.mask;
            }
            self.set[prev] = Slot::default();
            self.count -= 1;
        }
    }
}

/// BIND `isc__ascii_tolower1` (lib/isc/include/isc/ascii.h): adds 32 to
/// `A`..=`Z` only.  Label-length octets are < 0x40, so hashing and
/// comparison are unaffected by the fold — exactly as BIND's comment notes.
#[inline]
fn tolower1(c: u8) -> u8 {
    // isc__ascii_tolower1 (lib/isc/include/isc/ascii.h): adds 32 to
    // A..=Z only (is_ascii_uppercase is exactly 'A' <= c <= 'Z').
    c + (b'a' - b'A') * u8::from(c.is_ascii_uppercase())
}

/// BIND `hash_label`: DJB2 over the length octet + label octets of **one**
/// label, folded to 16 bits.  The caller accumulates one label per call,
/// right-to-left across the name, so the stored value is *not* the DJB2 of
/// the suffix bytes in wire order — it is only a filter; `match_suffix`
/// does the real comparison.  `first_label` is `[len][label bytes]`.
#[inline]
fn hash_label(init: u16, first_label: &[u8], case_sensitive: bool) -> u16 {
    let mut h: u32 = u32::from(init);
    for &b in first_label {
        let b = if case_sensitive { b } else { tolower1(b) };
        h = h.wrapping_mul(33).wrapping_add(u32::from(b));
    }
    ((h.wrapping_mul(GOLDEN_RATIO_32)) >> 16) as u16
}

/// BIND `match_wirename` / `isc_ascii_lowerequal`.
#[inline]
fn wire_equal(a: &[u8], b: &[u8], case_sensitive: bool) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if case_sensitive {
        a == b
    } else {
        a.iter().zip(b).all(|(&x, &y)| tolower1(x) == tolower1(y))
    }
}

/// BIND `match_suffix`: verify that the message bytes at `new_coff` really
/// are `sptr` (a suffix of the rendered name), and that this occurrence is
/// followed by the previously matched shorter suffix (at `old_coff`) — as a
/// literal copy, a compression pointer to it, or the root label.
fn match_suffix(
    buf: &[u8],
    new_coff: usize,
    sptr: &[u8],
    old_coff: usize,
    case_sensitive: bool,
) -> bool {
    // A pointer to old_coff (BIND builds these bytes even for the initial
    // old_coff == 0, i.e. a pointer to the root label).
    let pptr = [0xc0 | ((old_coff >> 8) as u8), (old_coff & 0xff) as u8];
    let blen0 = buf.len();
    let llen = sptr[0] as usize + 1;
    debug_assert!(llen <= 64 && llen < sptr.len());
    if blen0 < new_coff + llen {
        return false;
    }
    let mut bptr = &buf[new_coff..];
    let mut blen = blen0 - new_coff;
    // Does the first label of the suffix appear here?
    if !wire_equal(&bptr[..llen], &sptr[..llen], case_sensitive) {
        return false;
    }
    // Is this label followed by the previously matched suffix?
    if old_coff == new_coff + llen {
        return true;
    }
    blen -= llen;
    bptr = &bptr[llen..];
    let srest = &sptr[llen..];
    let slen = srest.len();
    // Are both labels followed by the root label?
    if blen >= 1 && slen == 1 && bptr[0] == 0 && srest[0] == 0 {
        return true;
    }
    // Is this label followed by a pointer to the previous match?
    if blen >= 2 && bptr[0] == pptr[0] && bptr[1] == pptr[1] {
        return true;
    }
    // Is this label followed by a full copy of the rest of the suffix?
    blen >= slen && wire_equal(&bptr[..slen], srest, case_sensitive)
}

/// BIND `insert`: continue from the search loop's probe position, inserting
/// the unmatched suffix and then every wider suffix of the name (each wider
/// suffix accumulates the next label into the hash, with `probe` reset).
#[allow(clippy::too_many_arguments)]
fn insert(
    table: &mut Table,
    scratch: &[u8],
    offsets: &[usize],
    mut label: usize,
    mut hash: u16,
    mut probe: usize,
    buffer_len: usize,
    case_sensitive: bool,
) {
    loop {
        let prefix_len = offsets[label];
        if !table.insert_label(buffer_len + prefix_len, hash, probe) {
            return;
        }
        if label == 0 {
            return;
        }
        label -= 1;
        let start = offsets[label];
        let first_len = 1 + scratch[start] as usize;
        hash = hash_label(hash, &scratch[start..start + first_len], case_sensitive);
        probe = 0;
    }
}

/// The message compressor.
///
/// Mirrors BIND's `dns_compress_t` + `dns_name_towire` (with
/// `name_coff == NULL`).  The observable contract, courted by
/// `RENDER-COMPRESS-*`:
///
/// - `disabled` (`DNS_COMPRESS_DISABLED`) makes name processing a complete
///   no-op: no table updates, no pointers.
/// - `permitted` (`DNS_COMPRESS_PERMITTED`) only gates whether pointers are
///   *emitted*; `dns_name_towire` always runs the table search/insert, so
///   an uncompressed name still becomes a compression target for later
///   names (RFC 3597 / TSIG names are the classic case).
#[derive(Debug)]
pub struct Compressor {
    table: Table,
    permitted: bool,
    disabled: bool,
    /// BIND `DNS_COMPRESS_CASE`.  Note: `named` enables case-*sensitive*
    /// compression by default for query responses (lib/ns/client.c), unless
    /// the peer matches the view's `nocasecompress` ACL; AXFR/IXFR use
    /// `CASE | LARGE` (lib/ns/xfrout.c).  Courted when the authoritative
    /// server lands.
    case_sensitive: bool,
    /// Scratch for the wire form plus the root octet (BIND's `ndata`).
    scratch: Vec<u8>,
}

impl Compressor {
    /// A fresh compressor for a new message (BIND `dns_compress_init`
    /// with flags 0: small table, permitted, case-insensitive).
    #[must_use]
    pub fn new() -> Self {
        Self::with_flags(false, false, false)
    }

    /// A compressor with explicit BIND flags (`disabled` =
    /// `DNS_COMPRESS_DISABLED`, `large` = `DNS_COMPRESS_LARGE`,
    /// `case_sensitive` = `DNS_COMPRESS_CASE`).  `permitted` starts set.
    #[must_use]
    pub fn with_flags(disabled: bool, large: bool, case_sensitive: bool) -> Self {
        Self {
            table: Table::new(if large { LARGE_SLOTS } else { SMALL_SLOTS }),
            permitted: true,
            disabled,
            case_sensitive,
            scratch: Vec::new(),
        }
    }

    /// Set whether pointers may be emitted (BIND
    /// `dns_compress_setpermitted`).  Names are still added to the table
    /// either way (`dns_name_towire` always calls `dns_compress_name`).
    pub const fn set_permitted(&mut self, permitted: bool) {
        self.permitted = permitted;
    }

    /// Whether pointers may be emitted (BIND `dns_compress_getpermitted`).
    #[must_use]
    pub const fn is_permitted(&self) -> bool {
        self.permitted
    }

    /// Remove every table entry at offset ≥ `offset` (BIND
    /// `dns_compress_rollback`); the message renderer uses this to undo
    /// the effect of an abandoned render.
    pub fn rollback(&mut self, offset: usize) {
        self.table.rollback(offset);
    }

    /// BIND `dns_compress_name`: find the longest suffix of `name` present
    /// in the table and insert the unmatched prefix.  `buf` is the message
    /// rendered so far; `buffer_len` is where `name` will start.
    ///
    /// Returns `(prefix_len, suffix_coff)` in BIND's terms: `prefix_len`
    /// octets of the wire form (including the root octet when the whole
    /// name is unmatched) must be written literally; a nonzero
    /// `suffix_coff` is followed by a two-octet pointer.
    fn compress_name(&mut self, name: &Name, buf: &[u8], buffer_len: usize) -> (usize, usize) {
        // BIND requires absolute names: the root octet that every suffix
        // hash/comparison ends with exists only for absolute names.
        debug_assert!(name.is_absolute());
        self.scratch.clear();
        self.scratch.extend_from_slice(name.as_wire_slice());
        self.scratch.push(0); // root octet (BIND ndata always ends with it)
        let scratch: &[u8] = &self.scratch;
        let full = scratch.len();

        // Label offsets within the wire form (BIND dns_offsets_t).  The
        // root label's index is `labels`; the loop below never uses it as a
        // body label (it starts at `labels - 1` and decrements).
        let mut offsets = [0usize; MAX_LABELS];
        let mut labels = 0usize;
        let mut i = 0usize;
        while i < name.wire_len() {
            offsets[labels] = i;
            labels += 1;
            i += 1 + scratch[i] as usize;
        }

        // Walk the suffixes from rightmost (shortest) to leftmost (whole
        // name); each step accumulates the next label into the hash.  A
        // match overwrites the return values, so the *longest* matching
        // suffix wins.
        let mut return_prefix = full;
        let mut return_coff = 0usize;
        let mut hash: u16 = HASH_INIT_DJB2;
        let mut label = labels; // index of the root label
        while label > 0 {
            label -= 1;
            let prefix_len = offsets[label];
            let suffix = &scratch[prefix_len..];
            let first_len = 1 + suffix[0] as usize;
            hash = hash_label(hash, &suffix[..first_len], self.case_sensitive);
            let mut probe = 0usize;
            loop {
                let slot = (hash as usize + probe) & self.table.mask;
                let coff = self.table.set[slot].coff;
                // If the entry would be inserted here (empty slot or this
                // probe distance beats the resident's), our suffix cannot
                // be in the table: insert the unmatched prefix and stop.
                if coff == 0 || probe > self.table.probe_distance(slot) {
                    insert(
                        &mut self.table,
                        scratch,
                        &offsets,
                        label,
                        hash,
                        probe,
                        buffer_len,
                        self.case_sensitive,
                    );
                    return (return_prefix, return_coff);
                }
                // This slot matches: provisionally record it and continue
                // with the next (wider) suffix.
                if hash == self.table.set[slot].hash
                    && match_suffix(buf, coff as usize, suffix, return_coff, self.case_sensitive)
                {
                    return_coff = coff as usize;
                    return_prefix = prefix_len;
                    break;
                }
                probe += 1;
            }
        }
        (return_prefix, return_coff)
    }

    /// Render `name` into `out` — BIND `dns_name_towire` with
    /// `name_coff == NULL` (lib/dns/name.c 9.20.26).
    pub fn render(&mut self, name: &Name, out: &mut Vec<u8>) {
        if name.wire_len() == 0 {
            // Root: the single root octet; the table is untouched (BIND's
            // label loop never runs for a one-label name, so nothing is
            // inserted or matched).
            out.push(0);
            return;
        }
        debug_assert!(name.is_absolute());
        let compress = self.permitted && !name.is_nocompress();
        let full = name.wire_len() + 1; // BIND name->length (includes root)
        let (mut prefix_len, mut suffix_coff) = (full, 0usize);
        if !self.disabled {
            (prefix_len, suffix_coff) = self.compress_name(name, &out[..], out.len());
        }
        if !compress {
            // BIND resets the return values when the name must not be
            // compressed: the full name is written, but dns_compress_name
            // already ran, so the table still gained this name for later
            // names to compress against.
            prefix_len = full;
            suffix_coff = 0;
        }
        let data = name.as_wire_slice();
        if prefix_len > data.len() {
            out.extend_from_slice(data);
            out.push(0);
        } else {
            out.extend_from_slice(&data[..prefix_len]);
        }
        if suffix_coff > 0 {
            out.push(0xc0 | ((suffix_coff >> 8) as u8));
            out.push((suffix_coff & 0xff) as u8);
        }
    }

    /// Render a name without consulting the compression table at all
    /// (question-section standalone rendering; the question cannot
    /// compress against anything earlier, and the message renderer routes
    /// it through [`Compressor::render`] so it still populates the table).
    pub fn render_uncompressed(name: &Name, out: &mut Vec<u8>) {
        out.extend_from_slice(name.as_wire_slice());
        out.push(0);
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

    /// The expectations in this module were verified against the real BIND
    /// oracle (RENDER-COMPRESS-0001..0005 courts, 9.20.26) and then frozen
    /// as regression invariants.  Note the empty-slot sentinel: `coff == 0`
    /// means "no entry" (the DNS header occupies offset 0 in real
    /// messages), so a name whose *whole-name* entry would sit at offset 0
    /// is invisible — later names match its shorter stored suffixes.
    #[test]
    fn root_not_compressed() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("."), &mut out);
        assert_eq!(out, b"\x00");
        // Root is never added, so a second render is still uncompressed.
        let mut out2 = Vec::new();
        c.render(&n("."), &mut out2);
        assert_eq!(out2, b"\x00");
    }

    #[test]
    fn second_render_matches_suffix_at_first_occurrence() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        assert_eq!(out, b"\x07example\x03com\x00");
        // The whole-name entry for offset 0 is the empty-slot sentinel, so
        // the second render matches "com." at its first occurrence
        // (offset 8): `\x07example` + pointer.  Oracle-verified.
        c.render(&n("example.com."), &mut out);
        assert_eq!(&out[13..], b"\x07example\xc0\x08");
    }

    #[test]
    fn longest_suffix_wins() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        // "www.example.com." cannot point at the invisible whole-name
        // entry at 0; the longest visible stored suffix is "com." at 8,
        // so BIND emits www + example + pointer.  Oracle-verified.
        c.render(&n("www.example.com."), &mut out);
        let tail = &out[13..];
        assert_eq!(tail, b"\x03www\x07example\xc0\x08");
    }

    #[test]
    fn ghost_entry_at_offset_zero_is_invisible() {
        // "com." rendered first stores its whole-name entry at offset 0
        // (the empty-slot sentinel) and only "com."@0 — so a later
        // "example.com." finds nothing and renders in full.
        // Oracle-verified (RENDER-COMPRESS-0001).
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("com."), &mut out);
        c.render(&n("example.com."), &mut out);
        assert_eq!(out, b"\x03com\x00\x07example\x03com\x00");
    }

    #[test]
    fn matching_is_case_insensitive_by_default() {
        // DNS_COMPRESS_CASE is not set: "Example.COM." and
        // "www.example.com." share suffixes.  Oracle-verified.
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("Example.COM."), &mut out);
        c.render(&n("www.example.com."), &mut out);
        let tail = &out[13..];
        assert_eq!(tail, b"\x03www\x07example\xc0\x08");
    }

    #[test]
    fn case_sensitive_flag_distinguishes_case() {
        // With DNS_COMPRESS_CASE set (as named does for query responses by
        // default), "Example.COM." is not a suffix match for
        // "www.example.com." — nothing compresses.  Oracle-verified
        // (RENDER-COMPRESS-0003).
        let mut c = Compressor::with_flags(false, false, true);
        let mut out = Vec::new();
        c.render(&n("Example.COM."), &mut out);
        c.render(&n("www.example.com."), &mut out);
        assert_eq!(out, b"\x07Example\x03COM\x00\x03www\x07example\x03com\x00");
    }

    #[test]
    fn disabled_leaves_table_untouched() {
        // DNS_COMPRESS_DISABLED: dns_compress_name is a no-op, so a second
        // render of the same name is still fully written.
        let mut c = Compressor::with_flags(true, false, false);
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        c.render(&n("example.com."), &mut out);
        assert_eq!(out, b"\x07example\x03com\x00\x07example\x03com\x00");
    }

    #[test]
    fn not_permitted_still_populates_table() {
        // setpermitted(false) (RFC 3597): no pointers emitted, but the
        // table gains the names; a later name compresses against them.
        // The mail render's pointer to 17 is oracle-verified: the enabled
        // mode produces the identical table state (RENDER-COMPRESS-0001
        // and 0005 use the same corpus; 0005 differs only in that no
        // pointers appear).
        let mut c = Compressor::new();
        c.set_permitted(false);
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        c.render(&n("www.example.com."), &mut out);
        assert_eq!(out, b"\x07example\x03com\x00\x03www\x07example\x03com\x00");
        c.set_permitted(true);
        c.render(&n("mail.example.com."), &mut out);
        // "example.com." was stored at its first occurrence (offset 17,
        // inside the uncompressed www render) — mail points there.
        // www.example.com. renders in full (17 octets): 13 + 17 = 30.
        let tail = &out[30..];
        assert_eq!(tail, &[0x04, b'm', b'a', b'i', b'l', 0xc0, 0x11]);
    }

    #[test]
    fn nocompress_name_still_populates_table() {
        // BIND DNS_NAMEATTR_NOCOMPRESS (TSIG key names): full name written,
        // but later names still compress against it.
        let mut c = Compressor::new();
        let mut out = Vec::new();
        let key = n("key.example.com.").with_nocompress(true);
        c.render(&key, &mut out);
        c.render(&n("www.example.com."), &mut out);
        // key.example.com. is 17 wire octets; www compresses against the
        // "example.com." suffix at its first occurrence (offset 4).
        let tail = &out[17..];
        assert_eq!(tail, &[0x03, b'w', b'w', b'w', 0xc0, 0x04]);
    }

    #[test]
    fn insert_rejects_offsets_at_pointer_max() {
        let mut table = Table::new(SMALL_SLOTS);
        assert!(!table.insert_label(POINTER_MAX, 0x1234, 0));
        assert!(table.insert_label(POINTER_MAX - 1, 0x1234, 0));
        assert_eq!(table.count, 1);
    }

    #[test]
    fn load_cap_is_75_percent() {
        let mut table = Table::new(SMALL_SLOTS);
        // BIND: `count > mask * 3 / 4` refuses further inserts — exactly
        // 48 of 64 slots (75%) may be occupied; the 49th is refused.
        for i in 0..48 {
            assert!(table.insert_label(12 + i, ((i as u16) << 1) | 1, 0));
        }
        assert!(!table.insert_label(12 + 48, 0xbeef, 0));
        assert_eq!(table.count, 48);
    }

    #[test]
    fn rollback_removes_entries_from_offset() {
        let mut table = Table::new(SMALL_SLOTS);
        assert!(table.insert_label(10, 0x1111, 0));
        assert!(table.insert_label(20, 0x2222, 0));
        assert!(table.insert_label(30, 0x3333, 0));
        table.rollback(20);
        assert_eq!(table.count, 1);
        assert_eq!(table.set.iter().filter(|s| s.coff != 0).count(), 1);
        assert!(table.set.iter().any(|s| s.coff == 10));
    }

    #[test]
    fn large_table_allows_more_entries() {
        let mut small = Table::new(SMALL_SLOTS);
        let mut large = Table::new(LARGE_SLOTS);
        for i in 0..200usize {
            let ok_small = small.insert_label(12 + i, ((i * 7919) & 0xffff) as u16, 0);
            let ok_large = large.insert_label(12 + i, ((i * 7919) & 0xffff) as u16, 0);
            // The small table must stop at 48; the large table keeps going.
            if i < 48 {
                assert!(ok_small);
            } else {
                assert!(!ok_small);
            }
            assert!(ok_large);
        }
        assert_eq!(large.count, 200);
    }
}
