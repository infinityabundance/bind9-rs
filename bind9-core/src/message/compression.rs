//! Message name compression, mirroring BIND's `dns_compress` (§16).
//!
//! BIND's observable algorithm (`lib/dns/compress.c`), courted by
//! `RENDER-COMPRESS-*` against captured oracle packets:
//!
//! - A table records every label-boundary *suffix* of each rendered name,
//!   with the offset at which that suffix begins in the message — but only
//!   for offsets `< 0x4000` (the 14-bit pointer limit).
//! - When rendering a name, the **longest** suffix already present in the
//!   table is replaced by a two-octet pointer; the remaining (prefix) labels
//!   are written uncompressed first.
//! - Names rendered after the 16384-octet boundary are not compressed (and
//!   stop being added to the table).
//! - The root name (one octet) is never worth compressing and BIND does not
//!   do so; the table never contains the empty suffix.
//!
//! The internal hash table here is Rust-idiomatic; BIND's exact hash
//! function is unobservable (lookups are equality-checked).  What is
//! observable — *which* suffix is chosen — is courted byte-for-byte.

use crate::name::Name;
use std::collections::HashMap;

/// Pointers can only address offsets below 2^14 (RFC 1035 §4.1.4; BIND
/// `DNS_POINTER_MAXOFFSET`).
pub const POINTER_MAX: usize = 0x4000;

/// Case-fold a wire suffix for the compressor's keys (BIND matches suffixes
/// case-insensitively; label length octets are < 64 so they are unaffected).
fn lower(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.to_ascii_lowercase()).collect()
}

/// The message compressor.
///
/// Matching is case-insensitive, exactly like BIND's (`DNS_COMPRESS_CASE`
/// is not set for messages; suffixes are compared with tolower).  The suffix
/// keys are therefore stored lowercased.
#[derive(Debug, Default)]
pub struct Compressor {
    /// Lowercased suffix wire bytes → offset in the message.
    table: HashMap<Vec<u8>, usize>,
}

/// A compression match: the matched suffix plus its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Number of *leading* labels of the name not covered by the match.
    pub prefix_labels: usize,
    /// Offset of the matched suffix in the message.
    pub offset: usize,
}

impl Compressor {
    /// A fresh compressor for a new message.
    #[must_use]
    pub fn new() -> Self {
        Compressor {
            table: HashMap::new(),
        }
    }

    /// Record the suffixes of `name` at `offset`, subject to the 0x4000 and
    /// non-empty-suffix rules.  Mirrors `dns_compress_add` (via
    /// `insert`/`insert_label` in 9.20), where each suffix is recorded at
    /// `buffer_length + prefix_len` — i.e. the message offset of that
    /// suffix, not the name start.
    pub fn add(&mut self, name: &Name, offset: usize) {
        if offset >= POINTER_MAX {
            return;
        }
        let data = name.as_wire_slice();
        let mut i = 0;
        while i < data.len() {
            let len = data[i] as usize;
            let suffix = &data[i..];
            // Insert only if not already present; keep the earliest offset
            // (a pointer may only point backwards, so earliest is always
            // usable from any later position).
            self.table.entry(lower(suffix)).or_insert(offset + i);
            i += 1 + len;
        }
    }

    /// Find the longest suffix of `name` present in the table.
    /// Mirrors `dns_compress_find` (9.20's `dns_compress_name`), which walks
    /// from the last real label backwards and keeps the first (longest)
    /// match.
    #[must_use]
    pub fn find(&self, name: &Name) -> Option<Match> {
        let data = name.as_wire_slice();
        let mut i = 0;
        let mut label_idx = 0;
        while i < data.len() {
            if let Some(&offset) = self.table.get(&lower(&data[i..])) {
                return Some(Match {
                    prefix_labels: label_idx,
                    offset,
                });
            }
            let len = data[i] as usize;
            i += 1 + len;
            label_idx += 1;
        }
        None
    }

    /// Render `name` into `out`, using compression when a match exists.
    ///
    /// Returns the offset at which the name starts in `out` (the position
    /// before this name was written), so callers can record it — mirroring
    /// BIND's message renderer, which adds every rendered name to the
    /// compressor.
    pub fn render(&mut self, name: &Name, out: &mut Vec<u8>) {
        if name.wire_len() == 0 {
            // Root: single octet, never compressed.
            out.push(0);
            return;
        }
        if let Some(m) = self.find(name) {
            // A pointer must reference an already-written offset within the
            // 14-bit range.  BIND does not re-check the current buffer
            // length here: the table only ever receives offsets recorded at
            // write time, so entries always point at prior data.  (Removing
            // a defensive length check here matches dns_name_towire, which
            // has no such guard either — courted by RENDER-COMPRESS-*.)
            if m.offset >= POINTER_MAX {
                let start = out.len();
                out.extend_from_slice(name.as_wire_slice());
                out.push(0);
                self.add(name, start);
                return;
            }
            let data = name.as_wire_slice();
            let mut i = 0;
            let mut label_idx = 0;
            while label_idx < m.prefix_labels {
                let len = data[i] as usize;
                out.extend_from_slice(&data[i..i + 1 + len]);
                i += 1 + len;
                label_idx += 1;
            }
            out.push(0xc0 | ((m.offset >> 8) as u8));
            out.push((m.offset & 0xff) as u8);
        } else {
            let start = out.len();
            out.extend_from_slice(name.as_wire_slice());
            out.push(0);
            self.add(name, start);
        }
    }

    /// Render an uncompressed name (question names, per BIND's renderer
    /// behavior; courted by `RENDER-QUESTION-COMPRESSION`).
    pub fn render_uncompressed(name: &Name, out: &mut Vec<u8>) {
        out.extend_from_slice(name.as_wire_slice());
        out.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;

    fn n(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

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
    fn full_name_match() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        assert_eq!(out, b"\x07example\x03com\x00");
        // Second render of the same name compresses to a pointer to 0.
        c.render(&n("example.com."), &mut out);
        assert_eq!(out[out.len() - 2..], [0xc0, 0x00]);
    }

    #[test]
    fn longest_suffix_wins() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        // "www.example.com." should compress the "example.com." suffix
        // (13 bytes for the first name, then www + pointer to offset 0).
        c.render(&n("www.example.com."), &mut out);
        let tail = &out[13..];
        assert_eq!(tail, &[0x03, b'w', b'w', b'w', 0xc0, 0x00]);
    }

    #[test]
    fn shorter_suffix_when_only_that_exists() {
        let mut c = Compressor::new();
        let mut out = Vec::new();
        // Only "com." is present (5 bytes).
        c.render(&n("com."), &mut out);
        c.render(&n("example.com."), &mut out);
        let tail = &out[5..];
        assert_eq!(
            tail,
            &[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xc0, 0x00]
        );
    }

    #[test]
    fn offset_limit() {
        // Names added beyond 0x4000 must not be added to the table.
        let mut c = Compressor::new();
        c.add(&n("example.com."), POINTER_MAX);
        assert!(c.find(&n("example.com.")).is_none());
        c.add(&n("example.com."), POINTER_MAX - 1);
        assert!(c.find(&n("example.com.")).is_some());
    }

    #[test]
    fn pointer_bytes() {
        // One compressor + one buffer per message (as in BIND).  The second
        // render of the same name is a full-match pointer to offset 0.
        let mut c = Compressor::new();
        let mut out = Vec::new();
        c.render(&n("example.com."), &mut out);
        c.render(&n("example.com."), &mut out);
        assert_eq!(&out[13..], &[0xc0, 0x00]);
    }
}
