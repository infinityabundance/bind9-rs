# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## LZ-LORE-0001 — the TR46 and NO_TR46 label-test sets disagree on hyphen placement

`lookup.c` runs `_tr46` per label with `TR46_NONTRANSITIONAL_CHECK`, which
includes `TEST_HYPHEN_STARTEND`; the NO_TR46 path (`idn2_lookup_u8` with
`IDN2_NO_TR46`) splits the domain and runs `_idn2_ascii`'s per-label test
set, which has `TEST_2HYPHEN` and `TEST_LEADING_COMBINING` but **no**
`TEST_HYPHEN_STARTEND`.  So `-aä.com` fails `IDN2_HYPHEN_STARTEND` under
NONTRANSITIONAL but encodes to `xn---a-wia.com` under NO_TR46, and `aä-.com`
encodes to `xn--a--via.com`.  The Rust keeps both test sets verbatim;
LZ-0001 pins the asymmetry.  (The `TEST_2HYPHEN` check also requires
`llen >= 4` because it inspects label[2]/label[3], so `aß--b` (4 chars) is
caught but a hypothetical two-char label never can be.)

## LZ-LORE-0002 — dig's C-locale pass-through sends raw UTF-8 on the wire

`dighost.c idn_input` retries `idn2_to_ascii_lz` with TRANSITIONAL only when
the first attempt failed with `IDN2_DISALLOWED`.  Under the C/POSIX locale
(charset ANSI_X3.4-1968) any non-ASCII name fails the locale → UTF-8
conversion first, with an error that is *not* `IDN2_DISALLOWED`, so the
fallback never fires and dig sends the original bytes (the raw UTF-8 name)
unchanged.  The Rust `idn_input` reproduces this with an explicit
ANSI_X3.4-1968 short-circuit.  CLI-DIG-0003 pins a UTF-8 locale for the
conversion path; the C-locale pass-through is LZ-0001's domain.

## LZ-LORE-0003 — `idn2_to_unicode_8zlz` ignores its flags argument

The decode direction (`decode.c`) takes the `flags` parameter for API-shape
compatibility only: `idn2_to_unicode_8zlz` always runs the A-label decode
with the same semantics and converts the output to the locale codeset.
The Rust `to_unicode_8zlz_u8` mirrors the ignored parameter.  The observable
consequences (case-preserving decode of `XN--MNCHEN-3YA.DE`, `IDN2_*
ENCODING_ERROR` when the U-label has no representation in the codeset) are
pinned by LZ-0001 under all three locales.

## LZ-LORE-0004 — `IDN2_NFC_INPUT` only skips the NFC quick check

`_idn2_u8_to_u32_nfc(src, srclen, &p, &plen, flags & IDN2_NFC_INPUT)` runs
`_isNFC` only when the bit is clear; the per-label NFC normalization happens
regardless.  `idn2_lookup_ul` forces `IDN2_NFC_INPUT` after the locale
conversion, so `idn2_to_ascii_lz` never pays for the quick check but is
behaviorally identical to `idn2_to_ascii_8z` under a UTF-8 locale.  The Rust
`to_ascii_lz_u8` forces the bit the same way and `label()` always NFCs.

## LZ-LORE-0005 — the TR46 map is compressed rows plus a LEB128 payload

`tr46map_data.c` stores the UTS #46 table as `idna_map_8/16/24` rows of
5/7/8 bytes each — (cp1, range, flag_index, offset, nmappings), with
`value = (nmappings << 14 | offset) << 3 | flag_index` — and `mapdata` as a
LEB128-style byte stream.  The Rust decodes the rows with
`partition_point` binary search and the payload with `get_map_data`, exactly
like `tr46map.c`'s `_fill_map`/`get_map_data`.  `libidn2_tr46map.rs` is
generated from the pinned `tr46map_data.c` (sha256 embedded) by
`scripts/archaeology/gen-libidn2-tr46map.py`, so a drifted oracle baseline
is a forensic event.
