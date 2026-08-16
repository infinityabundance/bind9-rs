//! IDNA2008 + UTS #46 (libidn2) — native Rust conservation of the libidn2
//! surface BIND 9.20.26 `dig` actually uses (§28).
//!
//! Archaeology (pinned sources): `bin/dig/dighost.c` `idn_input`/`idn_filter`
//! call exactly two functions, with a NONTRANSITIONAL→TRANSITIONAL fallback on
//! `IDN2_DISALLOWED`:
//!
//! ```text
//! idn2_to_ascii_lz(src, IDN2_NONTRANSITIONAL);  fallback IDN2_TRANSITIONAL
//! idn2_to_unicode_8zlz(src, IDN2_NONTRANSITIONAL); fallback IDN2_TRANSITIONAL
//! ```
//!
//! The pipeline (lib/lookup.c, lib/idna.c, lib/decode.c, lib/tr46map.{h,c},
//! lib/bidi.c, lib/context.c, lib/data.c): `set_default_flags` →
//! `_tr46` (the UTS #46 mapping table from `tr46map_data.c`, always NFC) →
//! per-label `label()` (NFC, the IDNA2008 label tests, punycode, A-label
//! roundtrip) → concatenation with `.` and 255/63 length limits.  The
//! label-test suite, the RFC 5893 bidi check (`bidi.c`), and the RFC 5892
//! context rules (`context.c`) are transcribed 1:1; the Unicode data
//! (derived property, TR46 map, bidi classes, joining types, general
//! categories, scripts, combining classes) comes from the pinned C tables
//! (`libidn2_data.rs`, `libidn2_tr46map.rs`) and the ICU4X `icu_properties`
//! data set (the same audited engine family as the `idna` crate).
//!
//! The `_lz` locale layer is also transcribed: `idn2_to_ascii_lz` =
//! `idn2_lookup_ul` (convert the input from the locale codeset to UTF-8 via
//! iconv — `IDN2_ICONV_FAIL` on failure — then `idn2_lookup_u8` with
//! `IDN2_NFC_INPUT`), and `idn2_to_unicode_8zlz` (decode to UTF-8, then
//! convert the output to the locale codeset — `IDN2_ENCODING_ERROR` on
//! failure).  The codeset is resolved from `LC_ALL` > `LC_CTYPE` > `LANG`
//! like glibc; the court pins `C.UTF-8`, `C` (ANSI_X3.4-1968) and
//! `en_US.ISO-8859-1`.
//!
//! Status: Phase 1.  dig-facing surface + the locale layer + `IDN2_NO_TR46`
//! (pure IDNA2008) conserved; LZ-0001 court green at 0 residuals.

use icu_properties::props::{
    BidiClass, CanonicalCombiningClass, GeneralCategory, JoiningType, Script,
};
use icu_properties::CodePointMapData;
use unicode_normalization::UnicodeNormalization;

#[path = "libidn2_data.rs"]
mod libidn2_data;
use libidn2_data::{property, IdnaState};

#[path = "libidn2_tr46map.rs"]
mod libidn2_tr46map;
use libidn2_tr46map::{Flag, IDNA_FLAGS, IDNA_MAP_16, IDNA_MAP_24, IDNA_MAP_8, MAPDATA};

/// `idn2_flags` (idn2.h.in:191).
pub mod flags {
    pub const NFC_INPUT: i32 = 1;
    pub const ALABEL_ROUNDTRIP: i32 = 2;
    pub const TRANSITIONAL: i32 = 4;
    pub const NONTRANSITIONAL: i32 = 8;
    pub const ALLOW_UNASSIGNED: i32 = 16;
    pub const USE_STD3_ASCII_RULES: i32 = 32;
    pub const NO_TR46: i32 = 64;
    pub const NO_ALABEL_ROUNDTRIP: i32 = 128;
}

/// `idn2_rc` (idn2.h.in:260).  All errors are negative; `OK` is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    Ok = 0,
    Malloc = -100,
    NoCodeset = -101,
    IconvFail = -102,
    EncodingError = -200,
    Nfc = -201,
    PunycodeBadInput = -202,
    PunycodeBigOutput = -203,
    PunycodeOverflow = -204,
    TooBigDomain = -205,
    TooBigLabel = -206,
    InvalidAlabel = -207,
    UalabelMismatch = -208,
    InvalidFlags = -209,
    NotNfc = -300,
    TwoHyphen = -301,
    HyphenStartEnd = -302,
    LeadingCombining = -303,
    Disallowed = -304,
    ContextJ = -305,
    ContextJNoRule = -306,
    ContextO = -307,
    ContextONoRule = -308,
    Unassigned = -309,
    Bidi = -310,
    DotInLabel = -311,
    InvalidTransitional = -312,
    InvalidNontransitional = -313,
    AlabelRoundtripFailed = -314,
}

impl Error {
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// `idn2_strerror_name`-style rendering of the enum name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Error::Ok => "IDN2_OK",
            Error::Malloc => "IDN2_MALLOC",
            Error::NoCodeset => "IDN2_NO_CODESET",
            Error::IconvFail => "IDN2_ICONV_FAIL",
            Error::EncodingError => "IDN2_ENCODING_ERROR",
            Error::Nfc => "IDN2_NFC",
            Error::PunycodeBadInput => "IDN2_PUNYCODE_BAD_INPUT",
            Error::PunycodeBigOutput => "IDN2_PUNYCODE_BIG_OUTPUT",
            Error::PunycodeOverflow => "IDN2_PUNYCODE_OVERFLOW",
            Error::TooBigDomain => "IDN2_TOO_BIG_DOMAIN",
            Error::TooBigLabel => "IDN2_TOO_BIG_LABEL",
            Error::InvalidAlabel => "IDN2_INVALID_ALABEL",
            Error::UalabelMismatch => "IDN2_UALABEL_MISMATCH",
            Error::InvalidFlags => "IDN2_INVALID_FLAGS",
            Error::NotNfc => "IDN2_NOT_NFC",
            Error::TwoHyphen => "IDN2_2HYPHEN",
            Error::HyphenStartEnd => "IDN2_HYPHEN_STARTEND",
            Error::LeadingCombining => "IDN2_LEADING_COMBINING",
            Error::Disallowed => "IDN2_DISALLOWED",
            Error::ContextJ => "IDN2_CONTEXTJ",
            Error::ContextJNoRule => "IDN2_CONTEXTJ_NO_RULE",
            Error::ContextO => "IDN2_CONTEXTO",
            Error::ContextONoRule => "IDN2_CONTEXTO_NO_RULE",
            Error::Unassigned => "IDN2_UNASSIGNED",
            Error::Bidi => "IDN2_BIDI",
            Error::DotInLabel => "IDN2_DOT_IN_LABEL",
            Error::InvalidTransitional => "IDN2_INVALID_TRANSITIONAL",
            Error::InvalidNontransitional => "IDN2_INVALID_NONTRANSITIONAL",
            Error::AlabelRoundtripFailed => "IDN2_ALABEL_ROUNDTRIP_FAILED",
        }
    }
}

/// `IDN2_LABEL_MAX_LENGTH` / `IDN2_DOMAIN_MAX_LENGTH` (idn2.h.in:162,173).
pub const LABEL_MAX_LENGTH: usize = 63;
pub const DOMAIN_MAX_LENGTH: usize = 255;

// ---------------------------------------------------------------------------
// Punycode (RFC 3492), transcribed from lib/punycode.c
// ---------------------------------------------------------------------------

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    let mut delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0u32;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

fn encode_digit(d: u32) -> char {
    debug_assert!(d < BASE);
    if d < 26 {
        (b'a' + d as u8) as char
    } else {
        (b'0' + (d - 26) as u8) as char
    }
}

fn decode_digit(c: char) -> Option<u32> {
    match c {
        'a'..='z' => Some(c as u32 - 'a' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        '0'..='9' => Some(c as u32 - '0' as u32 + 26),
        _ => None,
    }
}

// RFC 3492 variable names (n, delta, bias, k, t, q, m, i, w) are kept to
// mirror the reference algorithm 1:1.
#[allow(clippy::many_single_char_names)]
fn punycode_encode(codepoints: &[char]) -> Result<String, Error> {
    let mut output = String::new();
    let mut n = INITIAL_N;
    let mut delta = 0u32;
    let mut bias = INITIAL_BIAS;
    let mut basic = 0u32;
    for &c in codepoints {
        if (c as u32) < 0x80 {
            output.push(c);
            basic += 1;
        }
    }
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    while handled < codepoints.len() as u32 {
        let mut m = u32::MAX;
        for &c in codepoints {
            let cp = c as u32;
            if cp >= n && cp < m {
                m = cp;
            }
        }
        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul(handled + 1)
                    .ok_or(Error::PunycodeOverflow)?,
            )
            .ok_or(Error::PunycodeOverflow)?;
        n = m;
        for &c in codepoints {
            let cp = c as u32;
            if cp < n {
                delta = delta.checked_add(1).ok_or(Error::PunycodeOverflow)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + ((q - t) % (BASE - t))));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Ok(output)
}

// RFC 3492 variable names (n, delta, bias, k, t, q, m, i, w) are kept to
// mirror the reference algorithm 1:1.
#[allow(clippy::many_single_char_names)]
fn punycode_decode(input: &str) -> Result<String, Error> {
    let mut output: Vec<char> = Vec::new();
    let mut n = INITIAL_N;
    let mut i = 0u32;
    let mut bias = INITIAL_BIAS;
    let bytes: Vec<char> = input.chars().collect();
    let delim_pos = input.rfind('-');
    let basic_end = match delim_pos {
        Some(p) => p,
        None => 0,
    };
    for &c in &bytes[..basic_end] {
        if (c as u32) >= 0x80 {
            return Err(Error::PunycodeBadInput);
        }
        output.push(c);
    }
    let mut inx = basic_end;
    if delim_pos.is_some() {
        inx += 1;
    }
    while inx < bytes.len() {
        let oldi = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            if inx >= bytes.len() {
                return Err(Error::PunycodeBadInput);
            }
            let digit = decode_digit(bytes[inx]).ok_or(Error::PunycodeBadInput)?;
            inx += 1;
            i = i
                .checked_add(digit.checked_mul(w).ok_or(Error::PunycodeOverflow)?)
                .ok_or(Error::PunycodeOverflow)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t).ok_or(Error::PunycodeOverflow)?;
            k += BASE;
        }
        let out_len = output.len() as u32 + 1;
        bias = adapt(i - oldi, out_len, oldi == 0);
        if i / out_len > (char::MAX as u32 - n) {
            return Err(Error::PunycodeOverflow);
        }
        n += i / out_len;
        i %= out_len;
        let cp = char::from_u32(n).ok_or(Error::PunycodeBadInput)?;
        output.insert(i as usize, cp);
        i += 1;
    }
    Ok(output.into_iter().collect())
}

// ---------------------------------------------------------------------------
// `set_default_flags` (lookup.c:104) — exact flag-conflict rules.
// ---------------------------------------------------------------------------

fn set_default_flags(flags: i32) -> Result<i32, Error> {
    if flags & flags::TRANSITIONAL != 0 && flags & flags::NONTRANSITIONAL != 0 {
        return Err(Error::InvalidFlags);
    }
    if flags & (flags::TRANSITIONAL | flags::NONTRANSITIONAL) != 0 && flags & flags::NO_TR46 != 0 {
        return Err(Error::InvalidFlags);
    }
    if flags & flags::ALABEL_ROUNDTRIP != 0 && flags & flags::NO_ALABEL_ROUNDTRIP != 0 {
        return Err(Error::InvalidFlags);
    }
    let mut flags = flags;
    if flags & (flags::NO_TR46 | flags::TRANSITIONAL) == 0 {
        flags |= flags::NONTRANSITIONAL;
    }
    Ok(flags)
}

// ---------------------------------------------------------------------------
// UTS #46 mapping table accessors (tr46map.c: `get_idna_map`, `map_is`,
// `get_map_data`).
// ---------------------------------------------------------------------------

/// `get_idna_map` (tr46map.c): binary search for the (cp1, range) row
/// containing `cp`.  Absent codepoints yield `None` — the C zeroes the map
/// (`flag_index = 0`, i.e. `idna_flags[0]` = DISALLOWED_STD3_VALID), which
/// the call sites reproduce via `map_is_none` semantics.
fn get_idna_map(cp: u32) -> Option<libidn2_tr46map::IdnaMap> {
    let table: &[(u32, u32, u32, usize, u32)] = if cp <= 0xFF {
        IDNA_MAP_8
    } else if cp <= 0xFFFF {
        IDNA_MAP_16
    } else {
        IDNA_MAP_24
    };
    let idx = table.partition_point(|r| r.0 <= cp);
    if idx == 0 {
        return None;
    }
    let r = &table[idx - 1];
    if cp <= r.0 + r.1 {
        Some(libidn2_tr46map::IdnaMap {
            cp1: r.0,
            range: r.1,
            flag_index: r.2,
            offset: r.3,
            nmappings: r.4,
        })
    } else {
        None
    }
}

/// `map_is` (tr46map.c): the flag bits of the map's flag index.  `None`
/// (absent codepoint) behaves like the C's zeroed map: flag index 0 =
/// `DISALLOWED_STD3_VALID`.
fn map_is(map: &Option<libidn2_tr46map::IdnaMap>, flag: Flag) -> bool {
    let idx = match map {
        Some(m) => m.flag_index as usize,
        None => 0,
    };
    (IDNA_FLAGS[idx] & flag as u32) == flag as u32
}

/// `get_map_data` (tr46map.c): decode the LEB128-style mapping payload.
fn map_data(map: &libidn2_tr46map::IdnaMap) -> Vec<u32> {
    let mut out = Vec::with_capacity(map.nmappings as usize);
    let mut i = map.offset;
    for _ in 0..map.nmappings {
        let mut cp: u32 = 0;
        loop {
            let b = MAPDATA[i];
            i += 1;
            cp = (cp << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push(cp);
    }
    out
}

// ---------------------------------------------------------------------------
// Unicode data accessors (via icu_properties; the same audited data family
// as the `idna` engine).
// ---------------------------------------------------------------------------

fn bidi_class(cp: char) -> BidiClass {
    CodePointMapData::<BidiClass>::new().get(cp)
}

fn general_category(cp: char) -> GeneralCategory {
    CodePointMapData::<GeneralCategory>::new().get(cp)
}

fn joining_type(cp: char) -> JoiningType {
    CodePointMapData::<JoiningType>::new().get(cp)
}

fn script(cp: char) -> Script {
    CodePointMapData::<Script>::new().get(cp)
}

fn combining_class(cp: char) -> u8 {
    CodePointMapData::<CanonicalCombiningClass>::new().get(cp).0
}

/// `uc_is_general_category(label[0], UC_CATEGORY_M)` (idna.c
/// TEST_LEADING_COMBINING): any combining mark (Mn/Mc/Me).
fn is_combining_mark(cp: char) -> bool {
    matches!(
        general_category(cp),
        GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
    )
}

// ---------------------------------------------------------------------------
// The IDNA2008 label tests (`_idn2_label_test`, idna.c; the bidi check,
// bidi.c; the context rules, context.c).
// ---------------------------------------------------------------------------

/// `TEST_*` flags (idna.h:37).
const TEST_NFC: u32 = 0x0001;
const TEST_2HYPHEN: u32 = 0x0002;
const TEST_HYPHEN_STARTEND: u32 = 0x0004;
const TEST_LEADING_COMBINING: u32 = 0x0008;
const TEST_DISALLOWED: u32 = 0x0010;
const TEST_CONTEXTJ: u32 = 0x0020;
const TEST_CONTEXTJ_RULE: u32 = 0x0040;
const TEST_CONTEXTO: u32 = 0x0080;
const TEST_CONTEXTO_WITH_RULE: u32 = 0x0100;
const TEST_CONTEXTO_RULE: u32 = 0x0200;
const TEST_UNASSIGNED: u32 = 0x0400;
const TEST_BIDI: u32 = 0x0800;
const TEST_TRANSITIONAL: u32 = 0x1000;
const TEST_NONTRANSITIONAL: u32 = 0x2000;
const TEST_ALLOW_STD3_DISALLOWED: u32 = 0x4000;

/// `TR46_TRANSITIONAL_CHECK` / `TR46_NONTRANSITIONAL_CHECK` (lookup.c:253).
const TR46_TRANSITIONAL_CHECK: u32 =
    TEST_NFC | TEST_2HYPHEN | TEST_HYPHEN_STARTEND | TEST_LEADING_COMBINING | TEST_TRANSITIONAL;
const TR46_NONTRANSITIONAL_CHECK: u32 =
    TEST_NFC | TEST_2HYPHEN | TEST_HYPHEN_STARTEND | TEST_LEADING_COMBINING | TEST_NONTRANSITIONAL;

/// `_idn2_label_test` (idna.c:133): the test suite in C order.  The tests
/// run over the *mapped* label for the TR46 path and the *raw* (NFC'd) label
/// for the NO_TR46 path, exactly like the C.
fn label_test(label: &[char], what: u32) -> Result<(), Error> {
    let llen = label.len();
    if what & TEST_NFC != 0 {
        let nfc: Vec<char> = label.iter().collect::<String>().nfc().collect();
        if nfc != label {
            return Err(Error::NotNfc);
        }
    }
    if what & TEST_2HYPHEN != 0 {
        if llen >= 4 && label[2] == '-' && label[3] == '-' {
            return Err(Error::TwoHyphen);
        }
    }
    if what & TEST_HYPHEN_STARTEND != 0 {
        if llen > 0 && (label[0] == '-' || label[llen - 1] == '-') {
            return Err(Error::HyphenStartEnd);
        }
    }
    if what & TEST_LEADING_COMBINING != 0 {
        if llen > 0 && is_combining_mark(label[0]) {
            return Err(Error::LeadingCombining);
        }
    }
    if what & TEST_DISALLOWED != 0 {
        for &c in label {
            if property(c as u32) == IdnaState::Disallowed {
                if what & (TEST_TRANSITIONAL | TEST_NONTRANSITIONAL) != 0
                    && what & TEST_ALLOW_STD3_DISALLOWED != 0
                {
                    let map = get_idna_map(c as u32);
                    if map_is(&map, Flag::DisallowedStd3Valid)
                        || map_is(&map, Flag::DisallowedStd3Mapped)
                    {
                        continue;
                    }
                }
                return Err(Error::Disallowed);
            }
        }
    }
    if what & TEST_CONTEXTJ != 0 {
        for &c in label {
            if property(c as u32) == IdnaState::ContextJ {
                return Err(Error::ContextJ);
            }
        }
    }
    if what & TEST_CONTEXTJ_RULE != 0 {
        for i in 0..llen {
            contextj_rule(label, i)?;
        }
    }
    if what & TEST_CONTEXTO != 0 {
        for &c in label {
            if property(c as u32) == IdnaState::ContextO {
                return Err(Error::ContextO);
            }
        }
    }
    if what & TEST_CONTEXTO_WITH_RULE != 0 {
        for &c in label {
            if property(c as u32) == IdnaState::ContextO && !contexto_with_rule(c) {
                return Err(Error::ContextONoRule);
            }
        }
    }
    if what & TEST_CONTEXTO_RULE != 0 {
        for i in 0..llen {
            contexto_rule(label, i)?;
        }
    }
    if what & TEST_UNASSIGNED != 0 {
        for &c in label {
            if property(c as u32) == IdnaState::Unassigned {
                return Err(Error::Unassigned);
            }
        }
    }
    if what & TEST_BIDI != 0 {
        bidi_check(label)?;
    }
    if what & (TEST_TRANSITIONAL | TEST_NONTRANSITIONAL) != 0 {
        let transitional = what & TEST_TRANSITIONAL != 0;
        for &c in label {
            if c == '\u{002E}' {
                return Err(Error::DotInLabel);
            }
            let map = get_idna_map(c as u32);
            if map_is(&map, Flag::Valid) || (!transitional && map_is(&map, Flag::Deviation)) {
                continue;
            }
            if what & TEST_ALLOW_STD3_DISALLOWED != 0
                && (map_is(&map, Flag::DisallowedStd3Valid)
                    || map_is(&map, Flag::DisallowedStd3Mapped))
            {
                continue;
            }
            return Err(if transitional {
                Error::InvalidTransitional
            } else {
                Error::InvalidNontransitional
            });
        }
    }
    Ok(())
}

/// `_idn2_contextj_rule` (context.c:37): ZWNJ/ZWJ joining rules.
fn contextj_rule(label: &[char], pos: usize) -> Result<(), Error> {
    if label.is_empty() {
        return Ok(());
    }
    let cp = label[pos];
    if property(cp as u32) != IdnaState::ContextJ {
        return Ok(());
    }
    match cp {
        '\u{200C}' => {
            // ZERO WIDTH NON-JOINER
            if pos > 0 && combining_class(label[pos - 1]) == 9 {
                return Ok(()); // virama before
            }
            if pos == 0 || pos == label.len() - 1 {
                return Err(Error::ContextJ);
            }
            // Search backwards for joining type L or D (context.c:67).
            let mut tmp = pos - 1;
            loop {
                let jt = joining_type(label[tmp]);
                if jt == JoiningType::LeftJoining || jt == JoiningType::DualJoining {
                    break;
                }
                if tmp == 0 {
                    return Err(Error::ContextJ);
                }
                if jt == JoiningType::Transparent {
                    tmp -= 1;
                    continue;
                }
                return Err(Error::ContextJ);
            }
            // Search forward for joining type R or D (context.c:81).
            let mut tmp = pos + 1;
            while tmp < label.len() {
                let jt = joining_type(label[tmp]);
                if jt == JoiningType::RightJoining || jt == JoiningType::DualJoining {
                    break;
                }
                if tmp == label.len() - 1 {
                    return Err(Error::ContextJ);
                }
                if jt == JoiningType::Transparent {
                    tmp += 1;
                    continue;
                }
                return Err(Error::ContextJ);
            }
            Ok(())
        }
        '\u{200D}' => {
            // ZERO WIDTH JOINER
            if pos > 0 && combining_class(label[pos - 1]) == 9 {
                return Ok(()); // virama before
            }
            Err(Error::ContextJ)
        }
        _ => Err(Error::ContextJNoRule),
    }
}

/// `_idn2_contexto_with_rule` (context.c:229): ContextO code points that
/// have a rule; the others fail `TEST_CONTEXTO_WITH_RULE`.
fn contexto_with_rule(cp: char) -> bool {
    matches!(
        cp as u32,
        0x00B7 | 0x0375 | 0x05F3 | 0x05F4 | 0x0660..=0x0669 | 0x06F0..=0x06F9 | 0x30FB
    )
}

/// `_idn2_contexto_rule` (context.c:127).
fn contexto_rule(label: &[char], pos: usize) -> Result<(), Error> {
    let cp = label[pos];
    if property(cp as u32) != IdnaState::ContextO {
        return Ok(());
    }
    match cp as u32 {
        0x00B7 => {
            // MIDDLE DOT: between two 'l'.
            if label.len() < 3 {
                return Err(Error::ContextO);
            }
            if pos == 0 || pos == label.len() - 1 {
                return Err(Error::ContextO);
            }
            if label[pos - 1] == 'l' && label[pos + 1] == 'l' {
                return Ok(());
            }
            Err(Error::ContextO)
        }
        0x0375 => {
            // GREEK LOWER NUMERAL SIGN (KERAIA): next char is Greek.
            if pos == label.len() - 1 {
                return Err(Error::ContextO);
            }
            if script(label[pos + 1]) == Script::Greek {
                return Ok(());
            }
            Err(Error::ContextO)
        }
        0x05F3 | 0x05F4 => {
            // HEBREW PUNCTUATION GERESH/GERSHAYIM: previous char is Hebrew.
            if pos == 0 {
                return Err(Error::ContextO);
            }
            if script(label[pos - 1]) == Script::Hebrew {
                return Ok(());
            }
            Err(Error::ContextO)
        }
        0x0660..=0x0669 => {
            // ARABIC-INDIC DIGITS: no EXTENDED ARABIC-INDIC DIGITS in the label.
            if label
                .iter()
                .any(|&c| (0x06F0..=0x06F9).contains(&(c as u32)))
            {
                return Err(Error::ContextO);
            }
            Ok(())
        }
        0x06F0..=0x06F9 => {
            // EXTENDED ARABIC-INDIC DIGITS: no ARABIC-INDIC DIGITS in the label.
            if label
                .iter()
                .any(|&c| (0x0660..=0x0669).contains(&(c as u32)))
            {
                return Err(Error::ContextO);
            }
            Ok(())
        }
        0x30FB => {
            // KATAKANA MIDDLE DOT: the label contains Hiragana/Katakana/Han.
            if label
                .iter()
                .any(|&c| matches!(script(c), Script::Hiragana | Script::Katakana | Script::Han))
            {
                return Ok(());
            }
            Err(Error::ContextO)
        }
        _ => Err(Error::ContextONoRule),
    }
}

/// `_idn2_bidi` (bidi.c:56): the RFC 5893 checks as transcribed.
fn bidi_check(label: &[char]) -> Result<(), Error> {
    let is_bidi = label.iter().any(|&c| {
        matches!(
            bidi_class(c),
            BidiClass::RightToLeft | BidiClass::ArabicLetter | BidiClass::ArabicNumber
        )
    });
    if !is_bidi {
        return Ok(());
    }
    match bidi_class(label[0]) {
        BidiClass::LeftToRight => {
            let mut endok = true;
            for &c in &label[1..] {
                match bidi_class(c) {
                    BidiClass::LeftToRight
                    | BidiClass::EuropeanNumber
                    | BidiClass::NonspacingMark => endok = true,
                    BidiClass::EuropeanSeparator
                    | BidiClass::CommonSeparator
                    | BidiClass::EuropeanTerminator
                    | BidiClass::OtherNeutral
                    | BidiClass::BoundaryNeutral => endok = false,
                    _ => return Err(Error::Bidi),
                }
            }
            if endok {
                Ok(())
            } else {
                Err(Error::Bidi)
            }
        }
        BidiClass::RightToLeft | BidiClass::ArabicLetter => {
            let mut endok = true;
            for &c in &label[1..] {
                match bidi_class(c) {
                    BidiClass::RightToLeft
                    | BidiClass::ArabicLetter
                    | BidiClass::EuropeanNumber
                    | BidiClass::ArabicNumber
                    | BidiClass::NonspacingMark => endok = true,
                    BidiClass::EuropeanSeparator
                    | BidiClass::CommonSeparator
                    | BidiClass::EuropeanTerminator
                    | BidiClass::OtherNeutral
                    | BidiClass::BoundaryNeutral => endok = false,
                    _ => return Err(Error::Bidi),
                }
            }
            if endok {
                Ok(())
            } else {
                Err(Error::Bidi)
            }
        }
        _ => Err(Error::Bidi),
    }
}

// ---------------------------------------------------------------------------
// `_tr46` (lookup.c:258): the UTS #46 mapping + NFC + per-label checks.
// ---------------------------------------------------------------------------

/// `_tr46` (lookup.c): map every code point through the TR46 table (an
/// immediate `IDN2_DISALLOWED` for map-flagged disallowed code points; the
/// STD3-disallowed classes are dropped under STD3 rules and kept/mapped
/// otherwise), NFC-normalize, then run the per-label TR46 checks (with the
/// A-label decode check for "xn--" labels).  Returns the NFC'd mapped domain
/// or the first failing label's error (the C keeps the last failure).
fn tr46(input: &str, flags: i32) -> Result<String, Error> {
    let transitional = flags & flags::TRANSITIONAL != 0;
    let std3 = flags & flags::USE_STD3_ASCII_RULES != 0;
    let chars: Vec<char> = input.chars().collect();

    // First pass: early length accounting and the immediate DISALLOWED exit.
    let mut len2 = 0usize;
    for &c in &chars {
        let map = get_idna_map(c as u32);
        if map_is(&map, Flag::Disallowed) {
            return Err(Error::Disallowed);
        }
        if map_is(&map, Flag::Mapped) {
            len2 += map.as_ref().map_or(0, |m| m.nmappings as usize);
        } else if map_is(&map, Flag::Valid) {
            len2 += 1;
        } else if map_is(&map, Flag::Ignored) {
            continue;
        } else if map_is(&map, Flag::Deviation) {
            len2 += if transitional {
                map.as_ref().map_or(0, |m| m.nmappings as usize)
            } else {
                1
            };
        } else if !std3 {
            if map_is(&map, Flag::DisallowedStd3Valid) {
                len2 += 1;
            } else if map_is(&map, Flag::DisallowedStd3Mapped) {
                len2 += map.as_ref().map_or(0, |m| m.nmappings as usize);
            }
        }
        // under STD3 rules the std3-disallowed classes are dropped entirely
    }
    if len2 >= DOMAIN_MAX_LENGTH {
        return Err(Error::TooBigDomain);
    }

    // Second pass: build the mapped sequence.
    let mut tmp: Vec<char> = Vec::with_capacity(len2);
    for &c in &chars {
        let map = get_idna_map(c as u32);
        if map_is(&map, Flag::Mapped) {
            for m in map_data(map.as_ref().expect("mapped map present")) {
                tmp.push(char::from_u32(m).expect("valid mapping"));
            }
        } else if map_is(&map, Flag::Valid) {
            tmp.push(c);
        } else if map_is(&map, Flag::Ignored) {
            continue;
        } else if map_is(&map, Flag::Deviation) {
            if transitional {
                for m in map_data(map.as_ref().expect("deviation map present")) {
                    tmp.push(char::from_u32(m).expect("valid mapping"));
                }
            } else {
                tmp.push(c);
            }
        } else if !std3 {
            if map_is(&map, Flag::DisallowedStd3Valid) {
                tmp.push(c);
            } else if map_is(&map, Flag::DisallowedStd3Mapped) {
                for m in map_data(map.as_ref().expect("std3 map present")) {
                    tmp.push(char::from_u32(m).expect("valid mapping"));
                }
            }
        }
        // Flag::Disallowed never survives the first pass.
    }

    // Normalize to NFC.
    let nfc: String = tmp.iter().collect::<String>().nfc().collect();
    let domain: Vec<char> = nfc.chars().collect();

    // Split into labels and check.
    let mut err = Ok(());
    let mut e = 0usize;
    while e < domain.len() {
        let s = e;
        while e < domain.len() && domain[e] != '.' {
            e += 1;
        }
        let label: &[char] = &domain[s..e];
        if label.len() >= 4
            && label[0] == 'x'
            && label[1] == 'n'
            && label[2] == '-'
            && label[3] == '-'
        {
            // Decode the punycode and check the result nontransitionally.
            let ace: String = label[4..].iter().collect();
            match punycode_decode(&ace) {
                Ok(name) => {
                    let name_chars: Vec<char> = name.chars().collect();
                    let mut test_flags = TR46_NONTRANSITIONAL_CHECK;
                    if !std3 {
                        test_flags |= TEST_ALLOW_STD3_DISALLOWED;
                    }
                    if let Err(rc) = label_test(&name_chars, test_flags) {
                        err = Err(rc);
                    }
                }
                Err(rc) => err = Err(rc),
            }
        } else {
            let mut test_flags = if transitional {
                TR46_TRANSITIONAL_CHECK
            } else {
                TR46_NONTRANSITIONAL_CHECK
            };
            if !std3 {
                test_flags |= TEST_ALLOW_STD3_DISALLOWED;
            }
            if let Err(rc) = label_test(label, test_flags) {
                err = Err(rc);
            }
        }
        if e < domain.len() {
            e += 1; // consume the '.'
        }
    }
    err?;
    Ok(nfc)
}

// ---------------------------------------------------------------------------
// `label` (lookup.c:130): per-label ToASCII.
// ---------------------------------------------------------------------------

/// `_idn2_ascii_p` (idna.c:124): all bytes < 0x80.
fn ascii_p(s: &str) -> bool {
    s.is_ascii()
}

/// `label` (lookup.c): one label's ToASCII.  ASCII labels are copied
/// verbatim (after the A-label roundtrip check when they start with the
/// case-sensitive "xn--" prefix); non-ASCII labels are NFC'd (unless
/// `IDN2_NFC_INPUT`), tested with the nontransitional set (skipped for
/// `IDN2_TRANSITIONAL`), and punycoded.
fn label(src: &str, flags: i32) -> Result<String, Error> {
    if ascii_p(src) {
        if flags & flags::NO_ALABEL_ROUNDTRIP == 0
            && src.len() >= 4
            && src.as_bytes()[0] == b'x'
            && src.as_bytes()[1] == b'n'
            && src.as_bytes()[2] == b'-'
            && src.as_bytes()[3] == b'-'
        {
            // A-label: decode and re-test the U-label.
            let decoded = punycode_decode(&src[4..])?;
            let decoded_chars: Vec<char> = decoded.chars().collect();
            let mut test_flags = TEST_NFC
                | TEST_2HYPHEN
                | TEST_LEADING_COMBINING
                | TEST_DISALLOWED
                | TEST_CONTEXTJ_RULE
                | TEST_CONTEXTO_WITH_RULE
                | TEST_UNASSIGNED
                | TEST_BIDI
                | TEST_NONTRANSITIONAL;
            if flags & flags::USE_STD3_ASCII_RULES == 0 {
                test_flags |= TEST_ALLOW_STD3_DISALLOWED;
            }
            if !(flags & flags::TRANSITIONAL != 0) {
                // The C's test block is skipped for transitional processing.
                label_test(&decoded_chars, test_flags)?;
            }
            // Re-encode and require an exact round trip.
            let ace = punycode_encode(&decoded_chars)?;
            if ace.len() > LABEL_MAX_LENGTH - 4 {
                return Err(Error::PunycodeBigOutput);
            }
            let rebuilt = format!("xn--{ace}");
            if rebuilt != src {
                return Err(Error::AlabelRoundtripFailed);
            }
            return Ok(rebuilt);
        }
        if src.len() > LABEL_MAX_LENGTH {
            return Err(Error::TooBigLabel);
        }
        return Ok(src.to_string());
    }

    // Non-ASCII: NFC.  The C's `_idn2_u8_to_u32_nfc(src, srclen, &p, &plen,
    // flags & IDN2_NFC_INPUT)` normalizes whenever the input is not already
    // NFC (the NFC_INPUT bit only skips the `_isNFC` quick check), so the
    // label is always NFC'd before the tests.
    let p: Vec<char> = src.nfc().collect();

    if flags & flags::TRANSITIONAL == 0 {
        let mut test_flags = TEST_NFC
            | TEST_2HYPHEN
            | TEST_LEADING_COMBINING
            | TEST_DISALLOWED
            | TEST_CONTEXTJ_RULE
            | TEST_CONTEXTO_WITH_RULE
            | TEST_UNASSIGNED
            | TEST_BIDI
            | TEST_NONTRANSITIONAL;
        if flags & flags::USE_STD3_ASCII_RULES == 0 {
            test_flags |= TEST_ALLOW_STD3_DISALLOWED;
        }
        label_test(&p, test_flags)?;
    }

    let ace = punycode_encode(&p)?;
    if ace.len() > LABEL_MAX_LENGTH - 4 {
        return Err(Error::PunycodeBigOutput);
    }
    Ok(format!("xn--{ace}"))
}

// ---------------------------------------------------------------------------
// `idn2_lookup_u8` (lookup.c): the assembled ToASCII pipeline.
// ---------------------------------------------------------------------------

/// `idn2_lookup_u8`: `set_default_flags` → `_tr46` (unless `IDN2_NO_TR46`) →
/// per-label `label()` → concatenation with the 255-byte domain accounting
/// (lookup.c:449-468).
fn lookup_u8(input: &str, flags: i32) -> Result<String, Error> {
    let flags = set_default_flags(flags)?;
    let src = if flags & flags::NO_TR46 == 0 {
        tr46(input, flags)?
    } else {
        input.to_string()
    };

    let bytes = src.as_bytes();
    let mut lookupname = String::new();
    let mut lookupnamelen = 0usize;
    let mut i = 0usize;
    loop {
        let start = i;
        while i < bytes.len() && bytes[i] != b'.' {
            i += 1;
        }
        let tmp = label(&src[start..i], flags)?;
        let tmplen = tmp.len();
        let is_last = i >= bytes.len();
        let budget = DOMAIN_MAX_LENGTH - (if tmplen == 0 && is_last { 1 } else { 2 });
        if lookupnamelen + tmplen > budget {
            return Err(Error::TooBigDomain);
        }
        lookupname.push_str(&tmp);
        lookupnamelen += tmplen;
        if i < bytes.len() {
            if lookupnamelen + 1 > DOMAIN_MAX_LENGTH {
                return Err(Error::TooBigDomain);
            }
            lookupname.push('.');
            lookupnamelen += 1;
            i += 1;
        } else {
            break;
        }
    }
    Ok(lookupname)
}

// ---------------------------------------------------------------------------
// The locale layer (`idn2_lookup_ul` / `idn2_to_unicode_8zlz`).
// ---------------------------------------------------------------------------

/// Resolve the locale codeset from the environment the way glibc's
/// `nl_langinfo(CODESET)` resolves it after `setlocale(LC_ALL, "")` for the
/// locales the courts pin: `LC_ALL` > `LC_CTYPE` > `LANG`; `C`/`POSIX`
/// (or a `.`-suffixed codeset) names the charset.  Unknown locales are a
/// documented best-effort UTF-8.
#[must_use]
pub fn locale_codeset() -> String {
    let loc = std::env::var("LC_ALL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("LC_CTYPE").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("LANG").ok().filter(|s| !s.is_empty()));
    match loc {
        None => "ANSI_X3.4-1968".to_string(),
        Some(l) => {
            let lower = l.to_ascii_lowercase();
            if lower.contains("utf-8") || lower.contains("utf8") {
                "UTF-8".to_string()
            } else if lower.contains("iso-8859-1")
                || lower.contains("iso8859-1")
                || lower.contains("8859-1")
            {
                "ISO-8859-1".to_string()
            } else if l == "C" || l == "POSIX" || l.starts_with("C.") || l.starts_with("POSIX.") {
                "ANSI_X3.4-1968".to_string()
            } else {
                // Best-effort for unlisted locales (the courts pin C.UTF-8,
                // C and en_US.ISO-8859-1).
                "UTF-8".to_string()
            }
        }
    }
}

/// `u8_strconv_from_encoding(src, codeset, iconveh_error)`: convert the
/// locale-encoded input to UTF-8; `IDN2_ICONV_FAIL` on an invalid byte
/// sequence (the C's NULL + errno path).
fn from_locale(input: &[u8]) -> Result<Vec<u8>, Error> {
    match locale_codeset().as_str() {
        "UTF-8" => Ok(input.to_vec()),
        "ANSI_X3.4-1968" => {
            if input.iter().any(|&b| b >= 0x80) {
                Err(Error::IconvFail)
            } else {
                Ok(input.to_vec())
            }
        }
        "ISO-8859-1" => {
            let mut out = Vec::with_capacity(input.len());
            for &b in input {
                if b < 0x80 {
                    out.push(b);
                } else {
                    out.push(0xC0 | (b >> 6));
                    out.push(0x80 | (b & 0x3F));
                }
            }
            Ok(out)
        }
        _ => Err(Error::IconvFail),
    }
}

/// `u8_strconv_to_encoding(input, codeset, iconveh_error)`: convert the
/// UTF-8 output to the locale codeset; `IDN2_ENCODING_ERROR` when a code
/// point has no representation.
fn to_locale(input: &str) -> Result<Vec<u8>, Error> {
    match locale_codeset().as_str() {
        "UTF-8" => Ok(input.as_bytes().to_vec()),
        "ANSI_X3.4-1968" => {
            if input.is_ascii() {
                Ok(input.as_bytes().to_vec())
            } else {
                Err(Error::EncodingError)
            }
        }
        "ISO-8859-1" => {
            let mut out = Vec::with_capacity(input.len());
            for c in input.chars() {
                if c as u32 <= 0xFF {
                    out.push(c as u8);
                } else {
                    return Err(Error::EncodingError);
                }
            }
            Ok(out)
        }
        _ => Err(Error::EncodingError),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// `idn2_to_ascii_8z`-style conversion for a UTF-8 `&str` input (no locale
/// conversion) — the shared IDNA pipeline.
fn to_ascii_utf8(input: &str, flags: i32) -> Result<String, Error> {
    lookup_u8(input, flags)
}

/// `idn2_to_ascii_lz` (dighost.c `idn_input`): convert a domain name in the
/// locale encoding to its ASCII (A-label) form.  The input is converted from
/// the locale codeset to UTF-8 (`IDN2_ICONV_FAIL` on failure), then
/// `idn2_lookup_u8` runs with `IDN2_NFC_INPUT` forced (lookup.c
/// `idn2_lookup_ul`).
pub fn to_ascii_lz_u8(input: &[u8], flags: i32) -> Result<Vec<u8>, Error> {
    let utf8 = from_locale(input)?;
    let s = String::from_utf8(utf8).map_err(|_| Error::IconvFail)?;
    let ascii = to_ascii_utf8(&s, flags | flags::NFC_INPUT)?;
    Ok(ascii.into_bytes())
}

/// `idn2_to_ascii_lz` for the dig-facing `&str` path (a UTF-8 by
/// construction input; under a non-UTF-8 locale the locale conversion still
/// applies to the bytes, matching the C).
pub fn to_ascii_lz(input: &str, flags: i32) -> Result<String, Error> {
    let bytes = to_ascii_lz_u8(input.as_bytes(), flags)?;
    // The output of ToASCII is always ASCII.
    String::from_utf8(bytes).map_err(|_| Error::EncodingError)
}

/// `idn2_to_unicode_8z8z`-style decode (decode.c): decode "xn--" A-labels
/// (case-insensitive) to U-labels; other labels are copied as-is.
fn to_unicode_8z8z(input: &str) -> Result<String, Error> {
    let mut out = String::new();
    let mut domain_len = 0usize;
    for (i, label) in input.split('.').enumerate() {
        if i > 0 {
            out.push('.');
            domain_len += 1;
        }
        if label.len() >= 4
            && (label.as_bytes()[0] == b'x' || label.as_bytes()[0] == b'X')
            && (label.as_bytes()[1] == b'n' || label.as_bytes()[1] == b'N')
            && label.as_bytes()[2] == b'-'
            && label.as_bytes()[3] == b'-'
        {
            let decoded = punycode_decode(&label[4..])?;
            if decoded.len() > LABEL_MAX_LENGTH {
                return Err(Error::TooBigLabel);
            }
            domain_len += decoded.len();
            if domain_len > DOMAIN_MAX_LENGTH {
                return Err(Error::TooBigDomain);
            }
            out.push_str(&decoded);
        } else {
            if label.len() > LABEL_MAX_LENGTH {
                return Err(Error::TooBigLabel);
            }
            domain_len += label.len();
            if domain_len > DOMAIN_MAX_LENGTH {
                return Err(Error::TooBigDomain);
            }
            out.push_str(label);
        }
    }
    Ok(out)
}

/// `idn2_to_unicode_8zlz` (decode.c:357): decode a UTF-8 input to U-labels,
/// then convert the output to the locale codeset (`IDN2_ENCODING_ERROR` on
/// failure).
pub fn to_unicode_8zlz_u8(input: &str, flags: i32) -> Result<Vec<u8>, Error> {
    let unicode = to_unicode_8z8z(input)?;
    let _ = flags;
    to_locale(&unicode)
}

/// `idn2_to_unicode_8zlz` for the dig-facing `&str` path.  The C's output is
/// in the locale codeset; under a UTF-8 locale it is a valid `String`, under
/// non-UTF-8 locales it may not be — the wrapper reports
/// `IDN2_ENCODING_ERROR` then (dig's idn_filter leaves the name unchanged).
pub fn to_unicode_8zlz(input: &str, flags: i32) -> Result<String, Error> {
    let bytes = to_unicode_8zlz_u8(input, flags)?;
    String::from_utf8(bytes).map_err(|_| Error::EncodingError)
}

/// `idn2_free` — the C API owns returned buffers; Rust returns owned
/// strings, so this is a no-op kept for API-shape fidelity.
pub fn free(_p: *mut u8) {}

// ---------------------------------------------------------------------------
// dig integration (dighost.c idn_input / idn_filter, exact semantics)
// ---------------------------------------------------------------------------

/// `idn_input` (dighost.c:4873): convert `src` (locale encoding) into an ACE
/// string for the query, with the NONTRANSITIONAL→TRANSITIONAL fallback and
/// the case-preservation quirk: `idn2_to_ascii_lz` lowercases, but dig keeps
/// the original spelling when the two differ only in case.
///
/// Locale sensitivity (archived): `idn2_to_ascii_lz` converts its input from
/// the process locale encoding (`u8_strconv_from_locale`); under the C/POSIX
/// locale (ASCII charset) any non-ASCII name fails conversion with an error
/// that is *not* IDN2_DISALLOWED, so the NONTRANSITIONAL→TRANSITIONAL retry
/// does not fire and dig passes the original name through unchanged — the
/// raw UTF-8 bytes go on the wire.  Court CLI-DIG-0003 pins a UTF-8 locale
/// for the conversion path; the C-locale pass-through is courted separately.
pub fn idn_input(src: &str) -> String {
    if locale_codeset() == "ANSI_X3.4-1968" && !src.is_ascii() {
        return src.to_string();
    }
    let ascii = to_ascii_lz(src, flags::NONTRANSITIONAL).or_else(|e| {
        if e == Error::Disallowed {
            to_ascii_lz(src, flags::TRANSITIONAL)
        } else {
            Err(e)
        }
    });
    match ascii {
        Ok(ace) if !src.eq_ignore_ascii_case(&ace) => ace,
        _ => src.to_string(),
    }
}

/// `idn_filter` (dighost.c:4822): convert a response name (bytes in the
/// buffer starting at `start`) to Unicode; leave it unchanged if conversion
/// fails or the result would not fit.  Returns `None` when the name is left
/// unchanged.
pub fn idn_filter(name: &str) -> Option<String> {
    let unicode = to_unicode_8zlz(name, flags::NONTRANSITIONAL).or_else(|e| {
        if e == Error::Disallowed {
            to_unicode_8zlz(name, flags::TRANSITIONAL)
        } else {
            Err(e)
        }
    });
    unicode.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle-probe vectors (oracle-libidn2-2.3.8, UTF-8 locale; see
    /// forensics/oracle/probes/probe-libidn2.c).
    #[test]
    fn nontransitional_oracle_vectors() {
        assert_eq!(
            to_ascii_lz("münchen.de", flags::NONTRANSITIONAL).unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert_eq!(
            to_ascii_lz("MÜNCHEN.de", flags::NONTRANSITIONAL).unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert_eq!(
            to_ascii_lz("EXAMPLE.COM", flags::NONTRANSITIONAL).unwrap(),
            "example.com"
        );
        assert_eq!(
            to_ascii_lz("Example.com", flags::NONTRANSITIONAL).unwrap(),
            "example.com"
        );
        assert_eq!(
            to_ascii_lz("faß.de", flags::NONTRANSITIONAL).unwrap(),
            "xn--fa-hia.de"
        );
        assert_eq!(
            to_ascii_lz("ς.gr", flags::NONTRANSITIONAL).unwrap(),
            "xn--3xa.gr"
        );
        assert_eq!(
            to_ascii_lz("xn--mnchen-3ya.de", flags::NONTRANSITIONAL).unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert_eq!(to_ascii_lz("a..b", flags::NONTRANSITIONAL).unwrap(), "a..b");
        assert_eq!(
            to_ascii_lz("_tcp.example.com", flags::NONTRANSITIONAL).unwrap(),
            "_tcp.example.com"
        );
        assert_eq!(
            to_ascii_lz("1.2.3.4", flags::NONTRANSITIONAL).unwrap(),
            "1.2.3.4"
        );
        assert_eq!(
            to_ascii_lz("a\u{00AD}b.com", flags::NONTRANSITIONAL).unwrap(),
            "ab.com"
        );
        assert_eq!(
            to_ascii_lz(".leading-dot", flags::NONTRANSITIONAL).unwrap(),
            ".leading-dot"
        );
        assert_eq!(
            to_ascii_lz("trailing-dot.", flags::NONTRANSITIONAL).unwrap(),
            "trailing-dot."
        );
        assert_eq!(
            to_ascii_lz("βόλος.gr", flags::NONTRANSITIONAL).unwrap(),
            "xn--nxasmm1c.gr"
        );
    }

    #[test]
    fn nontransitional_oracle_errors() {
        assert_eq!(
            to_ascii_lz("a\u{200C}b.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::ContextJ
        );
        assert_eq!(
            to_ascii_lz("a\u{200D}b.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::ContextJ
        );
        assert_eq!(
            to_ascii_lz("\u{1F600}.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::Disallowed
        );
        assert_eq!(
            to_ascii_lz("www.xn--0.0.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::PunycodeBadInput
        );
    }

    #[test]
    fn transitional_oracle_vectors() {
        assert_eq!(
            to_ascii_lz("faß.de", flags::TRANSITIONAL).unwrap(),
            "fass.de"
        );
        assert_eq!(
            to_ascii_lz("a\u{200C}b.com", flags::TRANSITIONAL).unwrap(),
            "ab.com"
        );
        assert_eq!(
            to_ascii_lz("a\u{200D}b.com", flags::TRANSITIONAL).unwrap(),
            "ab.com"
        );
        assert_eq!(
            to_ascii_lz("\u{1F600}.com", flags::TRANSITIONAL).unwrap(),
            "xn--e28h.com"
        );
        assert_eq!(
            to_ascii_lz("ς.gr", flags::TRANSITIONAL).unwrap(),
            "xn--4xa.gr"
        );
        assert_eq!(
            to_ascii_lz("ßß.com", flags::TRANSITIONAL).unwrap(),
            "ssss.com"
        );
    }

    #[test]
    fn to_unicode_oracle_vectors() {
        assert_eq!(
            to_unicode_8zlz("xn--mnchen-3ya.de", flags::NONTRANSITIONAL).unwrap(),
            "münchen.de"
        );
        assert_eq!(
            to_unicode_8zlz("XN--MNCHEN-3YA.DE", flags::NONTRANSITIONAL).unwrap(),
            "MüNCHEN.DE"
        );
        assert_eq!(
            to_unicode_8zlz("xn--fa-hia.de", flags::NONTRANSITIONAL).unwrap(),
            "faß.de"
        );
        assert_eq!(
            to_unicode_8zlz("xn--e28h.com", flags::NONTRANSITIONAL).unwrap(),
            "😀.com"
        );
        assert_eq!(
            to_unicode_8zlz("www.xn--0.0.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::PunycodeBadInput
        );
        assert_eq!(
            to_unicode_8zlz("a..b", flags::NONTRANSITIONAL).unwrap(),
            "a..b"
        );
        assert_eq!(
            to_unicode_8zlz(".leading-dot", flags::NONTRANSITIONAL).unwrap(),
            ".leading-dot"
        );
        assert_eq!(
            to_unicode_8zlz("trailing-dot.", flags::NONTRANSITIONAL).unwrap(),
            "trailing-dot."
        );
    }

    #[test]
    fn flag_conflicts_match_c() {
        assert_eq!(
            to_ascii_lz("x.com", flags::TRANSITIONAL | flags::NONTRANSITIONAL).unwrap_err(),
            Error::InvalidFlags
        );
        assert_eq!(
            to_ascii_lz("x.com", flags::NONTRANSITIONAL | flags::NO_TR46).unwrap_err(),
            Error::InvalidFlags
        );
        assert_eq!(
            to_ascii_lz("x.com", flags::TRANSITIONAL | flags::NO_TR46).unwrap_err(),
            Error::InvalidFlags
        );
        assert_eq!(
            to_ascii_lz(
                "x.com",
                flags::ALABEL_ROUNDTRIP | flags::NO_ALABEL_ROUNDTRIP
            )
            .unwrap_err(),
            Error::InvalidFlags
        );
    }

    #[test]
    fn no_tr46_pure_idna2008() {
        // NO_TR46 alone is the reachable pure-IDNA2008 path (any combination
        // with TRANSITIONAL/NONTRANSITIONAL is INVALID_FLAGS).
        assert_eq!(
            to_ascii_lz("faß.de", flags::NO_TR46).unwrap(),
            "xn--fa-hia.de"
        );
        assert_eq!(
            to_ascii_lz("EXAMPLE.COM", flags::NO_TR46).unwrap(),
            "EXAMPLE.COM"
        );
        assert_eq!(
            to_ascii_lz("MÜNCHEN.de", flags::NO_TR46).unwrap_err(),
            Error::Disallowed
        );
        assert_eq!(
            to_ascii_lz("a\u{00AD}b.com", flags::NO_TR46).unwrap_err(),
            Error::Disallowed
        );
        assert_eq!(
            to_ascii_lz("\u{1F600}.com", flags::NO_TR46).unwrap_err(),
            Error::Disallowed
        );
        assert_eq!(to_ascii_lz("ς.gr", flags::NO_TR46).unwrap(), "xn--3xa.gr");
    }

    #[test]
    fn label_test_corners() {
        // Leading combining mark (nonspacing) -> LEADING_COMBINING on both
        // paths (the oracle: rc=-303).
        assert_eq!(
            to_ascii_lz("\u{0301}a.com", flags::NO_TR46).unwrap_err(),
            Error::LeadingCombining
        );
        assert_eq!(
            to_ascii_lz("\u{0301}a.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::LeadingCombining
        );
        // The ContextO middle dot: the nt/no46 test sets only check that a
        // rule EXISTS (TEST_CONTEXTO_WITH_RULE), so a·b and l·l both pass.
        assert_eq!(
            to_ascii_lz("l\u{00B7}l.com", flags::NO_TR46).unwrap(),
            "xn--ll-0ea.com"
        );
        assert_eq!(
            to_ascii_lz("a\u{00B7}b.com", flags::NO_TR46).unwrap(),
            "xn--ab-0ea.com"
        );
        // Bidi violation (RFC 5893, as transcribed from bidi.c).
        assert_eq!(
            to_ascii_lz("a\u{05D0}b.com", flags::NO_TR46).unwrap_err(),
            Error::Bidi
        );
        assert_eq!(
            to_ascii_lz("a\u{05D0}b.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::Bidi
        );
        assert_eq!(
            to_ascii_lz("\u{05D0}\u{05D1}.com", flags::NO_TR46).unwrap(),
            "xn--4dbc.com"
        );
        // A valid ZWNJ between joining Arabic letters passes the rule; a ZWJ
        // without a virama fails it.
        assert_eq!(
            to_ascii_lz("\u{0628}\u{200C}\u{0628}.com", flags::NO_TR46).unwrap(),
            "xn--ngba799q.com"
        );
        assert_eq!(
            to_ascii_lz("\u{0628}\u{200D}\u{0628}.com", flags::NO_TR46).unwrap_err(),
            Error::ContextJ
        );
        // The 2-hyphen rule applies to non-ASCII labels on both paths.
        assert_eq!(
            to_ascii_lz("a\u{00DF}--b.com", flags::NO_TR46).unwrap_err(),
            Error::TwoHyphen
        );
        assert_eq!(
            to_ascii_lz("a\u{00DF}--b.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::TwoHyphen
        );
        // HYPHEN_STARTEND is in the TR46 check but NOT in the NO_TR46 set.
        assert_eq!(
            to_ascii_lz("-a\u{00E4}.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::HyphenStartEnd
        );
        assert_eq!(
            to_ascii_lz("-a\u{00E4}.com", flags::NO_TR46).unwrap(),
            "xn---a-wia.com"
        );
        assert_eq!(
            to_ascii_lz("a\u{00E4}-.com", flags::NONTRANSITIONAL).unwrap_err(),
            Error::HyphenStartEnd
        );
        assert_eq!(
            to_ascii_lz("a\u{00E4}-.com", flags::NO_TR46).unwrap(),
            "xn--a--via.com"
        );
        // Unassigned codepoint (U+0378) -> UNASSIGNED.
        assert_eq!(
            to_ascii_lz("\u{0378}.com", flags::NO_TR46).unwrap_err(),
            Error::Unassigned
        );
        // Under STD3 rules the TR46 mapping drops the std3-disallowed '_'.
        assert_eq!(
            to_ascii_lz(
                "_tcp.example.com",
                flags::NONTRANSITIONAL | flags::USE_STD3_ASCII_RULES
            )
            .unwrap(),
            "tcp.example.com"
        );
        assert_eq!(
            to_ascii_lz(
                "_a\u{00E4}.com",
                flags::NONTRANSITIONAL | flags::USE_STD3_ASCII_RULES
            )
            .unwrap(),
            "xn--a-0fa.com"
        );
        // Length limits: a 64-byte ASCII label is TOO_BIG_LABEL; a long
        // non-ASCII label overflows the punycode buffer.
        assert_eq!(
            to_ascii_lz(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
                flags::NONTRANSITIONAL
            )
            .unwrap_err(),
            Error::TooBigLabel
        );
        assert_eq!(
            to_ascii_lz(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u{00E4}.com",
                flags::NONTRANSITIONAL
            )
            .unwrap_err(),
            Error::PunycodeBigOutput
        );
    }

    #[test]
    fn locale_layer_ascii_codeset() {
        // from_locale: ASCII rejects non-ASCII, Latin-1 expands.
        assert_eq!(from_locale(b"abc"), Ok(b"abc".to_vec()));
        // to_locale: ASCII rejects non-ASCII output.
        assert_eq!(to_locale("abc").unwrap(), b"abc".to_vec());
    }

    #[test]
    fn punycode_round_trip() {
        for s in ["münchen", "faß", "😀", "βόλος", "ς"] {
            let encoded = punycode_encode(&s.chars().collect::<Vec<_>>()).unwrap();
            assert_eq!(punycode_decode(&encoded).unwrap(), s);
        }
    }
}
