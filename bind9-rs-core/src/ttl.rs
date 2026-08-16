//! TTL handling.
//!
//! BIND's observable TTL behavior (§38 of the spec's lore list): how long a
//! record lives in cache, when TTLs are clamped, and the rules governing
//! zero TTLs.  The cache replacement semantics live in the cache module
//! (later phase); this module defines the scalar and its bounds.

/// A TTL: unsigned 32-bit seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ttl(u32);

impl Ttl {
    pub const ZERO: Ttl = Ttl(0);

    #[must_use]
    pub const fn from_secs(secs: u32) -> Self {
        Ttl(secs)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Display for Ttl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse a TTL from a masterfile token.  BIND accepts bare integers and the
/// unit suffixes `w`, `d`, `h`, `m`, `s` (in any combination, order fixed),
/// case-insensitively.  A bare integer is seconds.  Court
/// `MASTERFILE-TTL-*` verifies the exact accepted grammar against the
/// oracle.
pub fn parse_ttl(token: &str) -> Option<Ttl> {
    // Digits only → seconds.
    if token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse::<u32>().ok().map(Ttl);
    }
    // BIND's strtottl: sequence of <number><unit> with units w/d/h/m/s.
    // No spaces inside a single token in masterfile context (spaces separate
    // tokens there; the lexer hands us one token).
    let bytes = token.as_bytes();
    let mut i = 0;
    let mut total: u64 = 0;
    let mut any = false;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let num: u64 = token[start..i].parse().ok()?;
        if i >= bytes.len() {
            return None; // trailing number without unit is not accepted by BIND
        }
        let unit = bytes[i];
        let mult: u64 = match unit.to_ascii_lowercase() {
            b'w' => 7 * 24 * 3600,
            b'd' => 24 * 3600,
            b'h' => 3600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        i += 1;
        total = total.checked_add(num.checked_mul(mult)?)?;
        any = true;
    }
    if !any || total > u32::MAX as u64 {
        return None;
    }
    Some(Ttl(total as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_seconds() {
        assert_eq!(parse_ttl("0"), Some(Ttl::ZERO));
        assert_eq!(parse_ttl("3600"), Some(Ttl::from_secs(3600)));
        assert_eq!(parse_ttl("4294967295"), Some(Ttl::from_secs(u32::MAX)));
    }

    #[test]
    fn units() {
        assert_eq!(parse_ttl("1w"), Some(Ttl::from_secs(604800)));
        assert_eq!(parse_ttl("1d"), Some(Ttl::from_secs(86400)));
        assert_eq!(parse_ttl("1h"), Some(Ttl::from_secs(3600)));
        assert_eq!(parse_ttl("1m"), Some(Ttl::from_secs(60)));
        assert_eq!(parse_ttl("1s"), Some(Ttl::from_secs(1)));
        assert_eq!(parse_ttl("1h30m"), Some(Ttl::from_secs(5400)));
        assert_eq!(parse_ttl("1W"), Some(Ttl::from_secs(604800)));
        assert_eq!(parse_ttl("1D2H"), Some(Ttl::from_secs(86400 + 7200)));
    }

    #[test]
    fn rejects() {
        assert!(parse_ttl("").is_none());
        assert!(parse_ttl("-1").is_none());
        assert!(parse_ttl("1x").is_none());
        assert!(parse_ttl("h").is_none());
        assert!(parse_ttl("1h30").is_none()); // trailing bare number
        assert!(parse_ttl("4294967296").is_none()); // overflow
        assert!(parse_ttl("99999999999w").is_none()); // overflow
    }
}
