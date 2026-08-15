//! DNS classes.
//!
//! BIND models classes with the RFC 1035 numbers plus the meta-classes of RFC
//! 2136 (NONE) and RFC 1035 ANY.  `dns_class_fromtext`/`dns_class_totext`
//! accept the standard mnemonics, case-insensitively, and also accept
//! numeric forms (`CLASS<num>` is accepted by the text parser in some BIND
//! contexts — the masterfile lexer accepts `CLASS123`; court
//! `MASTERFILE-CLASS-*` covers this).

use crate::error::{Error, Result};

/// DNS class code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum Class {
    /// Internet (RFC 1035).
    In = 1,
    /// Chaos (RFC 1035).
    Ch = 3,
    /// Hesiod (RFC 1035).
    Hs = 4,
    /// None — meta-class used in dynamic update prerequisites (RFC 2136).
    None = 254,
    /// Any — meta-class (RFC 1035).
    Any = 255,
    /// Any other class, preserved numerically.
    Unknown(u16),
}

impl Class {
    /// The numeric class code.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Class::In => 1,
            Class::Ch => 3,
            Class::Hs => 4,
            Class::None => 254,
            Class::Any => 255,
            Class::Unknown(n) => n,
        }
    }

    /// Construct from a raw code, mapping known classes.
    #[must_use]
    pub const fn from_u16(n: u16) -> Self {
        match n {
            1 => Class::In,
            3 => Class::Ch,
            4 => Class::Hs,
            254 => Class::None,
            255 => Class::Any,
            _ => Class::Unknown(n),
        }
    }

    /// Text mnemonic exactly as BIND's `dns_class_totext` renders it.
    ///
    /// Unknown classes render as `CLASS<num>` — the same form BIND's
    /// `dns_class_totext` produces for out-of-range classes.  Court
    /// `PRESENTATION-CLASS-UNKNOWN` covers this against the oracle.
    #[must_use]
    pub fn to_text(self) -> String {
        match self {
            Class::In => "IN".to_string(),
            Class::Ch => "CH".to_string(),
            Class::Hs => "HS".to_string(),
            Class::None => "NONE".to_string(),
            Class::Any => "ANY".to_string(),
            Class::Unknown(n) => format!("CLASS{n}"),
        }
    }

    /// Parse a class mnemonic the way `dns_class_fromtext` does:
    /// case-insensitive mnemonics; numeric `CLASS<num>` forms accepted.
    pub fn from_text(s: &str) -> Result<Self> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "IN" => Ok(Class::In),
            "CH" => Ok(Class::Ch),
            "HS" => Ok(Class::Hs),
            "NONE" => Ok(Class::None),
            "ANY" => Ok(Class::Any),
            _ => {
                if let Some(num) = upper.strip_prefix("CLASS") {
                    let n: u16 = num.parse().map_err(|_| Error::BadData)?;
                    Ok(Class::from_u16(n))
                } else {
                    Err(Error::BadData)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known() {
        for c in [Class::In, Class::Ch, Class::Hs, Class::None, Class::Any] {
            assert_eq!(Class::from_u16(c.to_u16()), c);
            assert_eq!(Class::from_text(&c.to_text()).unwrap(), c);
        }
    }

    #[test]
    fn unknown_roundtrip() {
        assert_eq!(Class::from_u16(2), Class::Unknown(2));
        assert_eq!(Class::from_u16(2).to_text(), "CLASS2");
        assert_eq!(Class::from_text("class2").unwrap(), Class::Unknown(2));
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(Class::from_text("in").unwrap(), Class::In);
        assert_eq!(Class::from_text("In").unwrap(), Class::In);
        assert_eq!(Class::from_text("cH").unwrap(), Class::Ch);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Class::from_text("").is_err());
        assert!(Class::from_text("CLASS").is_err());
        assert!(Class::from_text("CLASSx").is_err());
        assert!(Class::from_text("BOGUS").is_err());
    }
}
