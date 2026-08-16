//! Response codes (RCODEs).
//!
//! The 4-bit header RCODE plus the extended-RCODE path through the EDNS OPT
//! (RFC 6891 §6.1.3): the EDNS extended rcode is the high 8 bits, the header
//! rcode the low 4.  BIND's observable mapping (`dns_rcode_totext`) is:
//! known mnemonics for 0..23, `RCODE<num>` for unknown values.  The BADCOOKIE
//! (23) case is documented in the cookie module's courts.

/// Full 12-bit rcode: header's 4 bits combined with the EDNS extended bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YxDomain = 6,
    YxRrset = 7,
    NxRrset = 8,
    NotAuth = 9,
    NotZone = 10,
    /// DSOTYPENI — DNS Stateful Operations type not implemented (RFC 8490).
    Dsotypeni = 11,
    /// BADVERS / BADSIG: EDNS version or signature failure (RFC 6891).
    BadVers = 16,
    /// BADKEY (RFC 2845).
    BadKey = 17,
    /// BADTIME (RFC 2845).
    BadTime = 18,
    /// BADMODE (RFC 2930).
    BadMode = 19,
    /// BADNAME (RFC 2930).
    BadName = 20,
    /// BADALG (RFC 2930).
    BadAlg = 21,
    /// BADTRUNC (RFC 4635).
    BadTrunc = 22,
    /// BADCOOKIE (RFC 7873).
    BadCookie = 23,
    /// Any other code, preserved numerically (BIND renders `RCODE<num>`).
    Unknown(u16),
}

impl Rcode {
    /// The full 12-bit value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::YxDomain => 6,
            Rcode::YxRrset => 7,
            Rcode::NxRrset => 8,
            Rcode::NotAuth => 9,
            Rcode::NotZone => 10,
            Rcode::Dsotypeni => 11,
            Rcode::BadVers => 16,
            Rcode::BadKey => 17,
            Rcode::BadTime => 18,
            Rcode::BadMode => 19,
            Rcode::BadName => 20,
            Rcode::BadAlg => 21,
            Rcode::BadTrunc => 22,
            Rcode::BadCookie => 23,
            Rcode::Unknown(n) => n,
        }
    }

    /// Construct from a raw 12-bit code.
    #[must_use]
    pub const fn from_u16(n: u16) -> Self {
        match n {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            6 => Rcode::YxDomain,
            7 => Rcode::YxRrset,
            8 => Rcode::NxRrset,
            9 => Rcode::NotAuth,
            10 => Rcode::NotZone,
            11 => Rcode::Dsotypeni,
            16 => Rcode::BadVers,
            17 => Rcode::BadKey,
            18 => Rcode::BadTime,
            19 => Rcode::BadMode,
            20 => Rcode::BadName,
            21 => Rcode::BadAlg,
            22 => Rcode::BadTrunc,
            23 => Rcode::BadCookie,
            n => Rcode::Unknown(n),
        }
    }

    /// Split into (header 4-bit rcode, extended 8-bit rcode).
    #[must_use]
    pub const fn split(self) -> (u8, u8) {
        let n = self.to_u16();
        ((n & 0x000f) as u8, (n >> 4) as u8)
    }

    /// Combine header + extended rcodes.
    #[must_use]
    pub const fn combine(header: u8, extended: u8) -> Self {
        Rcode::from_u16(((extended as u16) << 4) | (header as u16 & 0x0f))
    }

    /// Text form exactly as BIND's `dns_rcode_totext` renders it
    /// (lib/dns/rcode.c RCODENAMES/ERCODENAMES, 9.20.26): 0-10 mnemonics,
    /// 11-15 `RESERVED11`..`RESERVED15` (BIND never adopted DSOTYPENI),
    /// 16 BADVERS, 23 BADCOOKIE, everything else the bare number (dig then
    /// prefixes `?` for the numeric-only case).
    #[must_use]
    pub fn to_text(self) -> String {
        match self {
            Rcode::NoError => "NOERROR".to_string(),
            Rcode::FormErr => "FORMERR".to_string(),
            Rcode::ServFail => "SERVFAIL".to_string(),
            Rcode::NxDomain => "NXDOMAIN".to_string(),
            Rcode::NotImp => "NOTIMP".to_string(),
            Rcode::Refused => "REFUSED".to_string(),
            Rcode::YxDomain => "YXDOMAIN".to_string(),
            Rcode::YxRrset => "YXRRSET".to_string(),
            Rcode::NxRrset => "NXRRSET".to_string(),
            Rcode::NotAuth => "NOTAUTH".to_string(),
            Rcode::NotZone => "NOTZONE".to_string(),
            Rcode::Dsotypeni => "RESERVED11".to_string(),
            Rcode::BadVers => "BADVERS".to_string(),
            Rcode::BadCookie => "BADCOOKIE".to_string(),
            Rcode::BadKey
            | Rcode::BadTime
            | Rcode::BadMode
            | Rcode::BadName
            | Rcode::BadAlg
            | Rcode::BadTrunc => self.to_u16().to_string(),
            Rcode::Unknown(n) => n.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_combine() {
        assert_eq!(Rcode::BadVers.split(), (0, 1));
        assert_eq!(Rcode::BadCookie.split(), (7, 1));
        assert_eq!(Rcode::combine(0, 1), Rcode::BadVers);
        assert_eq!(Rcode::combine(7, 1), Rcode::BadCookie);
        assert_eq!(Rcode::ServFail.split(), (2, 0));
        assert_eq!(Rcode::combine(2, 0), Rcode::ServFail);
    }

    #[test]
    fn unknown_roundtrip() {
        assert_eq!(Rcode::from_u16(12), Rcode::Unknown(12));
        assert_eq!(Rcode::Unknown(12).to_u16(), 12);
        assert_eq!(Rcode::from_u16(4095), Rcode::Unknown(4095));
    }

    #[test]
    fn text_forms() {
        assert_eq!(Rcode::NxDomain.to_text(), "NXDOMAIN");
        assert_eq!(Rcode::BadCookie.to_text(), "BADCOOKIE");
        // BIND renders unknown rcodes as the bare number (dig adds '?').
        assert_eq!(Rcode::Unknown(12).to_text(), "12");
        // 11-15 render as RESERVED11..15, not DSOTYPENI.
        assert_eq!(Rcode::Dsotypeni.to_text(), "RESERVED11");
        // TSIG-only rcodes (17-22) are not in the message-rcode table.
        assert_eq!(Rcode::BadKey.to_text(), "17");
    }
}
