//! DNS RR types.
//!
//! The mnemonic table mirrors BIND's `lib/dns/rdatatype.c` known-type table,
//! which is itself the authoritative mapping BIND's `dns_rdatatype_fromtext`
//! and `dns_rdatatype_totext` use.  Unknown types render and parse as
//! `TYPE<num>` — the same generic form BIND emits.  Court
//! `PRESENTATION-RRTYPE-*` verifies this table against the oracle
//! (`dns_rdatatype_fromtext`/`dns_rdatatype_totext` probes).
//!
//! Historical types (MD, MF, MB, MG, MR, NULL, WKS, HINFO, MINFO, RP, X25,
//! ISDN, RT, NSAP, NSAP-PTR, SIG, KEY, PX, GPOS, NXT, EID, NIMLOC, ATMA, A6,
//! SINK, APL, NINFO, RKEY, UINFO, UID, GID, UNSPEC, TA, DLV, ...) are kept in
//! the table because BIND still parses/renders them — they are part of the
//! observable surface even where RFCs have obsoleted them (§17).

use crate::error::{Error, Result};

/// DNS RR type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum RrType {
    /// Reserved (0).
    Reserved0,
    A,
    Ns,
    Md,
    Mf,
    Cname,
    Soa,
    Mb,
    Mg,
    Mr,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    Mx,
    Tx,
    Rp,
    Afsdb,
    X25,
    Isdn,
    Rt,
    Nsap,
    NsapPtr,
    Sig,
    Key,
    Px,
    Gpos,
    Aaaa,
    Loc,
    Nxt,
    Eid,
    Nimloc,
    Srv,
    Atma,
    Naptr,
    Kx,
    Cert,
    A6,
    Dname,
    Sink,
    Opt,
    Apl,
    Ds,
    Sshfp,
    Ipseckey,
    Rrsig,
    Nsec,
    Dnskey,
    Dhcid,
    Nsec3,
    Nsec3Param,
    Tlsa,
    Smimea,
    Hip,
    Ninfo,
    Rkey,
    Talink,
    Cds,
    Cdnskey,
    Openpgpkey,
    Csync,
    Zonemd,
    Svcb,
    Https,
    Dsync,
    Hhit,
    Brid,
    Spf,
    Uinfo,
    Uid,
    Gid,
    Unspec,
    Nid,
    L32,
    L64,
    Lp,
    Eui48,
    Eui64,
    Tkey,
    Uri,
    Caa,
    Avc,
    Doa,
    Amtrelay,
    Resinfo,
    Wallet,
    Ta,
    Dlv,
    Tsig,
    Ixfr,
    Axfr,
    Mailb,
    Maila,
    Any,
    Keydata,
    /// Any other type, preserved numerically.
    Unknown(u16),
}

impl RrType {
    /// Numeric type code.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        use RrType::*;
        match self {
            Reserved0 => 0,
            A => 1,
            Ns => 2,
            Md => 3,
            Mf => 4,
            Cname => 5,
            Soa => 6,
            Mb => 7,
            Mg => 8,
            Mr => 9,
            Null => 10,
            Wks => 11,
            Ptr => 12,
            Hinfo => 13,
            Minfo => 14,
            Mx => 15,
            Tx => 16,
            Rp => 17,
            Afsdb => 18,
            X25 => 19,
            Isdn => 20,
            Rt => 21,
            Nsap => 22,
            NsapPtr => 23,
            Sig => 24,
            Key => 25,
            Px => 26,
            Gpos => 27,
            Aaaa => 28,
            Loc => 29,
            Nxt => 30,
            Eid => 31,
            Nimloc => 32,
            Srv => 33,
            Atma => 34,
            Naptr => 35,
            Kx => 36,
            Cert => 37,
            A6 => 38,
            Dname => 39,
            Sink => 40,
            Opt => 41,
            Apl => 42,
            Ds => 43,
            Sshfp => 44,
            Ipseckey => 45,
            Rrsig => 46,
            Nsec => 47,
            Dnskey => 48,
            Dhcid => 49,
            Nsec3 => 50,
            Nsec3Param => 51,
            Tlsa => 52,
            Smimea => 53,
            Hip => 55,
            Ninfo => 56,
            Rkey => 57,
            Talink => 58,
            Cds => 59,
            Cdnskey => 60,
            Openpgpkey => 61,
            Csync => 62,
            Zonemd => 63,
            Svcb => 64,
            Https => 65,
            Dsync => 66,
            Hhit => 67,
            Brid => 68,
            Spf => 99,
            Uinfo => 100,
            Uid => 101,
            Gid => 102,
            Unspec => 103,
            Nid => 104,
            L32 => 105,
            L64 => 106,
            Lp => 107,
            Eui48 => 108,
            Eui64 => 109,
            Tkey => 249,
            Uri => 256,
            Caa => 257,
            Avc => 258,
            Doa => 259,
            Amtrelay => 260,
            Resinfo => 261,
            Wallet => 262,
            Ta => 32768,
            Dlv => 32769,
            Tsig => 250,
            Ixfr => 251,
            Axfr => 252,
            Mailb => 253,
            Maila => 254,
            Any => 255,
            Keydata => 65533,
            Unknown(n) => n,
        }
    }

    /// Construct from a raw code.
    #[must_use]
    pub const fn from_u16(n: u16) -> Self {
        use RrType::*;
        match n {
            0 => Reserved0,
            1 => A,
            2 => Ns,
            3 => Md,
            4 => Mf,
            5 => Cname,
            6 => Soa,
            7 => Mb,
            8 => Mg,
            9 => Mr,
            10 => Null,
            11 => Wks,
            12 => Ptr,
            13 => Hinfo,
            14 => Minfo,
            15 => Mx,
            16 => Tx,
            17 => Rp,
            18 => Afsdb,
            19 => X25,
            20 => Isdn,
            21 => Rt,
            22 => Nsap,
            23 => NsapPtr,
            24 => Sig,
            25 => Key,
            26 => Px,
            27 => Gpos,
            28 => Aaaa,
            29 => Loc,
            30 => Nxt,
            31 => Eid,
            32 => Nimloc,
            33 => Srv,
            34 => Atma,
            35 => Naptr,
            36 => Kx,
            37 => Cert,
            38 => A6,
            39 => Dname,
            40 => Sink,
            41 => Opt,
            42 => Apl,
            43 => Ds,
            44 => Sshfp,
            45 => Ipseckey,
            46 => Rrsig,
            47 => Nsec,
            48 => Dnskey,
            49 => Dhcid,
            50 => Nsec3,
            51 => Nsec3Param,
            52 => Tlsa,
            53 => Smimea,
            55 => Hip,
            56 => Ninfo,
            57 => Rkey,
            58 => Talink,
            59 => Cds,
            60 => Cdnskey,
            61 => Openpgpkey,
            62 => Csync,
            63 => Zonemd,
            64 => Svcb,
            65 => Https,
            66 => Dsync,
            67 => Hhit,
            68 => Brid,
            99 => Spf,
            100 => Uinfo,
            101 => Uid,
            102 => Gid,
            103 => Unspec,
            104 => Nid,
            105 => L32,
            106 => L64,
            107 => Lp,
            108 => Eui48,
            109 => Eui64,
            249 => Tkey,
            250 => Tsig,
            251 => Ixfr,
            252 => Axfr,
            253 => Mailb,
            254 => Maila,
            255 => Any,
            256 => Uri,
            257 => Caa,
            258 => Avc,
            259 => Doa,
            260 => Amtrelay,
            261 => Resinfo,
            262 => Wallet,
            32768 => Ta,
            32769 => Dlv,
            65533 => Keydata,
            n => Unknown(n),
        }
    }

    /// Text mnemonic as BIND's `dns_rdatatype_totext` renders it.
    #[must_use]
    pub fn to_text(self) -> String {
        use RrType::*;
        let s = match self {
            // Type 0 is outside BIND's `dns_rdatatype_totext` switch (the
            // fromtext side still accepts "RESERVED0"), so the name renders
            // as `TYPE0` (verified against the oracle).
            Reserved0 => "TYPE0",
            A => "A",
            Ns => "NS",
            Md => "MD",
            Mf => "MF",
            Cname => "CNAME",
            Soa => "SOA",
            Mb => "MB",
            Mg => "MG",
            Mr => "MR",
            Null => "NULL",
            Wks => "WKS",
            Ptr => "PTR",
            Hinfo => "HINFO",
            Minfo => "MINFO",
            Mx => "MX",
            Tx => "TXT",
            Rp => "RP",
            Afsdb => "AFSDB",
            X25 => "X25",
            Isdn => "ISDN",
            Rt => "RT",
            Nsap => "NSAP",
            NsapPtr => "NSAP-PTR",
            Sig => "SIG",
            Key => "KEY",
            Px => "PX",
            Gpos => "GPOS",
            Aaaa => "AAAA",
            Loc => "LOC",
            Nxt => "NXT",
            Eid => "EID",
            Nimloc => "NIMLOC",
            Srv => "SRV",
            Atma => "ATMA",
            Naptr => "NAPTR",
            Kx => "KX",
            Cert => "CERT",
            A6 => "A6",
            Dname => "DNAME",
            Sink => "SINK",
            Opt => "OPT",
            Apl => "APL",
            Ds => "DS",
            Sshfp => "SSHFP",
            Ipseckey => "IPSECKEY",
            Rrsig => "RRSIG",
            Nsec => "NSEC",
            Dnskey => "DNSKEY",
            Dhcid => "DHCID",
            Nsec3 => "NSEC3",
            Nsec3Param => "NSEC3PARAM",
            Tlsa => "TLSA",
            Smimea => "SMIMEA",
            Hip => "HIP",
            Ninfo => "NINFO",
            Rkey => "RKEY",
            Talink => "TALINK",
            Cds => "CDS",
            Cdnskey => "CDNSKEY",
            Openpgpkey => "OPENPGPKEY",
            Csync => "CSYNC",
            Zonemd => "ZONEMD",
            Svcb => "SVCB",
            Https => "HTTPS",
            Dsync => "DSYNC",
            Hhit => "HHIT",
            Brid => "BRID",
            Spf => "SPF",
            Uinfo => "UINFO",
            Uid => "UID",
            Gid => "GID",
            Unspec => "UNSPEC",
            Nid => "NID",
            L32 => "L32",
            L64 => "L64",
            Lp => "LP",
            Eui48 => "EUI48",
            Eui64 => "EUI64",
            Tkey => "TKEY",
            Uri => "URI",
            Caa => "CAA",
            Avc => "AVC",
            Doa => "DOA",
            Amtrelay => "AMTRELAY",
            Resinfo => "RESINFO",
            Wallet => "WALLET",
            Ta => "TA",
            Dlv => "DLV",
            Tsig => "TSIG",
            Ixfr => "IXFR",
            Axfr => "AXFR",
            Mailb => "MAILB",
            Maila => "MAILA",
            Any => "ANY",
            // BIND's `dns_rdatatype_totext` has no mnemonic for KEYDATA
            // (only its rdata totext exists); the type name renders as
            // `TYPE65533` (verified against the oracle).
            Keydata => "TYPE65533",
            Unknown(_) => return format!("TYPE{}", self.to_u16()),
        };
        s.to_string()
    }

    /// Parse a type mnemonic the way `dns_rdatatype_fromtext` does:
    /// case-insensitive mnemonics; numeric `TYPE<num>` forms.
    pub fn from_text(s: &str) -> Result<Self> {
        let upper = s.to_ascii_uppercase();
        use RrType::*;
        let t = match upper.as_str() {
            "A" => A,
            "NS" => Ns,
            "MD" => Md,
            "MF" => Mf,
            "CNAME" => Cname,
            "SOA" => Soa,
            "MB" => Mb,
            "MG" => Mg,
            "MR" => Mr,
            "NULL" => Null,
            "WKS" => Wks,
            "PTR" => Ptr,
            "HINFO" => Hinfo,
            "MINFO" => Minfo,
            "MX" => Mx,
            "TXT" => Tx,
            "RP" => Rp,
            "AFSDB" => Afsdb,
            "X25" => X25,
            "ISDN" => Isdn,
            "RT" => Rt,
            "NSAP" => Nsap,
            "NSAP-PTR" => NsapPtr,
            "SIG" => Sig,
            "KEY" => Key,
            "PX" => Px,
            "GPOS" => Gpos,
            "AAAA" => Aaaa,
            "LOC" => Loc,
            "NXT" => Nxt,
            "EID" => Eid,
            "NIMLOC" => Nimloc,
            "SRV" => Srv,
            "ATMA" => Atma,
            "NAPTR" => Naptr,
            "KX" => Kx,
            "CERT" => Cert,
            "A6" => A6,
            "DNAME" => Dname,
            "SINK" => Sink,
            "OPT" => Opt,
            "APL" => Apl,
            "DS" => Ds,
            "SSHFP" => Sshfp,
            "IPSECKEY" => Ipseckey,
            "RRSIG" => Rrsig,
            "NSEC" => Nsec,
            "DNSKEY" => Dnskey,
            "DHCID" => Dhcid,
            "NSEC3" => Nsec3,
            "NSEC3PARAM" => Nsec3Param,
            "TLSA" => Tlsa,
            "SMIMEA" => Smimea,
            "HIP" => Hip,
            "NINFO" => Ninfo,
            "RKEY" => Rkey,
            "TALINK" => Talink,
            "CDS" => Cds,
            "CDNSKEY" => Cdnskey,
            "OPENPGPKEY" => Openpgpkey,
            "CSYNC" => Csync,
            "ZONEMD" => Zonemd,
            "SVCB" => Svcb,
            "HTTPS" => Https,
            "DSYNC" => Dsync,
            "HHIT" => Hhit,
            "BRID" => Brid,
            "SPF" => Spf,
            "UINFO" => Uinfo,
            "UID" => Uid,
            "GID" => Gid,
            "UNSPEC" => Unspec,
            "NID" => Nid,
            "L32" => L32,
            "L64" => L64,
            "LP" => Lp,
            "EUI48" => Eui48,
            "EUI64" => Eui64,
            "TKEY" => Tkey,
            "URI" => Uri,
            "CAA" => Caa,
            "AVC" => Avc,
            "DOA" => Doa,
            "AMTRELAY" => Amtrelay,
            "RESINFO" => Resinfo,
            "WALLET" => Wallet,
            "TA" => Ta,
            "DLV" => Dlv,
            "TSIG" => Tsig,
            "IXFR" => Ixfr,
            "AXFR" => Axfr,
            "MAILB" => Mailb,
            "MAILA" => Maila,
            "ANY" => Any,
            "KEYDATA" => Keydata,
            _ => {
                if let Some(num) = upper.strip_prefix("TYPE") {
                    // BIND `dns_rdatatype_fromtext`: the TYPE<n> form is
                    // `strtoul` (a leading `+` accepted), lengths 5..=9,
                    // value <= 0xffff.
                    if (5..=9).contains(&s.len()) {
                        let digits = num.strip_prefix('+').unwrap_or(num);
                        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                            if let Ok(n) = digits.parse::<u32>() {
                                if let Ok(n) = u16::try_from(n) {
                                    return Ok(RrType::from_u16(n));
                                }
                            }
                        }
                    }
                }
                return Err(Error::UnknownClassType);
            }
        };
        Ok(t)
    }

    /// True if this is a meta-type: not a real RR type allowed in zone data.
    /// BIND: `dns_rdatatype_ismeta`.  OPT, TKEY, TSIG, IXFR, AXFR, MAILB,
    /// MAILA, ANY are meta; types 128..=255 without a concrete
    /// implementation carry the `UNKNOWN | META` attributes; URI and CAA are
    /// NOT (they are real types that happen to have codes ≥ 256).
    #[must_use]
    pub const fn is_meta(self) -> bool {
        match self {
            RrType::Opt
            | RrType::Tkey
            | RrType::Tsig
            | RrType::Ixfr
            | RrType::Axfr
            | RrType::Mailb
            | RrType::Maila
            | RrType::Any => true,
            RrType::Unknown(n) => n >= 128 && n <= 255,
            _ => false,
        }
    }

    /// BIND `dns_rdatatype_issingleton`: the type carries
    /// `DNS_RDATATYPEATTR_SINGLETON` (CNAME, SOA, DNAME, OPT, RESINFO).
    #[must_use]
    pub const fn is_singleton(self) -> bool {
        matches!(
            self,
            RrType::Cname | RrType::Soa | RrType::Dname | RrType::Opt | RrType::Resinfo
        )
    }

    /// BIND `dns_rdatatype_isknown`: the type has no `UNKNOWN` attribute,
    /// i.e. BIND has a concrete implementation (type 0 is unknown — its
    /// attributes are `UNKNOWN`; the type-name totext renders `TYPE0`).
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, RrType::Unknown(_) | RrType::Reserved0)
    }

    /// True if RDATA of this type may contain domain names that the message
    /// renderer may compress (BIND's `dns_rdatatype_compression` table /
    /// per-type `towire` handling).  Note: BIND compresses only in specific
    /// positions of specific types; the precise per-position rules live in
    /// the rdata implementations.
    #[must_use]
    pub const fn has_names_in_rdata(self) -> bool {
        use RrType::*;
        matches!(
            self,
            Ns | Md
                | Mf
                | Cname
                | Soa
                | Mb
                | Mg
                | Mr
                | Ptr
                | Minfo
                | Mx
                | Rp
                | Afsdb
                | Rt
                | NsapPtr
                | Px
                | Srv
                | Kx
                | Dname
                | Talink
                | Nid
                | L32
                | L64
                | Lp
                | Amtrelay
                | Dsync
                | Tsig
        )
    }
}

impl core::fmt::Display for RrType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types_roundtrip() {
        for t in [
            RrType::A,
            RrType::Ns,
            RrType::Cname,
            RrType::Soa,
            RrType::Mx,
            RrType::Tx,
            RrType::Ptr,
            RrType::Aaaa,
            RrType::Opt,
            RrType::Tsig,
            RrType::Axfr,
            RrType::Any,
            RrType::Https,
            RrType::Zonemd,
            RrType::Tlsa,
            RrType::Caa,
            RrType::Uri,
        ] {
            assert_eq!(RrType::from_u16(t.to_u16()), t, "u16 roundtrip {t:?}");
            assert_eq!(
                RrType::from_text(&t.to_text()).unwrap(),
                t,
                "text roundtrip {}",
                t.to_text()
            );
        }
    }

    #[test]
    fn unknown_roundtrip() {
        assert_eq!(RrType::from_u16(65000), RrType::Unknown(65000));
        assert_eq!(RrType::from_u16(65000).to_text(), "TYPE65000");
        assert_eq!(
            RrType::from_text("type65000").unwrap(),
            RrType::Unknown(65000)
        );
        assert_eq!(
            RrType::from_text("TYPE65280").unwrap(),
            RrType::Unknown(65280)
        );
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(RrType::from_text("a").unwrap(), RrType::A);
        assert_eq!(RrType::from_text("cNaMe").unwrap(), RrType::Cname);
        assert_eq!(RrType::from_text("https").unwrap(), RrType::Https);
    }

    #[test]
    fn rejects_garbage() {
        assert!(RrType::from_text("").is_err());
        assert!(RrType::from_text("TYPE").is_err());
        assert!(RrType::from_text("TYPEx").is_err());
        assert!(RrType::from_text("BOGUS").is_err());
    }

    #[test]
    fn meta_types() {
        assert!(RrType::Opt.is_meta());
        assert!(RrType::Any.is_meta());
        assert!(!RrType::A.is_meta());
        assert!(!RrType::Caa.is_meta());
        assert!(!RrType::Uri.is_meta());
    }

    #[test]
    fn name_containing_types() {
        assert!(RrType::Ns.has_names_in_rdata());
        assert!(RrType::Soa.has_names_in_rdata());
        assert!(RrType::Mx.has_names_in_rdata());
        assert!(RrType::Tsig.has_names_in_rdata());
        assert!(!RrType::A.has_names_in_rdata());
        assert!(!RrType::Tx.has_names_in_rdata());
        assert!(!RrType::Caa.has_names_in_rdata());
    }
}
