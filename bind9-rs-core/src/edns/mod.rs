//! EDNS (RFC 6891): the OPT pseudo-record and its options.
//!
//! BIND's observable OPT handling is courted by `WIRE-EDNS-*` and
//! `RENDER-OPT-PLACEMENT`:
//!
//! - OPT owner name is the root; type 41; class = UDP payload size; TTL
//!   packs extended-rcode (8) | version (8) | DO (1) | Z (15);
//! - a second OPT in one message is FORMERR (court `WIRE-MESSAGE-DUPOPT`);
//! - an EDNS version the server does not support yields BADVERS with the
//!   highest supported version in the response OPT (server layer, Phase 3);
//! - unknown options are preserved opaquely (BIND keeps them and passes
//!   them through in responses where policy permits; courted by
//!   `WIRE-EDNS-UNKNOWNOPT`).
//!
//! Known options (NSID, COOKIE, ECS, EDE, ...) get typed modules as their
//! courts land; until then they round-trip as opaque data, which is honest
//! scaffolding (the generic form IS the BIND behavior for unrecognized
//! options).

use crate::error::{Error, Result};
use crate::message::compression::Compressor;
use crate::rcode::Rcode;
use crate::rrtype::RrType;

/// One EDNS option: code + opaque data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// Known EDNS option codes (IANA "DNS EDNS0 Options").
pub mod option_code {
    pub const LLQ: u16 = 1;
    pub const UL: u16 = 2;
    pub const NSID: u16 = 3;
    pub const DAU: u16 = 5;
    pub const DHU: u16 = 6;
    pub const N3U: u16 = 7;
    pub const ECS: u16 = 8;
    pub const EXPIRE: u16 = 9;
    pub const COOKIE: u16 = 10;
    pub const TCP_KEEPALIVE: u16 = 11;
    pub const PADDING: u16 = 12;
    pub const CHAIN: u16 = 13;
    pub const KEY_TAG: u16 = 14;
    pub const EDE: u16 = 15;
}

/// BIND's per-option length/shape validation (`fromwire_opt` in
/// lib/dns/rdata/generic/opt_41.c).  Returns `DNS_R_OPTERR` on violation.
pub(crate) fn validate_opt_option(code: u16, data: &[u8]) -> Result<()> {
    let len = data.len();
    match code {
        option_code::LLQ => {
            if len != 18 {
                return Err(Error::Opterr);
            }
        }
        option_code::UL => {
            if len != 4 && len != 8 {
                return Err(Error::Opterr);
            }
        }
        option_code::ECS => {
            if len < 4 {
                return Err(Error::Opterr);
            }
            let family = u16::from_be_bytes([data[0], data[1]]);
            let addrlen = data[2];
            let scope = data[3];
            match family {
                0 => {
                    if addrlen != 0 || scope != 0 {
                        return Err(Error::Opterr);
                    }
                }
                1 => {
                    if addrlen > 32 || scope > 32 {
                        return Err(Error::Opterr);
                    }
                }
                2 => {
                    if addrlen > 128 || scope > 128 {
                        return Err(Error::Opterr);
                    }
                }
                _ => return Err(Error::Opterr),
            }
            let addrbytes = (usize::from(addrlen) + 7) / 8;
            if addrbytes + 4 != len {
                return Err(Error::Opterr);
            }
            if addrbytes != 0 && addrlen % 8 != 0 {
                let bits = !0u8 << (8 - addrlen % 8);
                if bits & data[4 + addrbytes - 1] != data[4 + addrbytes - 1] {
                    return Err(Error::Opterr);
                }
            }
        }
        option_code::EXPIRE => {
            if len != 0 && len != 4 {
                return Err(Error::Opterr);
            }
        }
        option_code::COOKIE => {
            if len != 8 && !(16..=40).contains(&len) {
                return Err(Error::Opterr);
            }
        }
        option_code::KEY_TAG => {
            if len == 0 || len % 2 != 0 {
                return Err(Error::Opterr);
            }
        }
        option_code::EDE => {
            if len < 2 {
                return Err(Error::Opterr);
            }
            // BIND `isc_utf8_bom`: the UTF-8 byte order mark is not
            // permitted (RFC 5198).
            if len >= 5 && data[2..5] == [0xef, 0xbb, 0xbf] {
                return Err(Error::Opterr);
            }
            if !isc_utf8_valid(&data[2..]) {
                return Err(Error::Opterr);
            }
        }
        16 | 17 => {
            // DNS_OPT_CLIENT_TAG / DNS_OPT_SERVER_TAG
            if len != 2 {
                return Err(Error::Opterr);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate a whole OPT RDATA region (the option framing plus each
/// option's payload) — BIND `fromwire_opt`.  A truncated option header or
/// an option length overrunning the region is `ISC_R_UNEXPECTEDEND`;
/// shape violations of known options are `DNS_R_OPTERR` ("malformed OPT
/// option").  The wire bytes are preserved verbatim.
pub(crate) fn validate_opt_data(rdata: &[u8]) -> Result<()> {
    let mut pos = 0usize;
    while pos < rdata.len() {
        if pos + 4 > rdata.len() {
            return Err(Error::UnexpectedEnd);
        }
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return Err(Error::UnexpectedEnd);
        }
        validate_opt_option(code, &rdata[pos..pos + len])?;
        pos += len;
    }
    Ok(())
}

/// BIND `isc_utf8_valid` (lib/isc/utf8.c, 9.20.26) reproduced exactly:
/// RFC 3629 ranges with overlong and > U+10FFFF rejections — but *without*
/// a surrogate check (a 3-byte U+D800..U+DFFF encoding is accepted, which
/// `std::str::from_utf8` would reject).
fn isc_utf8_valid(buf: &[u8]) -> bool {
    let mut i = 0usize;
    while i < buf.len() {
        if buf[i] <= 0x7f {
            i += 1;
            continue;
        }
        if i + 1 < buf.len() && buf[i] & 0xe0 == 0xc0 && buf[i + 1] & 0xc0 == 0x80 {
            let w = ((u16::from(buf[i]) & 0x1f) << 6) | u16::from(buf[i + 1] & 0x3f);
            if w < 0x80 {
                return false;
            }
            i += 2;
            continue;
        }
        if i + 2 < buf.len()
            && buf[i] & 0xf0 == 0xe0
            && buf[i + 1] & 0xc0 == 0x80
            && buf[i + 2] & 0xc0 == 0x80
        {
            let w = ((u32::from(buf[i]) & 0x0f) << 12)
                | ((u32::from(buf[i + 1]) & 0x3f) << 6)
                | u32::from(buf[i + 2] & 0x3f);
            if w < 0x0800 {
                return false;
            }
            i += 3;
            continue;
        }
        if i + 3 < buf.len()
            && buf[i] & 0xf8 == 0xf0
            && buf[i + 1] & 0xc0 == 0x80
            && buf[i + 2] & 0xc0 == 0x80
            && buf[i + 3] & 0xc0 == 0x80
        {
            let w = ((u32::from(buf[i]) & 0x07) << 18)
                | ((u32::from(buf[i + 1]) & 0x3f) << 12)
                | ((u32::from(buf[i + 2]) & 0x3f) << 6)
                | u32::from(buf[i + 3] & 0x3f);
            if !(0x10000..=0x10ffff).contains(&w) {
                return false;
            }
            i += 4;
            continue;
        }
        return false;
    }
    true
}

/// The OPT pseudo-record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    /// Class field: maximum UDP payload size the sender can accept.
    udp_size: u16,
    /// Extended rcode (high 8 bits of the 12-bit rcode).
    ext_rcode: u8,
    /// EDNS version.
    version: u8,
    /// DNSSEC OK bit.
    do_flag: bool,
    /// Reserved Z bits (15).
    z: u16,
    /// The EDNS options.
    options: Vec<EdnsOption>,
}

impl Opt {
    /// A minimal OPT with the given UDP payload size, version 0, DO clear.
    #[must_use]
    pub fn new(udp_size: u16) -> Self {
        Opt {
            udp_size,
            ext_rcode: 0,
            version: 0,
            do_flag: false,
            z: 0,
            options: Vec::new(),
        }
    }

    /// A copy with the DO (DNSSEC OK) bit set.
    #[must_use]
    pub fn with_do(mut self) -> Self {
        self.do_flag = true;
        self
    }

    /// A copy with the CO (0x4000, RFC 8764 "co" bit) set.  dig's `+coflag`.
    #[must_use]
    pub fn with_co(mut self) -> Self {
        self.z |= 0x4000;
        self
    }

    /// A copy with an EDNS option appended (dig's `+ednsopt`/`+cookie`
    /// machinery and the resolver's option-forwarding path).
    #[must_use]
    pub fn with_option(mut self, code: u16, data: Vec<u8>) -> Self {
        self.options.push(EdnsOption { code, data });
        self
    }

    #[must_use]
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_size
    }

    #[must_use]
    pub fn ext_rcode(&self) -> u8 {
        self.ext_rcode
    }

    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub fn do_flag(&self) -> bool {
        self.do_flag
    }

    /// The CO bit (RFC 8764).
    #[must_use]
    pub fn co_flag(&self) -> bool {
        self.z & 0x4000 != 0
    }

    /// The raw Z field (15 bits).
    #[must_use]
    pub fn z(&self) -> u16 {
        self.z & 0x7fff
    }

    #[must_use]
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// The raw OPT TTL field (ext-rcode | version | DO | Z).
    #[must_use]
    pub fn raw_ttl(&self) -> u32 {
        ((u32::from(self.ext_rcode)) << 24)
            | ((u32::from(self.version)) << 16)
            | (u32::from(self.do_flag) << 15)
            | (self.z as u32 & 0x7fff)
    }

    /// The full 12-bit rcode given the header's low 4 bits.
    #[must_use]
    pub fn full_rcode(&self, header_low: u8) -> Rcode {
        Rcode::combine(header_low, self.ext_rcode)
    }

    /// Parse from the wire form: class (udp size), TTL (ext/version/DO/Z)
    /// and the raw option bytes.  Option payloads are validated per BIND's
    /// `fromwire_opt` (lib/dns/rdata/generic/opt_41.c): known option codes
    /// must satisfy their length/shape rules or the parse fails with
    /// `DNS_R_OPTERR` ("malformed OPT option"); unknown codes pass through
    /// opaquely.
    pub fn from_wire(class: u16, ttl: u32, rdata: &[u8]) -> Result<Opt> {
        let ext_rcode = ((ttl >> 24) & 0xff) as u8;
        let version = ((ttl >> 16) & 0xff) as u8;
        let do_flag = ttl & 0x8000 != 0;
        let z = (ttl & 0x7fff) as u16;

        validate_opt_data(rdata)?;
        let mut options = Vec::new();
        let mut pos = 0usize;
        while pos < rdata.len() {
            let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
            pos += 4;
            options.push(EdnsOption {
                code,
                data: rdata[pos..pos + len].to_vec(),
            });
            pos += len;
        }

        Ok(Opt {
            udp_size: class,
            ext_rcode,
            version,
            do_flag,
            z,
            options,
        })
    }

    /// Render into the message (owner = root, type = OPT).
    pub fn render(&self, out: &mut Vec<u8>, comp: Option<&mut Compressor>) -> Result<()> {
        self.render_with_ttl(out, self.raw_ttl(), comp)
    }

    /// Render with an explicit TTL — the message renderer folds the merged
    /// extended rcode into the TTL before writing (BIND `dns_message_renderend`).
    pub fn render_with_ttl(
        &self,
        out: &mut Vec<u8>,
        ttl: u32,
        _comp: Option<&mut Compressor>,
    ) -> Result<()> {
        out.push(0); // root name
        out.extend_from_slice(&RrType::Opt.to_u16().to_be_bytes());
        out.extend_from_slice(&self.udp_size.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        let len_pos = out.len();
        out.extend_from_slice(&0u16.to_be_bytes());
        for o in &self.options {
            out.extend_from_slice(&o.code.to_be_bytes());
            out.extend_from_slice(&(o.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&o.data);
        }
        let rdlen = (out.len() - len_pos - 2) as u16;
        out[len_pos..len_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let mut o = Opt::new(1232);
        o.do_flag = true;
        o.ext_rcode = 1;
        o.options.push(EdnsOption {
            code: option_code::NSID,
            data: b"nsid".to_vec(),
        });
        let mut out = Vec::new();
        o.render(&mut out, None).unwrap();
        // name root | type 41 | class 1232 | ttl | rdlen
        assert_eq!(out[0], 0);
        assert_eq!(&out[1..3], &[0, 41]);
        assert_eq!(&out[3..5], &[0x04, 0xd0]);
        assert_eq!(&out[5..6], &[0x01]); // ext rcode 1
        assert_eq!(&out[6..7], &[0x00]); // version 0
        assert_eq!(&out[7..8], &[0x80]); // DO
        assert_eq!(&out[8..9], &[0x00]); // z
        assert_eq!(&out[9..11], &[0, 8]); // rdlen
        assert_eq!(&out[11..13], &[0, 3]); // NSID
        assert_eq!(&out[13..15], &[0, 4]);
        assert_eq!(&out[15..19], b"nsid");

        let parsed = Opt::from_wire(1232, 0x01008000, &out[11..19]).unwrap();
        assert_eq!(parsed, o);
        assert_eq!(parsed.full_rcode(0), Rcode::BadVers);
    }

    #[test]
    fn malformed_option_rejected() {
        // Option length overruns rdata.
        let rdata = [0, 3, 0, 5, b'n', b's']; // claims 5 bytes, has 2
        assert!(Opt::from_wire(1232, 0, &rdata).is_err());
        // Truncated option header.
        assert!(Opt::from_wire(1232, 0, &[0, 3, 0]).is_err());
    }

    #[test]
    fn unknown_options_preserved() {
        let rdata = [0xfe, 0xed, 0, 2, 0xab, 0xcd];
        let o = Opt::from_wire(1232, 0, &rdata).unwrap();
        assert_eq!(o.options.len(), 1);
        assert_eq!(o.options[0].code, 0xfeed);
        assert_eq!(o.options[0].data, vec![0xab, 0xcd]);
    }

    #[test]
    fn bind_utf8_accepts_surrogates() {
        // Oracle-pinned (WIRE-MESSAGE): BIND's isc_utf8_valid accepts a
        // 3-byte surrogate encoding, unlike std::str::from_utf8.
        assert!(isc_utf8_valid(&[0xed, 0xa0, 0x80]));
        assert!(isc_utf8_valid(b"hi"));
        assert!(!isc_utf8_valid(&[0xff]));
        assert!(!isc_utf8_valid(&[0xc0, 0x80])); // overlong
        assert!(!isc_utf8_valid(&[0xf4, 0x90, 0x80, 0x80])); // > U+10FFFF
    }
}
