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

    #[must_use]
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// The full 12-bit rcode given the header's low 4 bits.
    #[must_use]
    pub fn full_rcode(&self, header_low: u8) -> Rcode {
        Rcode::combine(header_low, self.ext_rcode)
    }

    /// Parse from the wire form: class (udp size), TTL (ext/version/DO/Z)
    /// and the raw option bytes.
    pub fn from_wire(class: u16, ttl: u32, rdata: &[u8]) -> Result<Opt> {
        let ext_rcode = ((ttl >> 24) & 0xff) as u8;
        let version = ((ttl >> 16) & 0xff) as u8;
        let do_flag = ttl & 0x8000 != 0;
        let z = (ttl & 0x7fff) as u16;

        let mut options = Vec::new();
        let mut pos = 0usize;
        while pos < rdata.len() {
            if pos + 4 > rdata.len() {
                return Err(Error::FormErr);
            }
            let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
            pos += 4;
            if pos + len > rdata.len() {
                return Err(Error::FormErr);
            }
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
    pub fn render(&self, out: &mut Vec<u8>, _comp: Option<&mut Compressor>) -> Result<()> {
        out.push(0); // root name
        out.extend_from_slice(&RrType::Opt.to_u16().to_be_bytes());
        out.extend_from_slice(&self.udp_size.to_be_bytes());
        let ttl: u32 = ((self.ext_rcode as u32) << 24)
            | ((self.version as u32) << 16)
            | (u32::from(self.do_flag) << 15)
            | (self.z as u32 & 0x7fff);
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
}
