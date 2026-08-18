//! The RDATA framework and concrete type implementations (§17).
//!
//! The architecture is an enum of typed variants with a dispatch table —
//! the Rust analogue of BIND's per-type `dns_rdata_*` method tables.  Every
//! type implements the five surfaces BIND's rdata API exposes:
//!
//! - wire parse (`dns_rdata_fromwire`), with message-compression awareness
//!   for name fields;
//! - wire render (`dns_rdata_towire`), with compressor awareness;
//! - text parse (`dns_rdata_fromtext`) from the masterfile lexer;
//! - text render (`dns_rdata_totext`);
//! - canonical form (`dns_rdata_canonical` / `dns_rdata_digest`): lowercased
//!   uncompressed wire form for DNSSEC.
//!
//! Unknown types use the generic `\# <length> <hex>` form, as BIND does.
//! The type atlas (§17) is generated from this module plus the archaeology
//! records; each type's courts are listed in `docs/compatibility/parity-ledger.md`.

pub mod txt;
pub mod unknown;

use crate::class::Class;
use crate::edns::validate_opt_data;
use crate::error::{Error, Result};
use crate::message::compression::Compressor;
use crate::name::Name;
use crate::presentation::lexer::{Lexer, Token};
use crate::rrtype::RrType;
use std::net::{Ipv4Addr, Ipv6Addr};

pub use txt::Txt;
pub use unknown::UnknownRdata;

/// An SOA record (RFC 1035 §3.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// An MX record (RFC 1035 §3.3.9).  RT (RFC 1183), AFSDB (RFC 1183) and KX
/// (RFC 2230) share the `preference + name` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefName {
    pub preference: u16,
    pub name: Name,
}

/// An SRV record (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Name,
}

/// A CH-class A record (RFC 1035 §3.4.1): a domain name plus a 16-bit
/// domain number rendered in octal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChA {
    pub name: Name,
    pub addr: u16,
}

/// A MINFO record (RFC 1035 §3.3.7) / RP record (RFC 1183): two names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoNames {
    pub first: Name,
    pub second: Name,
}

/// An RRSIG record (RFC 4034 §3.1).  SIG (RFC 2535) shares the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    pub covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub time_signed: u32,
    pub key_tag: u16,
    pub signer: Name,
    pub signature: Vec<u8>,
}

/// An NSEC3 record (RFC 5155 §3.2).  `types` is the raw type-bitmap
/// (window blocks), validated like BIND's `typemap_test`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    pub hash: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next: Vec<u8>,
    pub types: Vec<u8>,
}

/// A TSIG record (RFC 8945 §4.2).  `time_signed` is the 48-bit value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tsig {
    pub algorithm: Name,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    pub original_id: u16,
    pub error: u16,
    pub other: Vec<u8>,
}

/// A TKEY record (RFC 2930 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tkey {
    pub algorithm: Name,
    pub inception: u32,
    pub expiration: u32,
    pub mode: u16,
    pub error: u16,
    pub key: Vec<u8>,
    pub other: Vec<u8>,
}

/// Parsed RDATA for the Phase-1 type set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    /// A (RFC 1035).
    A(Ipv4Addr),
    /// AAAA (RFC 3596).
    Aaaa(Ipv6Addr),
    /// Single-name types: NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME.
    Name { type_: RrType, name: Name },
    /// SOA.
    Soa(Soa),
    /// MX, RT, AFSDB, KX.
    PrefName { type_: RrType, value: PrefName },
    /// SRV.
    Srv(Srv),
    /// CH-class A (RFC 1035 §3.4.1): name + 16-bit octal domain number.
    ChA(ChA),
    /// MINFO, RP.
    TwoNames { type_: RrType, value: TwoNames },
    /// TXT (and SPF, which shares the character-string syntax).
    Txt { type_: RrType, value: Txt },
    /// RRSIG (RFC 4034 §3.1).
    Rrsig(Rrsig),
    /// SIG (RFC 2535) — the same layout as RRSIG without the label-count
    /// check and with a different empty-signature result code.
    Sig(Rrsig),
    /// NSEC3 (RFC 5155 §3.2).
    Nsec3(Nsec3),
    /// TSIG (RFC 8945 §4.2).
    Tsig(Tsig),
    /// TKEY (RFC 2930 §2).
    Tkey(Tkey),
    /// OPT RDATA (RFC 6891): the raw option octets, validated like BIND's
    /// `fromwire_opt`.  Only reachable when an OPT record lands in a
    /// section (a second OPT, or an OPT outside the additional section,
    /// under best-effort parsing); the first well-placed OPT is captured
    /// as [`crate::edns::Opt`].
    OptData(Vec<u8>),
    /// A DynDNS meta-RR (RFC 2136 prerequisite/update record): empty rdata
    /// with BIND's `DNS_RDATA_UPDATE` flag — totext and towire produce
    /// nothing.
    UpdateMeta(RrType),
    /// Any type not yet given a concrete implementation, handled with the
    /// generic wire/presentation forms.
    Unknown(UnknownRdata),
}

/// Types with a single domain name in their RDATA.
const SINGLE_NAME_TYPES: &[RrType] = &[
    RrType::Ns,
    RrType::Md,
    RrType::Mf,
    RrType::Cname,
    RrType::Mb,
    RrType::Mg,
    RrType::Mr,
    RrType::Ptr,
    RrType::Dname,
];

/// Types with `preference + name` RDATA.
const PREF_NAME_TYPES: &[RrType] = &[RrType::Mx, RrType::Rt, RrType::Afsdb, RrType::Kx];

/// Types with two names in their RDATA.
const TWO_NAME_TYPES: &[RrType] = &[RrType::Minfo, RrType::Rp];

/// Types with character-string RDATA (TXT syntax).
const TXT_TYPES: &[RrType] = &[RrType::Tx, RrType::Spf];

impl Rdata {
    /// The RR type of this RDATA.
    #[must_use]
    pub fn rrtype(&self) -> RrType {
        match self {
            Rdata::A(_) => RrType::A,
            Rdata::Aaaa(_) => RrType::Aaaa,
            Rdata::Name { type_, .. } => *type_,
            Rdata::Soa(_) => RrType::Soa,
            Rdata::PrefName { type_, .. } => *type_,
            Rdata::Srv(_) => RrType::Srv,
            Rdata::ChA(_) => RrType::A,
            Rdata::TwoNames { type_, .. } => *type_,
            Rdata::Txt { type_, .. } => *type_,
            Rdata::Rrsig(_) => RrType::Rrsig,
            Rdata::Sig(_) => RrType::Sig,
            Rdata::Nsec3(_) => RrType::Nsec3,
            Rdata::Tsig(_) => RrType::Tsig,
            Rdata::Tkey(_) => RrType::Tkey,
            Rdata::OptData(_) => RrType::Opt,
            Rdata::UpdateMeta(t) => *t,
            Rdata::Unknown(u) => u.rrtype(),
        }
    }

    /// Parse RDATA from wire form, dispatching on the record's class the
    /// way BIND's class-gated `dns_rdata_fromwire` does: a class the type
    /// has no implementation for falls back to the RFC 3597 generic form
    /// (verbatim copy, no validation).  See [`rrtype_native_class`].
    pub fn from_wire_class(
        type_: RrType,
        class: Class,
        buf: &[u8],
        pos: &mut usize,
        end: usize,
    ) -> Result<Rdata> {
        if type_ == RrType::A && class == Class::Ch {
            // CH-class A (lib/dns/rdata/ch_3/a_1.c): a name (compression
            // allowed, bounded by the rdlength region) followed by a 16-bit
            // domain number.
            if *pos >= end {
                return Err(Error::UnexpectedEnd);
            }
            let fw = crate::name::wire::from_wire_bounded(buf, *pos, end, true)?;
            if fw.consumed > end {
                return Err(Error::FormErr);
            }
            let p = fw.consumed;
            if end - p < 2 {
                return Err(Error::UnexpectedEnd);
            }
            let addr = u16::from_be_bytes([buf[p], buf[p + 1]]);
            *pos = end;
            if p + 2 != end {
                // BIND: the fromwire wrapper rejects trailing octets.
                return Err(Error::ExtraData);
            }
            return Ok(Rdata::ChA(ChA {
                name: fw.name,
                addr,
            }));
        }
        if rrtype_native_class(type_, class) {
            Rdata::from_wire(type_, buf, pos, end)
        } else {
            let data = UnknownRdata::from_wire(buf, pos, end)?.with_type(type_);
            Ok(Rdata::Unknown(data))
        }
    }

    /// Parse RDATA from wire form.
    ///
    /// `buf` is the whole message (so compressed names resolve), `pos` the
    /// start of RDATA, `end` the end of RDATA (`rdlength` bound).  Exactly
    /// `end - pos` octets must be consumed, else [`Error::FormErr`] (BIND
    /// reports a trailing-data mismatch — court `WIRE-RDATA-LENGTH-*`).
    pub fn from_wire(type_: RrType, buf: &[u8], pos: &mut usize, end: usize) -> Result<Rdata> {
        let r = match type_ {
            RrType::A => {
                if end - *pos < 4 {
                    return Err(Error::UnexpectedEnd);
                }
                let ip = Ipv4Addr::new(buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]);
                *pos += 4;
                Rdata::A(ip)
            }
            RrType::Aaaa => {
                if end - *pos < 16 {
                    return Err(Error::UnexpectedEnd);
                }
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[*pos..*pos + 16]);
                *pos += 16;
                Rdata::Aaaa(Ipv6Addr::from(o))
            }
            t if SINGLE_NAME_TYPES.contains(&t) => {
                let (name, npos) = parse_rdata_name(buf, *pos, end)?;
                *pos = npos;
                Rdata::Name { type_: t, name }
            }
            RrType::Soa => {
                let (mname, p1) = parse_rdata_name(buf, *pos, end)?;
                let (rname, p2) = parse_rdata_name(buf, p1, end)?;
                if end - p2 < 20 {
                    return Err(Error::UnexpectedEnd);
                }
                let soa = Soa {
                    mname,
                    rname,
                    serial: rd_u32(buf, p2),
                    refresh: rd_u32(buf, p2 + 4),
                    retry: rd_u32(buf, p2 + 8),
                    expire: rd_u32(buf, p2 + 12),
                    minimum: rd_u32(buf, p2 + 16),
                };
                *pos = p2 + 20;
                Rdata::Soa(soa)
            }
            t if PREF_NAME_TYPES.contains(&t) => {
                if end - *pos < 3 {
                    return Err(Error::UnexpectedEnd);
                }
                let preference = rd_u16(buf, *pos);
                let (name, npos) = parse_rdata_name(buf, *pos + 2, end)?;
                *pos = npos;
                Rdata::PrefName {
                    type_: t,
                    value: PrefName { preference, name },
                }
            }
            RrType::Srv => {
                if end - *pos < 7 {
                    return Err(Error::UnexpectedEnd);
                }
                let priority = rd_u16(buf, *pos);
                let weight = rd_u16(buf, *pos + 2);
                let port = rd_u16(buf, *pos + 4);
                let (target, npos) = parse_rdata_name(buf, *pos + 6, end)?;
                *pos = npos;
                Rdata::Srv(Srv {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            t if TWO_NAME_TYPES.contains(&t) => {
                let (first, p1) = parse_rdata_name(buf, *pos, end)?;
                let (second, p2) = parse_rdata_name(buf, p1, end)?;
                *pos = p2;
                Rdata::TwoNames {
                    type_: t,
                    value: TwoNames { first, second },
                }
            }
            t if TXT_TYPES.contains(&t) => {
                let value = Txt::from_wire(buf, pos, end)?;
                Rdata::Txt { type_: t, value }
            }
            RrType::Rrsig => {
                let r = rrsig_from_wire(buf, *pos, end, true)?;
                *pos = end;
                Rdata::Rrsig(r)
            }
            RrType::Sig => {
                let r = rrsig_from_wire(buf, *pos, end, false)?;
                *pos = end;
                Rdata::Sig(r)
            }
            RrType::Nsec3 => {
                let n = nsec3_from_wire(buf, *pos, end)?;
                *pos = end;
                Rdata::Nsec3(n)
            }
            RrType::Tsig => {
                let (t, consumed) = tsig_from_wire(buf, *pos, end)?;
                *pos = consumed;
                Rdata::Tsig(t)
            }
            RrType::Tkey => {
                let (t, consumed) = tkey_from_wire(buf, *pos, end)?;
                *pos = consumed;
                Rdata::Tkey(t)
            }
            RrType::Opt => {
                // OPT RDATA is a sequence of EDNS options validated like
                // BIND's fromwire_opt; the bytes are preserved verbatim.
                let data = buf[*pos..end].to_vec();
                validate_opt_data(&data)?;
                *pos = end;
                Rdata::OptData(data)
            }
            _ => {
                let data = UnknownRdata::from_wire(buf, pos, end)?.with_type(type_);
                Rdata::Unknown(data)
            }
        };
        if *pos != end {
            // BIND dns_rdata_fromwire: unconsumed source bytes are
            // DNS_R_EXTRADATA ("extra input data").
            return Err(Error::ExtraData);
        }
        Ok(r)
    }

    /// Render RDATA to wire form; name fields may be compressed via `comp`.
    pub fn to_wire(&self, out: &mut Vec<u8>, mut comp: Option<&mut Compressor>) -> Result<()> {
        match self {
            Rdata::A(ip) => {
                out.extend_from_slice(&ip.octets());
            }
            Rdata::Aaaa(ip) => {
                out.extend_from_slice(&ip.octets());
            }
            Rdata::Name { type_, name } => match comp.as_deref_mut() {
                Some(c) => render_rdata_name(out, name, Some(c), rdata_towire_compresses(*type_))?,
                None => {
                    crate::name::wire::to_wire_uncompressed(name, out)?;
                }
            },
            Rdata::Soa(soa) => {
                render_rdata_name(out, &soa.mname, comp.as_deref_mut(), true)?;
                render_rdata_name(out, &soa.rname, comp.as_deref_mut(), true)?;
                out.extend_from_slice(&soa.serial.to_be_bytes());
                out.extend_from_slice(&soa.refresh.to_be_bytes());
                out.extend_from_slice(&soa.retry.to_be_bytes());
                out.extend_from_slice(&soa.expire.to_be_bytes());
                out.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            Rdata::PrefName { type_, value } => {
                out.extend_from_slice(&value.preference.to_be_bytes());
                render_rdata_name(out, &value.name, comp.as_deref_mut(), *type_ == RrType::Mx)?;
            }
            Rdata::Srv(srv) => {
                out.extend_from_slice(&srv.priority.to_be_bytes());
                out.extend_from_slice(&srv.weight.to_be_bytes());
                out.extend_from_slice(&srv.port.to_be_bytes());
                render_rdata_name(out, &srv.target, comp.as_deref_mut(), false)?;
            }
            Rdata::ChA(ch) => {
                render_rdata_name(out, &ch.name, comp.as_deref_mut(), true)?;
                out.extend_from_slice(&ch.addr.to_be_bytes());
            }
            Rdata::TwoNames { type_, value } => {
                let compress = *type_ == RrType::Minfo;
                render_rdata_name(out, &value.first, comp.as_deref_mut(), compress)?;
                render_rdata_name(out, &value.second, comp.as_deref_mut(), compress)?;
            }
            Rdata::Txt { value, .. } => value.to_wire(out)?,
            Rdata::Rrsig(r) => rrsig_to_wire(r, out, comp.as_deref_mut())?,
            Rdata::Sig(r) => rrsig_to_wire(r, out, comp.as_deref_mut())?,
            Rdata::Nsec3(n) => {
                out.push(n.hash);
                out.push(n.flags);
                out.extend_from_slice(&n.iterations.to_be_bytes());
                out.push(n.salt.len() as u8);
                out.extend_from_slice(&n.salt);
                out.push(n.next.len() as u8);
                out.extend_from_slice(&n.next);
                out.extend_from_slice(&n.types);
            }
            Rdata::Tsig(t) => {
                render_rdata_name(out, &t.algorithm, comp.as_deref_mut(), false)?;
                let hi = ((t.time_signed >> 32) & 0xffff) as u16;
                let lo = (t.time_signed & 0xffff_ffff) as u32;
                out.extend_from_slice(&hi.to_be_bytes());
                out.extend_from_slice(&lo.to_be_bytes());
                out.extend_from_slice(&t.fudge.to_be_bytes());
                out.extend_from_slice(&(t.mac.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.mac);
                out.extend_from_slice(&t.original_id.to_be_bytes());
                out.extend_from_slice(&t.error.to_be_bytes());
                out.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.other);
            }
            Rdata::Tkey(t) => {
                render_rdata_name(out, &t.algorithm, comp.as_deref_mut(), false)?;
                out.extend_from_slice(&t.inception.to_be_bytes());
                out.extend_from_slice(&t.expiration.to_be_bytes());
                out.extend_from_slice(&t.mode.to_be_bytes());
                out.extend_from_slice(&t.error.to_be_bytes());
                out.extend_from_slice(&(t.key.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.key);
                out.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.other);
            }
            Rdata::OptData(d) => out.extend_from_slice(d),
            Rdata::UpdateMeta(_) => {}
            Rdata::Unknown(u) => u.to_wire(out)?,
        }
        Ok(())
    }

    /// Canonical wire form (RFC 4034 §6.2): names uncompressed and
    /// lowercased, everything else identical.  Courted by
    /// `DNSSEC-CANONICAL-*`.
    pub fn canonical_wire(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Rdata::A(ip) => out.extend_from_slice(&ip.octets()),
            Rdata::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            Rdata::Name { name, .. } => {
                let lower = Name::from_text_downcase(&name.to_text(), Some(&Name::root()))
                    .map_err(|_| Error::Dnssec)?;
                crate::name::wire::to_wire_uncompressed(&lower, out)?;
            }
            Rdata::Soa(soa) => {
                let mname = canonical_name(&soa.mname);
                let rname = canonical_name(&soa.rname);
                crate::name::wire::to_wire_uncompressed(&mname, out)?;
                crate::name::wire::to_wire_uncompressed(&rname, out)?;
                out.extend_from_slice(&soa.serial.to_be_bytes());
                out.extend_from_slice(&soa.refresh.to_be_bytes());
                out.extend_from_slice(&soa.retry.to_be_bytes());
                out.extend_from_slice(&soa.expire.to_be_bytes());
                out.extend_from_slice(&soa.minimum.to_be_bytes());
            }
            Rdata::PrefName { value, .. } => {
                out.extend_from_slice(&value.preference.to_be_bytes());
                let name = canonical_name(&value.name);
                crate::name::wire::to_wire_uncompressed(&name, out)?;
            }
            Rdata::Srv(srv) => {
                out.extend_from_slice(&srv.priority.to_be_bytes());
                out.extend_from_slice(&srv.weight.to_be_bytes());
                out.extend_from_slice(&srv.port.to_be_bytes());
                let target = canonical_name(&srv.target);
                crate::name::wire::to_wire_uncompressed(&target, out)?;
            }
            Rdata::ChA(ch) => {
                let name = canonical_name(&ch.name);
                crate::name::wire::to_wire_uncompressed(&name, out)?;
                out.extend_from_slice(&ch.addr.to_be_bytes());
            }
            Rdata::TwoNames { value, .. } => {
                let first = canonical_name(&value.first);
                let second = canonical_name(&value.second);
                crate::name::wire::to_wire_uncompressed(&first, out)?;
                crate::name::wire::to_wire_uncompressed(&second, out)?;
            }
            Rdata::Txt { value, .. } => value.to_wire(out)?,
            Rdata::Rrsig(r) => {
                out.extend_from_slice(&r.covered.to_be_bytes());
                out.push(r.algorithm);
                out.push(r.labels);
                out.extend_from_slice(&r.original_ttl.to_be_bytes());
                out.extend_from_slice(&r.expiration.to_be_bytes());
                out.extend_from_slice(&r.time_signed.to_be_bytes());
                out.extend_from_slice(&r.key_tag.to_be_bytes());
                let signer = canonical_name(&r.signer);
                crate::name::wire::to_wire_uncompressed(&signer, out)?;
                out.extend_from_slice(&r.signature);
            }
            Rdata::Sig(r) => {
                out.extend_from_slice(&r.covered.to_be_bytes());
                out.push(r.algorithm);
                out.push(r.labels);
                out.extend_from_slice(&r.original_ttl.to_be_bytes());
                out.extend_from_slice(&r.expiration.to_be_bytes());
                out.extend_from_slice(&r.time_signed.to_be_bytes());
                out.extend_from_slice(&r.key_tag.to_be_bytes());
                let signer = canonical_name(&r.signer);
                crate::name::wire::to_wire_uncompressed(&signer, out)?;
                out.extend_from_slice(&r.signature);
            }
            Rdata::Nsec3(n) => {
                out.push(n.hash);
                out.push(n.flags);
                out.extend_from_slice(&n.iterations.to_be_bytes());
                out.push(n.salt.len() as u8);
                out.extend_from_slice(&n.salt);
                out.push(n.next.len() as u8);
                out.extend_from_slice(&n.next);
                out.extend_from_slice(&n.types);
            }
            Rdata::Tsig(t) => {
                let alg = canonical_name(&t.algorithm);
                crate::name::wire::to_wire_uncompressed(&alg, out)?;
                let hi = ((t.time_signed >> 32) & 0xffff) as u16;
                let lo = (t.time_signed & 0xffff_ffff) as u32;
                out.extend_from_slice(&hi.to_be_bytes());
                out.extend_from_slice(&lo.to_be_bytes());
                out.extend_from_slice(&t.fudge.to_be_bytes());
                out.extend_from_slice(&(t.mac.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.mac);
                out.extend_from_slice(&t.original_id.to_be_bytes());
                out.extend_from_slice(&t.error.to_be_bytes());
                out.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.other);
            }
            Rdata::Tkey(t) => {
                let alg = canonical_name(&t.algorithm);
                crate::name::wire::to_wire_uncompressed(&alg, out)?;
                out.extend_from_slice(&t.inception.to_be_bytes());
                out.extend_from_slice(&t.expiration.to_be_bytes());
                out.extend_from_slice(&t.mode.to_be_bytes());
                out.extend_from_slice(&t.error.to_be_bytes());
                out.extend_from_slice(&(t.key.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.key);
                out.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
                out.extend_from_slice(&t.other);
            }
            Rdata::OptData(d) => out.extend_from_slice(d),
            Rdata::UpdateMeta(_) => {}
            Rdata::Unknown(u) => u.to_wire(out)?,
        }
        Ok(())
    }

    /// Parse RDATA from masterfile text.
    ///
    /// `lex` is the shared masterfile lexer; BIND's per-type `fromtext`
    /// functions read tokens from it.  `origin` resolves relative names.
    ///
    /// Mirrors `dns_rdata_fromtext`: a leading `\#` token selects the
    /// RFC 3597 generic form (valid for any type); otherwise the token is
    /// pushed back and the type-specific parser runs.
    pub fn from_text(type_: RrType, lex: &mut Lexer, origin: Option<&Name>) -> Result<Rdata> {
        let first = lex.next()?;
        if matches!(&first, Token::String(b) if b.as_slice() == b"\\#") {
            // RFC 3597 generic form.  BIND (rdata.c `dns_rdata_fromtext`):
            // for TXT, `\#` is only the generic marker when followed by a
            // NUMBER token; otherwise it is an escaped '#' string
            // (DNS_RDATA_UNKNOWNESCAPE — BIND injects the literal "#"
            // string instead of ungetting, because the lexer pushback is
            // single-slot).  For every other type `\#` is always generic.
            if TXT_TYPES.contains(&type_) {
                let next = lex.next()?;
                if matches!(&next, Token::String(b) if is_pure_number(b)) {
                    lex.unget(next);
                    // Fall through to the generic form with the number as
                    // the length token.
                } else {
                    lex.unget(next);
                    let value = Txt::from_text_prefix(lex, Some(b"#".to_vec()))?;
                    return Ok(Rdata::Txt {
                        type_: type_,
                        value,
                    });
                }
            }
            // BIND unknown_fromtext: type 0 and meta-types are rejected.
            if type_ == RrType::Reserved0 || type_.is_meta() {
                return Err(Error::MetaType);
            }
            let data = UnknownRdata::from_text(lex)?.with_type(type_);
            let r = Self::validate_generic(type_, data)?;
            // The consume-to-eol wrapper applies to the generic form too.
            expect_eof(lex)?;
            return Ok(r);
        }
        lex.unget(first);
        Self::from_text_typed(type_, lex, origin)
    }

    /// Type-specific text parsing (BIND's `FROMTEXTSWITCH`).  Callers must
    /// consume the `\#` generic-marker decision first.
    fn from_text_typed(type_: RrType, lex: &mut Lexer, origin: Option<&Name>) -> Result<Rdata> {
        let r = match type_ {
            RrType::A => {
                let t = lex.next()?;
                let ip = parse_ipv4(t.bytes())?;
                Rdata::A(ip)
            }
            RrType::Aaaa => {
                let t = lex.next()?;
                let ip = parse_ipv6(t.bytes())?;
                Rdata::Aaaa(ip)
            }
            t if SINGLE_NAME_TYPES.contains(&t) => {
                let tok = lex.next()?;
                let name = parse_text_name(&tok, origin)?;
                Rdata::Name { type_: t, name }
            }
            RrType::Soa => {
                let mname_t = lex.next()?;
                let mname = parse_text_name(&mname_t, origin)?;
                let rname_t = lex.next()?;
                let rname = parse_text_name(&rname_t, origin)?;
                let serial = parse_u32_token(lex)?;
                // BIND: refresh/retry/expire/minimum use dns_counter_fromtext
                // (TTL syntax: digits with optional w/d/h/m/s units).
                let refresh = parse_counter_token(lex)?;
                let retry = parse_counter_token(lex)?;
                let expire = parse_counter_token(lex)?;
                let minimum = parse_counter_token(lex)?;
                Rdata::Soa(Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            t if PREF_NAME_TYPES.contains(&t) => {
                let preference: u16 = parse_u16_token(lex)?;
                let name_t = lex.next()?;
                let name = parse_text_name(&name_t, origin)?;
                Rdata::PrefName {
                    type_: t,
                    value: PrefName { preference, name },
                }
            }
            RrType::Srv => {
                let prio = parse_u16_token(lex)?;
                let weight = parse_u16_token(lex)?;
                let port = parse_u16_token(lex)?;
                let name_t = lex.next()?;
                let target = parse_text_name(&name_t, origin)?;
                Rdata::Srv(Srv {
                    priority: prio,
                    weight,
                    port,
                    target,
                })
            }
            t if TWO_NAME_TYPES.contains(&t) => {
                let f = lex.next()?;
                let first = parse_text_name(&f, origin)?;
                let s = lex.next()?;
                let second = parse_text_name(&s, origin)?;
                Rdata::TwoNames {
                    type_: t,
                    value: TwoNames { first, second },
                }
            }
            t if TXT_TYPES.contains(&t) => {
                let value = Txt::from_text(lex)?;
                Rdata::Txt { type_: t, value }
            }
            _ => {
                // No concrete fromtext (meta types included).  BIND returns
                // ISC_R_NOTIMPLEMENTED for the type-specific parse; the
                // METATYPE rejection applies only to the `\#` generic form.
                return Err(Error::NotImplemented);
            }
        };
        // BIND consumes to end-of-line after the type-specific parse and
        // reports any further tokens as DNS_R_EXTRATOKEN.
        expect_eof(lex)?;
        Ok(r)
    }

    /// BIND `rdata_validate` (rdata.c): the generic `\#` form for a KNOWN
    /// type must be valid wire data for that type — a validation failure is
    /// the fromwire error (e.g. `TYPE16 \# 2 00ff` → "unexpected end of
    /// input", oracle-verified), and success yields the concrete record
    /// (rendered with the type's own totext).  Unknown types pass through
    /// opaque.
    fn validate_generic(type_: RrType, data: UnknownRdata) -> Result<Rdata> {
        let wire = data.data();
        let mut pos = 0;
        match Rdata::from_wire(type_, wire, &mut pos, wire.len()) {
            Ok(r) if pos == wire.len() => Ok(r),
            Ok(_) => Err(Error::ExtraData),
            Err(e) => Err(e),
        }
    }

    /// Render RDATA to text in the canonical BIND form (the
    /// `dns_master_style` "default" style, courted by `TEXT-RDATA-*`).
    #[must_use]
    pub fn to_text(&self) -> String {
        self.to_text_filtered(&mut |s| s.to_string())
    }

    /// Like `to_text`, but every name field is passed through `filter`
    /// first — dig's `+idnout` totext filter (dighost.c `idn_filter` via
    /// `dns_name_settotextfilter`) applies to every name in the message,
    /// including names inside RDATA (NS targets, SOA, MX, ...).
    #[must_use]
    pub fn to_text_filtered(&self, filter: &mut dyn FnMut(&str) -> String) -> String {
        match self {
            Rdata::A(ip) => ip.to_string(),
            Rdata::Aaaa(ip) => ip.to_string(),
            Rdata::Name { name, .. } => filter(&name.to_text()),
            Rdata::Soa(soa) => format!(
                "{} {} {} {} {} {} {}",
                filter(&soa.mname.to_text()),
                filter(&soa.rname.to_text()),
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum
            ),
            Rdata::PrefName { value, .. } => {
                format!("{} {}", value.preference, filter(&value.name.to_text()))
            }
            Rdata::Srv(srv) => format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                filter(&srv.target.to_text())
            ),
            Rdata::ChA(ch) => format!("{} {:o}", filter(&ch.name.to_text()), ch.addr),
            Rdata::TwoNames { value, .. } => format!(
                "{} {}",
                filter(&value.first.to_text()),
                filter(&value.second.to_text())
            ),
            Rdata::Txt { value, .. } => value.to_text(),
            Rdata::Rrsig(r) => rrsig_totext(r, false),
            Rdata::Sig(r) => rrsig_totext(r, true),
            Rdata::Nsec3(n) => nsec3_totext(n),
            Rdata::Tsig(t) => tsig_totext(t),
            Rdata::Tkey(t) => tkey_totext(t),
            Rdata::OptData(d) => optdata_totext(d),
            Rdata::UpdateMeta(_) => String::new(),
            Rdata::Unknown(u) => u.to_text(),
        }
    }

    /// BIND `dns_rdata_compare` for the singleton-equality check
    /// (lib/dns/message.c `getsection`): names compare case-insensitively
    /// (`dns_name_rdatacompare`), numeric fields numerically, everything
    /// else by wire-order octets.  Only the singleton types reach this in
    /// message parsing (CNAME, SOA, DNAME, OPT), but the generic fallback
    /// covers the rest.
    #[must_use]
    pub fn bind_compare(&self, other: &Rdata) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self, other) {
            (Rdata::Name { name: a, .. }, Rdata::Name { name: b, .. }) => a.rdatacompare(b),
            (Rdata::Soa(a), Rdata::Soa(b)) => {
                let o = a.mname.rdatacompare(&b.mname);
                if o != Ordering::Equal {
                    return o;
                }
                let o = a.rname.rdatacompare(&b.rname);
                if o != Ordering::Equal {
                    return o;
                }
                a.serial
                    .cmp(&b.serial)
                    .then(a.refresh.cmp(&b.refresh))
                    .then(a.retry.cmp(&b.retry))
                    .then(a.expire.cmp(&b.expire))
                    .then(a.minimum.cmp(&b.minimum))
            }
            (Rdata::OptData(a), Rdata::OptData(b)) => a.cmp(b),
            (Rdata::UpdateMeta(_), Rdata::UpdateMeta(_)) => std::cmp::Ordering::Equal,
            _ => {
                let mut aw = Vec::new();
                let mut bw = Vec::new();
                if self.to_wire(&mut aw, None).is_err() || other.to_wire(&mut bw, None).is_err() {
                    return Ordering::Equal;
                }
                aw.cmp(&bw)
            }
        }
    }
}

/// Whether BIND has a concrete rdata implementation for `type_` in this
/// class (the class-gated `dns_rdata_fromwire`/`totext` dispatch).
/// Class-gated types: A (IN/CH/HS), WKS/NSAP/NSAP-PTR/PX/AAAA/EID/NIMLOC/
/// SRV/ATMA/KX/A6/APL/DHCID/SVCB/HTTPS (IN only), TSIG (ANY only).
pub(crate) fn rrtype_native_class(type_: RrType, class: Class) -> bool {
    match type_ {
        RrType::A => matches!(class, Class::In | Class::Ch | Class::Hs),
        RrType::Tsig => class == Class::Any,
        RrType::Wks
        | RrType::Nsap
        | RrType::NsapPtr
        | RrType::Px
        | RrType::Aaaa
        | RrType::Eid
        | RrType::Nimloc
        | RrType::Srv
        | RrType::Atma
        | RrType::Kx
        | RrType::A6
        | RrType::Apl
        | RrType::Dhcid
        | RrType::Svcb
        | RrType::Https => class == Class::In,
        _ => true,
    }
}

/// Parse a name inside RDATA: starts at `pos`, must terminate at or before
/// `end`.  Returns (name, new_pos).
fn parse_rdata_name(buf: &[u8], pos: usize, end: usize) -> Result<(Name, usize)> {
    if pos >= end {
        return Err(Error::UnexpectedEnd);
    }
    let fw = crate::name::wire::from_wire(buf, pos, true)?;
    if fw.consumed > end {
        return Err(Error::FormErr);
    }
    Ok((fw.name, fw.consumed))
}

fn render_rdata_name(
    out: &mut Vec<u8>,
    name: &Name,
    mut comp: Option<&mut Compressor>,
    compress: bool,
) -> Result<()> {
    match comp.as_deref_mut() {
        Some(c) => {
            if compress {
                c.render(name, out);
            } else {
                // BIND's towire for the type sets the decompression
                // context to not-permitted: the name is written in full but
                // the compression table still gains it (dns_compress_name
                // always runs).  The permitted flag is restored afterwards
                // so the next owner-name render behaves as BIND's
                // per-record `dns_compress_setpermitted(cctx, true)`.
                let saved = c.is_permitted();
                c.set_permitted(false);
                c.render(name, out);
                c.set_permitted(saved);
            }
        }
        None => crate::name::wire::to_wire_uncompressed(name, out)?,
    }
    Ok(())
}

/// Whether BIND's towire for this type compresses its embedded names
/// (the type's towire calls `dns_compress_setpermitted(cctx, true)`;
/// everything else renders rdata names uncompressed — RP, SRV, KX, AFSDB,
/// RT, PX, NAPTR, A6, NXT, NSEC, NSAP-PTR, DNAME, RRSIG, SIG, TSIG, TKEY,
/// TALINK, SVCB, DSYNC set it false in 9.20.26).
pub(crate) fn rdata_towire_compresses(type_: RrType) -> bool {
    matches!(
        type_,
        RrType::A
            | RrType::Ns
            | RrType::Md
            | RrType::Mf
            | RrType::Cname
            | RrType::Mb
            | RrType::Mg
            | RrType::Mr
            | RrType::Ptr
            | RrType::Soa
            | RrType::Mx
            | RrType::Minfo
    )
}

fn canonical_name(name: &Name) -> Name {
    // RFC 4034 §6.2: DNS names in canonical form are lowercased.
    match Name::from_text_downcase(&name.to_text(), Some(&Name::root())) {
        Ok(n) => n,
        Err(_) => name.clone(),
    }
}

// ---------------------------------------------------------------------------
// RRSIG / SIG (lib/dns/rdata/generic/rrsig_46.c, sig_24.c, 9.20.26)
// ---------------------------------------------------------------------------

/// Parse an RRSIG (`is_rrsig = true`) or SIG (`false`) record.
///
/// BIND `fromwire_rrsig`/`fromwire_sig`: 18 fixed octets, then the signer
/// name with compression *disallowed*, then the signature.  The two differ
/// in the label-count check (RRSIG only) and the empty-signature result
/// (RRSIG: `DNS_R_FORMERR`; SIG: `ISC_R_UNEXPECTEDEND`).
fn rrsig_from_wire(buf: &[u8], pos: usize, end: usize, is_rrsig: bool) -> Result<Rrsig> {
    if end - pos < 18 {
        return Err(Error::UnexpectedEnd);
    }
    let covered = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let algorithm = buf[pos + 2];
    let labels = buf[pos + 3];
    let original_ttl = rd_u32(buf, pos + 4);
    let expiration = rd_u32(buf, pos + 8);
    let time_signed = rd_u32(buf, pos + 12);
    let key_tag = u16::from_be_bytes([buf[pos + 16], buf[pos + 17]]);
    let mut p = pos + 18;
    // The message-parse decompression context is DNS_DECOMPRESS_ALWAYS, so
    // `dns_decompress_setpermitted(dctx, false)` inside fromwire_rrsig is a
    // no-op: the signer may use compression pointers (resolved against the
    // whole message) but is bounded by the rdlength region.
    if p >= end {
        return Err(Error::UnexpectedEnd);
    }
    let fw = crate::name::wire::from_wire_bounded(buf, p, end, true)?;
    p = fw.consumed;
    if is_rrsig && (labels as usize + 1) < fw.name.label_count() {
        return Err(Error::FormErr);
    }
    let signature = &buf[p..end];
    if signature.is_empty() {
        return Err(if is_rrsig {
            Error::FormErr
        } else {
            Error::UnexpectedEnd
        });
    }
    Ok(Rrsig {
        covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        time_signed,
        key_tag,
        signer: fw.name,
        signature: signature.to_vec(),
    })
}

/// BIND `towire_rrsig`/`towire_sig`: the fixed 18 octets, the signer
/// (compression not permitted — BIND sets the context false, so the name
/// is written in full but still enters the compression table), then the
/// signature verbatim.
fn rrsig_to_wire(r: &Rrsig, out: &mut Vec<u8>, comp: Option<&mut Compressor>) -> Result<()> {
    out.extend_from_slice(&r.covered.to_be_bytes());
    out.push(r.algorithm);
    out.push(r.labels);
    out.extend_from_slice(&r.original_ttl.to_be_bytes());
    out.extend_from_slice(&r.expiration.to_be_bytes());
    out.extend_from_slice(&r.time_signed.to_be_bytes());
    out.extend_from_slice(&r.key_tag.to_be_bytes());
    render_rdata_name(out, &r.signer, comp, false)?;
    out.extend_from_slice(&r.signature);
    Ok(())
}

/// The covered type of an RRSIG/SIG record — BIND `dns_rdata_covers`.
#[must_use]
pub fn rrsig_covers(r: &Rrsig) -> u16 {
    r.covered
}

/// `dns_rdata_totext` for RRSIG (covered mnemonic, `TYPE%u` fallback) and
/// SIG (covered mnemonic, plain `%u` fallback).  The style is the
/// single-line default: flags 0, width 60, linebreak " " — so the base64
/// signature splits into 60-character words (BIND's `width - 2 = 58`
/// threshold fires at 60).
fn rrsig_totext(r: &Rrsig, is_sig: bool) -> String {
    let mut s = String::new();
    let covered = r.covered;
    if covered != 0 && rrtype_known(covered) {
        s.push_str(&RrType::from_u16(covered).to_text());
    } else if is_sig {
        s.push_str(&covered.to_string());
    } else {
        s.push_str(&format!("TYPE{covered}"));
    }
    s.push_str(&format!(
        " {} {} {} {} {} {} {}",
        r.algorithm,
        r.labels,
        r.original_ttl,
        time32_totext(r.expiration),
        time32_totext(r.time_signed),
        r.key_tag,
        r.signer.to_text()
    ));
    s.push(' ');
    s.push_str(&base64_bind(&r.signature, 60, " "));
    s
}

// ---------------------------------------------------------------------------
// NSEC3 (lib/dns/rdata/generic/nsec3_50.c, 9.20.26)
// ---------------------------------------------------------------------------

/// BIND `fromwire_nsec3`: fixed fields, salt, next-hash (length checked
/// against the hash algorithm), then a validated type bitmap.
fn nsec3_from_wire(buf: &[u8], pos: usize, end: usize) -> Result<Nsec3> {
    if end - pos < 5 {
        return Err(Error::FormErr);
    }
    let hash = buf[pos];
    let flags = buf[pos + 1];
    let iterations = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    let saltlen = buf[pos + 4] as usize;
    let mut p = pos + 5;
    if end - p < saltlen {
        return Err(Error::FormErr);
    }
    let salt = buf[p..p + saltlen].to_vec();
    p += saltlen;
    if end - p < 1 {
        return Err(Error::FormErr);
    }
    let hashlen = buf[p] as usize;
    p += 1;
    match hash {
        1 => {
            // SHA-1: exactly 20 octets.
            if hashlen != 20 || end - p < hashlen {
                return Err(Error::FormErr);
            }
        }
        _ => {
            if hashlen < 1 || hashlen > NSEC3_MAX_HASH_LENGTH || end - p < hashlen {
                return Err(Error::FormErr);
            }
        }
    }
    let next = buf[p..p + hashlen].to_vec();
    p += hashlen;
    let types = buf[p..end].to_vec();
    typemap_validate(&types)?;
    Ok(Nsec3 {
        hash,
        flags,
        iterations,
        salt,
        next,
        types,
    })
}

/// BIND `typemap_test(sr, allow_empty = true)` for NSEC3: window blocks in
/// strictly increasing window order, length 1..=32, last bitmap octet
/// nonzero, exact consumption.  An empty bitmap is allowed for NSEC3.
fn typemap_validate(types: &[u8]) -> Result<()> {
    let mut i = 0usize;
    let mut lastwindow = 0u16;
    let mut first = true;
    while i < types.len() {
        if i + 2 > types.len() {
            return Err(Error::FormErr);
        }
        let window = types[i] as u16;
        let len = types[i + 1] as usize;
        i += 2;
        if !first && window <= lastwindow {
            return Err(Error::FormErr);
        }
        if len < 1 || len > 32 {
            return Err(Error::FormErr);
        }
        if i + len > types.len() {
            return Err(Error::FormErr);
        }
        if types[i + len - 1] == 0 {
            return Err(Error::FormErr);
        }
        lastwindow = window;
        first = false;
        i += len;
    }
    Ok(())
}

/// BIND `dns_rdata_checkowner` for NSEC3: the first label must decode as
/// unpadded base32hex (`isc_base32hexnp_decoderegion`).
#[must_use]
pub fn nsec3_owner_ok(name: &Name) -> bool {
    let wire = name.as_wire_slice();
    if wire.is_empty() {
        return false;
    }
    let len = wire[0] as usize;
    if len == 0 || len > wire.len() - 1 {
        return false;
    }
    let label = &wire[1..1 + len];
    base32hex_np_decode_valid(label)
}

/// BIND `isc_base32hexnp_decoderegion` validity: characters from the
/// base32hex alphabet (0-9A-Va-v — BIND's table carries an uppercase and a
/// lowercase copy), length mod 8 in {0, 2, 4, 5, 7}, and the trailing pad
/// bits zero.
fn base32hex_np_decode_valid(s: &[u8]) -> bool {
    if s.is_empty() {
        return true; // zero bytes decode fine
    }
    let mut vals = [0u8; 64];
    let mut n = 0usize;
    for &c in s {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'V' => c - b'A' + 10,
            b'a'..=b'v' => c - b'a' + 10,
            _ => return false,
        };
        vals[n] = v;
        n += 1;
        if n >= vals.len() {
            return false;
        }
    }
    let rem = n % 8;
    match rem {
        0 => true,
        2 => vals[n - 1] & 0x03 == 0,
        4 => vals[n - 1] & 0x0f == 0,
        5 => vals[n - 1] & 0x01 == 0,
        7 => vals[n - 1] & 0x07 == 0,
        _ => false,
    }
}

/// BIND `isc_base32hexnp_totext`: base32hex with the padding stripped.
fn base32hex_np(data: &[u8]) -> String {
    const HEX32: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut i = 0usize;
    while data.len() - i >= 5 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        let b3 = data[i + 3];
        let b4 = data[i + 4];
        out.push(HEX32[((b0 >> 3) & 0x1f) as usize] as char);
        out.push(HEX32[(((b0 << 2) & 0x1c) | ((b1 >> 6) & 0x03)) as usize] as char);
        out.push(HEX32[((b1 >> 1) & 0x1f) as usize] as char);
        out.push(HEX32[(((b1 << 4) & 0x10) | ((b2 >> 4) & 0x0f)) as usize] as char);
        out.push(HEX32[(((b2 << 1) & 0x1e) | ((b3 >> 7) & 0x01)) as usize] as char);
        out.push(HEX32[((b3 >> 2) & 0x1f) as usize] as char);
        out.push(HEX32[(((b3 << 3) & 0x18) | ((b4 >> 5) & 0x07)) as usize] as char);
        out.push(HEX32[(b4 & 0x1f) as usize] as char);
        i += 5;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b0 = data[i];
        out.push(HEX32[((b0 >> 3) & 0x1f) as usize] as char);
        out.push(HEX32[((b0 << 2) & 0x1c) as usize] as char);
    } else if rem == 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        out.push(HEX32[((b0 >> 3) & 0x1f) as usize] as char);
        out.push(HEX32[(((b0 << 2) & 0x1c) | ((b1 >> 6) & 0x03)) as usize] as char);
        out.push(HEX32[((b1 >> 1) & 0x1f) as usize] as char);
        out.push(HEX32[((b1 << 4) & 0x10) as usize] as char);
    } else if rem == 3 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        out.push(HEX32[((b0 >> 3) & 0x1f) as usize] as char);
        out.push(HEX32[(((b0 << 2) & 0x1c) | ((b1 >> 6) & 0x03)) as usize] as char);
        out.push(HEX32[((b1 >> 1) & 0x1f) as usize] as char);
        out.push(HEX32[(((b1 << 4) & 0x10) | ((b2 >> 4) & 0x0f)) as usize] as char);
        out.push(HEX32[((b2 << 1) & 0x1e) as usize] as char);
    } else if rem == 4 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        let b3 = data[i + 3];
        out.push(HEX32[((b0 >> 3) & 0x1f) as usize] as char);
        out.push(HEX32[(((b0 << 2) & 0x1c) | ((b1 >> 6) & 0x03)) as usize] as char);
        out.push(HEX32[((b1 >> 1) & 0x1f) as usize] as char);
        out.push(HEX32[(((b1 << 4) & 0x10) | ((b2 >> 4) & 0x0f)) as usize] as char);
        out.push(HEX32[(((b2 << 1) & 0x1e) | ((b3 >> 7) & 0x01)) as usize] as char);
        out.push(HEX32[((b3 >> 2) & 0x1f) as usize] as char);
        out.push(HEX32[((b3 << 3) & 0x18) as usize] as char);
    }
    out
}

/// BIND `typemap_totext`: type mnemonics space-separated.
fn typemap_totext(types: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    let mut first = true;
    while i < types.len() {
        let window = types[i] as u16;
        let len = types[i + 1] as usize;
        i += 2;
        for j in 0..len {
            let byte = types[i + j];
            if byte == 0 {
                continue;
            }
            for k in 0..8u16 {
                if byte & (0x80 >> k) == 0 {
                    continue;
                }
                let t = window * 256 + (j as u16) * 8 + k;
                if !first {
                    out.push(' ');
                }
                first = false;
                out.push_str(&rrtype_known_totext(t));
            }
        }
        i += len;
    }
    out
}

/// BIND `dns_rdatatype_isknown`: no `UNKNOWN` attribute.  Type 0 is
/// unknown in BIND's tables (it prints as `TYPE0`).
fn rrtype_known(t: u16) -> bool {
    t != 0 && !matches!(RrType::from_u16(t), RrType::Unknown(_))
}

/// BIND `dns_rdatatype_totext`: the mnemonic when known, else `TYPE%u`.
fn rrtype_known_totext(t: u16) -> String {
    if rrtype_known(t) {
        RrType::from_u16(t).to_text()
    } else {
        format!("TYPE{t}")
    }
}

/// BIND `dns_time32_totext`: civil time from the Unix epoch, formatted
/// `YYYYMMDDHHMMSS`.
fn time32_totext(t: u32) -> String {
    let days = i64::from(t) / 86400;
    let secs = i64::from(t) % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Days-since-epoch → (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's algorithm; identical to BIND's year-walk for
/// the u32 epoch range).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// BIND `isc_base64_totext` (9.20.26): 4 chars per 3 octets, a break after
/// `wordlength` chars when more data remains (the check fires at
/// `(loops + 1) * 4 >= wordlength`, so with wordlength 58 the words are
/// 60 chars), standard `=` padding.  `wordlength < 4` clamps to 4.
fn base64_bind(data: &[u8], wordlength: usize, wordbreak: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let wl = wordlength.max(4);
    let mut out = String::new();
    let mut i = 0usize;
    let mut loops = 0usize;
    while data.len() - i > 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        out.push(B64[((b0 >> 2) & 0x3f) as usize] as char);
        out.push(B64[(((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)) as usize] as char);
        out.push(B64[(((b1 << 2) & 0x3c) | ((b2 >> 6) & 0x03)) as usize] as char);
        out.push(B64[(b2 & 0x3f) as usize] as char);
        i += 3;
        loops += 1;
        if data.len() - i != 0 && (loops + 1) * 4 >= wl {
            loops = 0;
            out.push_str(wordbreak);
        }
    }
    if data.len() - i == 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        out.push(B64[((b0 >> 2) & 0x3f) as usize] as char);
        out.push(B64[(((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)) as usize] as char);
        out.push(B64[((b1 << 2) & 0x3c) as usize] as char);
        out.push('=');
    } else if data.len() - i == 1 {
        let b0 = data[i];
        out.push(B64[((b0 >> 2) & 0x3f) as usize] as char);
        out.push(B64[((b0 << 4) & 0x30) as usize] as char);
        out.push('=');
        out.push('=');
    }
    out
}

/// BIND `isc_hex_totext` with an empty break: continuous uppercase hex.
fn hex_upper(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    data.iter()
        .map(|b| {
            format!(
                "{}{}",
                HEX[(b >> 4) as usize] as char,
                HEX[(b & 0xf) as usize] as char
            )
        })
        .collect()
}

/// BIND `dns_mnemonic_totext` over the TSIG error table (`tsigrcodes[]` =
/// RCODENAMES + TSIGRCODENAMES) — see [`crate::rcode::tsigrcode_to_text`].
fn tsigrcode_totext(n: u16) -> String {
    crate::rcode::tsigrcode_to_text(n)
}

// ---------------------------------------------------------------------------
// TSIG (lib/dns/rdata/any_255/tsig_250.c, 9.20.26)
// ---------------------------------------------------------------------------

/// BIND `fromwire_any_tsig`: algorithm name, 48-bit time + fudge, MAC,
/// original ID + error, other data.  Returns the consumed position so the
/// caller's trailing-octet check (DNS_R_EXTRADATA) fires for leftovers.
fn tsig_from_wire(buf: &[u8], pos: usize, end: usize) -> Result<(Tsig, usize)> {
    let mut p = pos;
    if p >= end {
        return Err(Error::UnexpectedEnd);
    }
    let fw = crate::name::wire::from_wire_bounded(buf, p, end, true)?;
    p = fw.consumed;
    if end - p < 8 {
        return Err(Error::UnexpectedEnd);
    }
    let time_signed = (u64::from(u16::from_be_bytes([buf[p], buf[p + 1]])) << 32)
        | u64::from(u32::from_be_bytes([
            buf[p + 2],
            buf[p + 3],
            buf[p + 4],
            buf[p + 5],
        ]));
    let fudge = u16::from_be_bytes([buf[p + 6], buf[p + 7]]);
    p += 8;
    if end - p < 2 {
        return Err(Error::UnexpectedEnd);
    }
    let maclen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if end - p < maclen {
        return Err(Error::UnexpectedEnd);
    }
    let mac = buf[p..p + maclen].to_vec();
    p += maclen;
    if end - p < 4 {
        return Err(Error::UnexpectedEnd);
    }
    let original_id = u16::from_be_bytes([buf[p], buf[p + 1]]);
    let error = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
    p += 4;
    if end - p < 2 {
        return Err(Error::UnexpectedEnd);
    }
    let otherlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if end - p < otherlen {
        return Err(Error::UnexpectedEnd);
    }
    let other = buf[p..p + otherlen].to_vec();
    p += otherlen;
    Ok((
        Tsig {
            algorithm: fw.name,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        },
        p,
    ))
}

/// BIND `totext_any_tsig` (single-line style: width 60, linebreak " "):
/// `alg time fudge macsize [mac] origid tsigrcode othersize other`.  The
/// MAC splits at 58 (60 actual) and the other data at 60.
fn tsig_totext(t: &Tsig) -> String {
    let mut s = format!(
        "{} {} {} {}",
        t.algorithm.to_text(),
        t.time_signed,
        t.fudge,
        t.mac.len()
    );
    if !t.mac.is_empty() {
        s.push(' ');
        s.push_str(&base64_bind(&t.mac, 58, " "));
        s.push(' ');
    } else {
        s.push(' ');
    }
    s.push_str(&format!("{} {}", t.original_id, tsigrcode_totext(t.error)));
    s.push_str(&format!(" {} ", t.other.len()));
    s.push_str(&base64_bind(&t.other, 60, " "));
    s
}

// ---------------------------------------------------------------------------
// TKEY (lib/dns/rdata/generic/tkey_249.c, 9.20.26)
// ---------------------------------------------------------------------------

/// BIND `fromwire_tkey`: algorithm name, inception/expiration/mode/error,
/// key data, other data.  Returns the consumed position so the caller's
/// trailing-octet check (DNS_R_EXTRADATA) fires for leftovers.
fn tkey_from_wire(buf: &[u8], pos: usize, end: usize) -> Result<(Tkey, usize)> {
    let mut p = pos;
    if p >= end {
        return Err(Error::UnexpectedEnd);
    }
    let fw = crate::name::wire::from_wire_bounded(buf, p, end, true)?;
    p = fw.consumed;
    if end - p < 12 {
        return Err(Error::UnexpectedEnd);
    }
    let inception = rd_u32(buf, p);
    let expiration = rd_u32(buf, p + 4);
    let mode = u16::from_be_bytes([buf[p + 8], buf[p + 9]]);
    let error = u16::from_be_bytes([buf[p + 10], buf[p + 11]]);
    p += 12;
    if end - p < 2 {
        return Err(Error::UnexpectedEnd);
    }
    let keylen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if end - p < keylen {
        return Err(Error::UnexpectedEnd);
    }
    let key = buf[p..p + keylen].to_vec();
    p += keylen;
    if end - p < 2 {
        return Err(Error::UnexpectedEnd);
    }
    let otherlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if end - p < otherlen {
        return Err(Error::UnexpectedEnd);
    }
    let other = buf[p..p + otherlen].to_vec();
    p += otherlen;
    Ok((
        Tkey {
            algorithm: fw.name,
            inception,
            expiration,
            mode,
            error,
            key,
            other,
        },
        p,
    ))
}

/// BIND `totext_tkey` (single-line style): `alg inception expiration mode
/// tsigrcode keysize [key] othersize [other]`; the binary fields split at
/// 58 (60 actual) with " ".  BIND emits the linebreak and a trailing space
/// around the key data unconditionally, so an empty key leaves two spaces
/// between the size fields.
fn tkey_totext(t: &Tkey) -> String {
    let mut s = format!(
        "{} {} {} {} {} {}",
        t.algorithm.to_text(),
        t.inception,
        t.expiration,
        t.mode,
        tsigrcode_totext(t.error),
        t.key.len()
    );
    s.push(' ');
    s.push_str(&base64_bind(&t.key, 58, " "));
    s.push(' ');
    s.push_str(&t.other.len().to_string());
    if !t.other.is_empty() {
        s.push(' ');
        s.push_str(&base64_bind(&t.other, 58, " "));
    }
    s
}

/// The NSEC3 next-hash length bound (BIND `NSEC3_MAX_HASH_LENGTH`).
pub const NSEC3_MAX_HASH_LENGTH: usize = 39;

/// BIND `totext_opt` (lib/dns/rdata/generic/opt_41.c), single-line style:
/// per option `code len` followed by the payload as base64 splitting at 58
/// (60 actual) with " ".
fn optdata_totext(data: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    let mut first = true;
    while i < data.len() {
        let code = u16::from_be_bytes([data[i], data[i + 1]]);
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if !first {
            s.push(' ');
        }
        first = false;
        s.push_str(&format!("{code} {len}"));
        if len > 0 {
            s.push(' ');
            s.push_str(&base64_bind(&data[i..i + len], 58, " "));
        }
        i += len;
    }
    s
}

/// Render NSEC3 to text (single-line style): `hash flags iterations salt
/// next typemap` with the salt as uppercase hex (`-` when empty) and the
/// next hash as unpadded base32hex.
fn nsec3_totext(n: &Nsec3) -> String {
    let mut s = format!("{} {} {} ", n.hash, n.flags, n.iterations);
    if n.salt.is_empty() {
        s.push('-');
    } else {
        s.push_str(&hex_upper(&n.salt));
    }
    s.push(' ');
    s.push_str(&base32hex_np(&n.next));
    if !n.types.is_empty() {
        s.push(' ');
        s.push_str(&typemap_totext(&n.types));
    }
    s
}

fn rd_u16(buf: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([buf[pos], buf[pos + 1]])
}

fn rd_u32(buf: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
}

fn parse_text_name(token: &Token, origin: Option<&Name>) -> Result<Name> {
    // BIND: getmastertoken(isc_tokentype_string) at end-of-line fails with
    // ISC_R_UNEXPECTEDEND (a missing field is not a valid name).
    if matches!(token, Token::Eof) {
        return Err(Error::UnexpectedEnd);
    }
    let s = std::str::from_utf8(token.bytes()).map_err(|_| Error::BadData)?;
    Name::from_text(s, origin)
}

/// BIND's consume-to-end-of-line check (`dns_rdata_fromtext`): any token
/// after the parsed fields is DNS_R_EXTRATOKEN ("extra input text").
fn expect_eof(lex: &mut Lexer) -> Result<()> {
    match lex.next()? {
        Token::Eof => Ok(()),
        _ => Err(Error::ExtraToken),
    }
}

/// Is every byte an ASCII digit (BIND's number tokens are digit-only; the
/// lexer classifies anything else as a string, and a required number token
/// then fails with ISC_R_BADNUMBER)?
fn is_pure_number(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}

/// Parse a required NUMBER token (BIND `isc_tokentype_number`): digit-only,
/// overflow past the 32-bit range is ISC_R_RANGE, anything else is
/// ISC_R_BADNUMBER.
fn parse_u32_token(lex: &mut Lexer) -> Result<u32> {
    let t = lex.next()?;
    if matches!(t, Token::Eof) {
        // BIND getmastertoken at end-of-line: ISC_R_UNEXPECTEDEND.
        return Err(Error::UnexpectedEnd);
    }
    let b = t.bytes();
    if !is_pure_number(b) {
        return Err(Error::BadNumber);
    }
    let s = std::str::from_utf8(b).map_err(|_| Error::BadNumber)?;
    s.parse().map_err(|_| Error::Range)
}

/// Like [`parse_u32_token`] but for the 16-bit fields (MX preference, SRV
/// priority/weight/port; BIND checks `as_ulong > 0xffff` → ISC_R_RANGE).
fn parse_u16_token(lex: &mut Lexer) -> Result<u16> {
    let t = lex.next()?;
    if matches!(t, Token::Eof) {
        return Err(Error::UnexpectedEnd);
    }
    let b = t.bytes();
    if !is_pure_number(b) {
        return Err(Error::BadNumber);
    }
    let s = std::str::from_utf8(b).map_err(|_| Error::BadNumber)?;
    let v: u32 = s.parse().map_err(|_| Error::Range)?;
    u16::try_from(v).map_err(|_| Error::Range)
}

/// Parse a counter field (BIND `dns_counter_fromtext` → `bind_ttl`,
/// lib/dns/ttl.c): digit groups with optional unit letters `w d h m s`;
/// a plain number is seconds.  A missing field is ISC_R_UNEXPECTEDEND; a
/// non-digit start is DNS_R_SYNTAX; a digit group overflowing 32 bits is
/// DNS_R_SYNTAX (per-group `isc_parse_uint32` failure); the summed total
/// overflowing 32 bits is ISC_R_RANGE.
fn parse_counter_token(lex: &mut Lexer) -> Result<u32> {
    let t = lex.next()?;
    if matches!(t, Token::Eof) {
        return Err(Error::UnexpectedEnd);
    }
    let s = std::str::from_utf8(t.bytes()).map_err(|_| Error::Syntax)?;
    let b = s.as_bytes();
    let mut i = 0;
    let mut total: u64 = 0;
    let mut saw_unit = false;
    loop {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return Err(Error::Syntax);
        }
        let n: u32 = s[start..i].parse().map_err(|_| Error::Syntax)?;
        match b.get(i) {
            Some(b'w' | b'W') => {
                total += u64::from(n) * 7 * 24 * 3600;
                saw_unit = true;
                i += 1;
            }
            Some(b'd' | b'D') => {
                total += u64::from(n) * 24 * 3600;
                saw_unit = true;
                i += 1;
            }
            Some(b'h' | b'H') => {
                total += u64::from(n) * 3600;
                saw_unit = true;
                i += 1;
            }
            Some(b'm' | b'M') => {
                total += u64::from(n) * 60;
                saw_unit = true;
                i += 1;
            }
            Some(b's' | b'S') => {
                total += u64::from(n);
                saw_unit = true;
                i += 1;
            }
            Some(_) => return Err(Error::Syntax),
            None => {
                // A trailing plain number is only legal when no units were
                // seen (BIND: `case '\0': if (tmp != 0) SYNTAX;`).
                if saw_unit {
                    return Err(Error::Syntax);
                }
                total = u64::from(n);
            }
        }
        if i >= b.len() {
            break;
        }
    }
    u32::try_from(total).map_err(|_| Error::Range)
}

/// Strict dotted-quad parser with `inet_pton(AF_INET)` semantics: exactly
/// four decimal parts, no leading zeros (a lone "0" is allowed), each ≤
/// 255.  (Rust's `Ipv4Addr::from_str` is not equivalent — it accepts
/// forms inet_pton rejects.)
fn parse_ipv4(bytes: &[u8]) -> Result<Ipv4Addr> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::BadDottedQuad)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::BadDottedQuad);
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty()
            || p.len() > 3
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return Err(Error::BadDottedQuad);
        }
        let v: u16 = p.parse().map_err(|_| Error::BadDottedQuad)?;
        if v > 255 {
            return Err(Error::BadDottedQuad);
        }
        octets[i] = v as u8;
    }
    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// IPv6 address parse (BIND `inet_pton(AF_INET6)`; failures are
/// DNS_R_BADAAAAA).  Rust's parser follows the standard textual form.
fn parse_ipv6(bytes: &[u8]) -> Result<Ipv6Addr> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::BadIpv6)?;
    s.parse().map_err(|_| Error::BadIpv6)
}

/// Character-string escaping used by TXT and friends — BIND's
/// `commatxt_totext` with `quote = true` (rdata.c): `"` and `\` are
/// backslash-escaped, octets outside 0x20..=0x7e use `\DDD` **decimal**
/// digits, and the space itself is literal inside quotes.
pub(crate) fn escape_char_string(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for &b in s {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                out.push('\\');
                out.push(char::from(b'0' + (b / 100)));
                out.push(char::from(b'0' + ((b / 10) % 10)));
                out.push(char::from(b'0' + (b % 10)));
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::lexer::Lexer;

    fn name(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

    fn lex(s: &str) -> Lexer<'_> {
        Lexer::new(s.as_bytes())
    }

    #[test]
    fn a_wire_roundtrip() {
        let r = Rdata::A("192.0.2.1".parse().unwrap());
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        assert_eq!(out, [192, 0, 2, 1]);
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::A, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
        assert_eq!(parsed.to_text(), "192.0.2.1");
    }

    #[test]
    fn a_wrong_length_rejected() {
        let mut pos = 0;
        assert!(Rdata::from_wire(RrType::A, &[1, 2, 3], &mut pos, 3).is_err());
    }

    #[test]
    fn aaaa_wire_roundtrip() {
        let r = Rdata::Aaaa("2001:db8::1".parse().unwrap());
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        assert_eq!(out.len(), 16);
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::Aaaa, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
        assert_eq!(parsed.to_text(), "2001:db8::1");
    }

    #[test]
    fn ns_wire_roundtrip_with_compression() {
        // One compressor + one buffer per message, exactly as in BIND
        // (sharing a cctx across two buffers is never valid: recorded
        // offsets refer to one buffer).
        let mut msg = Vec::new();
        let mut comp = Compressor::new();
        // First render the origin name in a "question-like" position.
        comp.render(&name("example.com."), &mut msg);
        let r = Rdata::Name {
            type_: RrType::Ns,
            name: name("ns1.example.com."),
        };
        r.to_wire(&mut msg, Some(&mut comp)).unwrap();
        // The "example.com." entry at offset 0 is invisible (coff == 0 is
        // the empty-slot sentinel), so ns1 compresses only the "com."
        // suffix at offset 8 — oracle-verified byte sequence (RENDER-
        // COMPRESS-0001; in a real message offset 0 is the header and
        // a pointer to it is impossible).
        assert_eq!(
            &msg[13..],
            &[3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xc0, 0x08,]
        );
        // Parse the rdata back from the full message buffer.
        let mut pos = 13;
        let parsed = Rdata::from_wire(RrType::Ns, &msg, &mut pos, msg.len()).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn soa_text_and_wire() {
        let r = Rdata::from_text(
            RrType::Soa,
            &mut lex("ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300"),
            Some(&name("example.com.")),
        )
        .unwrap();
        assert_eq!(
            r.to_text(),
            "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300"
        );
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::Soa, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn soa_relative_names_resolve() {
        let r = Rdata::from_text(
            RrType::Soa,
            &mut lex("ns1 hostmaster 1 2 3 4 5"),
            Some(&name("example.com.")),
        )
        .unwrap();
        assert_eq!(
            r.to_text(),
            "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"
        );
    }

    #[test]
    fn mx_text_and_wire() {
        let r = Rdata::from_text(
            RrType::Mx,
            &mut lex("10 mail.example.com."),
            Some(&name("example.com.")),
        )
        .unwrap();
        assert_eq!(r.to_text(), "10 mail.example.com.");
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::Mx, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn srv_text_and_wire() {
        let r = Rdata::from_text(
            RrType::Srv,
            &mut lex("0 5 443 target.example.com."),
            Some(&name("example.com.")),
        )
        .unwrap();
        assert_eq!(r.to_text(), "0 5 443 target.example.com.");
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::Srv, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn txt_multiple_strings() {
        let r = Rdata::from_text(RrType::Tx, &mut lex("\"hello\" \"world\""), None).unwrap();
        assert_eq!(r.to_text(), "\"hello\" \"world\"");
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        assert_eq!(
            out,
            [5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd']
        );
        let mut pos = 0;
        let parsed = Rdata::from_wire(RrType::Tx, &out, &mut pos, out.len()).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn unknown_generic_text() {
        let r = Rdata::from_text(RrType::Unknown(65000), &mut lex(r"\# 4 01020304"), None).unwrap();
        assert_eq!(r.to_text(), r"\# 4 01020304");
        let mut out = Vec::new();
        r.to_wire(&mut out, None).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn canonical_lowercases_names() {
        let r = Rdata::Name {
            type_: RrType::Ns,
            name: name("NS1.EXAMPLE.COM."),
        };
        let mut out = Vec::new();
        r.canonical_wire(&mut out).unwrap();
        assert_eq!(out, b"\x03ns1\x07example\x03com\x00");
    }

    #[test]
    fn canonical_matches_normal_for_lowercase() {
        let r = Rdata::Name {
            type_: RrType::Ns,
            name: name("ns1.example.com."),
        };
        let mut canon = Vec::new();
        r.canonical_wire(&mut canon).unwrap();
        let mut plain = Vec::new();
        r.to_wire(&mut plain, None).unwrap();
        assert_eq!(canon, plain);
    }

    #[test]
    fn rdata_length_mismatch_rejected() {
        // A MX with trailing garbage after the name: BIND's fromwire
        // reports DNS_R_EXTRADATA ("extra input data").
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.extend_from_slice(b"\x03com\x00");
        buf.push(0xde); // trailing byte
        let mut pos = 0;
        assert_eq!(
            Rdata::from_wire(RrType::Mx, &buf, &mut pos, buf.len()).map(|_| ()),
            Err(Error::ExtraData)
        );
    }
}
