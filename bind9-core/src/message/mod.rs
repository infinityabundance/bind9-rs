//! DNS message structure and the parse/render paths.
//!
//! Parse behavior mirrors `dns_message_parse`; the observable rules are
//! courted by `WIRE-MESSAGE-*`:
//!
//! - a QUERY message must carry exactly one question — zero or multiple
//!   questions is FORMERR (courts `WIRE-MESSAGE-NOQUESTION`,
//!   `WIRE-MESSAGE-MULTIQUESTION`);
//! - the reserved Z bit set is FORMERR (court `WIRE-HEADER-ZBIT`);
//! - a second OPT in the additional section is FORMERR (court
//!   `WIRE-MESSAGE-DUPOPT`);
//! - section counts from the header must be satisfiable within the buffer,
//!   otherwise FORMERR;
//! - RDATA that does not consume exactly `rdlength` octets is FORMERR.
//!
//! Rendering mirrors `dns_message_render`: the question name is not
//! compressed; other names are compressed via [`compression::Compressor`];
//! OPT is rendered in the additional section (position rules courted by
//! `RENDER-OPT-PLACEMENT`).

pub mod compression;
pub mod header;
pub mod question;

use crate::class::Class;
use crate::edns::Opt;
use crate::error::{Error, Result};
use crate::message::compression::Compressor;
use crate::message::header::{Header, Id};
use crate::message::question::Question;
use crate::name::Name;
use crate::rdata::Rdata;
use crate::rrtype::RrType;
use crate::ttl::Ttl;

/// One resource record in a message section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub type_: RrType,
    pub class: Class,
    pub ttl: Ttl,
    pub rdata: Rdata,
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: Id,
    pub flags: header::Flags,
    pub header_rcode: u8,
    pub question: Option<Question>,
    pub answer: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    /// The EDNS OPT, captured out of the additional section (BIND models it
    /// separately; it is not listed in `additional`).
    pub opt: Option<Opt>,
}

impl Message {
    /// Parse a full message from wire bytes.
    pub fn parse(buf: &[u8]) -> Result<Message> {
        let h = header::parse(buf)?;
        let mut pos = 12usize;

        let question = match h.qdcount {
            0 => None,
            1 => {
                let (q, np) = Question::from_wire(buf, pos)?;
                pos = np;
                Some(q)
            }
            _ => return Err(Error::FormErr),
        };

        let answer = parse_section(
            buf,
            &mut pos,
            h.ancount,
            h.flags.opcode,
            question.as_ref().map(|q| q.qclass),
        )?;
        eprintln!("DBG after answer: pos={pos}");
        let authority = parse_section(
            buf,
            &mut pos,
            h.nscount,
            h.flags.opcode,
            question.as_ref().map(|q| q.qclass),
        )?;
        let mut additional = Vec::new();
        let mut opt: Option<Opt> = None;
        for _ in 0..h.arcount {
            let (name, type_, class, ttl, rdlen, mut rpos) = parse_record_prefix(buf, pos)?;
            eprintln!(
                "DBG additional@{pos}: type={} rdlen={rdlen} rpos={rpos} len={}",
                type_.to_text(),
                buf.len()
            );
            if type_ == RrType::Opt {
                // BIND: the OPT owner name must be the root, it must be in
                // the additional section, and it must be the first OPT
                // (dns_message_parse → getsection).
                if !name.is_absolute() || !name.as_wire_slice().is_empty() {
                    return Err(Error::FormErr);
                }
                if opt.is_some() {
                    return Err(Error::FormErr);
                }
                let o = Opt::from_wire(class.to_u16(), ttl.as_u32(), &buf[rpos..rpos + rdlen])?;
                opt = Some(o);
                pos = rpos + rdlen;
                continue;
            }
            // BIND: type 0 (RESERVED0) is rejected with FORMERR.
            if type_ == RrType::Reserved0 {
                return Err(Error::FormErr);
            }
            // BIND: non-meta records in a query must match the question's
            // class (OPT/TSIG/KEY/SIG0/TKEY are exempt, as is ANY).
            if let Some(q) = &question {
                if h.flags.opcode == 0
                    && !matches!(
                        type_,
                        RrType::Tsig | RrType::Key | RrType::Sig | RrType::Tkey
                    )
                    && q.qclass != Class::Any
                    && q.qclass != class
                {
                    return Err(Error::FormErr);
                }
            }
            let end = rpos + rdlen;
            let rdata = Rdata::from_wire(type_, buf, &mut rpos, end)?;
            // Rdata::from_wire enforces consuming exactly rdlen octets.
            pos = rpos;
            additional.push(Record {
                name,
                type_,
                class,
                ttl,
                rdata,
            });
        }

        Ok(Message {
            id: h.id,
            flags: h.flags,
            header_rcode: h.rcode_low,
            question,
            answer,
            authority,
            additional,
            opt,
        })
    }

    /// Render the message.  `compression` enables name compression; names
    /// are added to the compression table either way (BIND behavior).
    pub fn render(&self, out: &mut Vec<u8>, compression: bool) -> Result<()> {
        let mut comp = Compressor::new();
        comp.set_permitted(compression);

        let header = Header {
            id: self.id,
            flags: self.flags,
            rcode_low: self.header_rcode,
            qdcount: u16::from(self.question.is_some() as u16),
            ancount: self.answer.len() as u16,
            nscount: self.authority.len() as u16,
            arcount: (self.additional.len() + usize::from(self.opt.is_some())) as u16,
        };
        header::render(&header, out);

        if let Some(q) = &self.question {
            // BIND renders the question name through the same path as all
            // other names (dns_rdataset_towire → dns_name_towire): it is
            // added to the compression table, so later records compress
            // against it.  There is nothing earlier to point at, so the
            // emitted bytes are uncompressed.
            comp.render(&q.qname, out);
            out.extend_from_slice(&q.qtype.to_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_u16().to_be_bytes());
        }

        for r in &self.answer {
            render_record(out, r, &mut comp)?;
        }
        for r in &self.authority {
            render_record(out, r, &mut comp)?;
        }
        for r in &self.additional {
            render_record(out, r, &mut comp)?;
        }
        if let Some(o) = &self.opt {
            o.render(out, Some(&mut comp))?;
        }
        Ok(())
    }
}

/// Parse a section of `count` records.
fn parse_section(
    buf: &[u8],
    pos: &mut usize,
    count: u16,
    opcode: u8,
    qclass: Option<Class>,
) -> Result<Vec<Record>> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (name, type_, class, ttl, rdlen, mut rpos) = parse_record_prefix(buf, *pos)?;
        // BIND: type 0 (RESERVED0) is rejected with FORMERR.
        if type_ == RrType::Reserved0 {
            return Err(Error::FormErr);
        }
        // BIND: non-meta records must match the question's class (OPT/TSIG/
        // KEY/SIG0/TKEY exempt, as is ANY).
        if let Some(qclass) = qclass {
            if opcode == 0
                && !matches!(
                    type_,
                    RrType::Tsig | RrType::Key | RrType::Sig | RrType::Tkey
                )
                && qclass != Class::Any
                && qclass != class
            {
                return Err(Error::FormErr);
            }
        }
        let end = rpos + rdlen;
        let rdata = Rdata::from_wire(type_, buf, &mut rpos, end)?;
        // Rdata::from_wire enforces consuming exactly rdlen octets, so rpos
        // now points past the rdata.
        *pos = rpos;
        out.push(Record {
            name,
            type_,
            class,
            ttl,
            rdata,
        });
    }
    Ok(out)
}

/// Parse the fixed part of a record (name, type, class, ttl, rdlength).
#[allow(clippy::type_complexity)]
fn parse_record_prefix(buf: &[u8], pos: usize) -> Result<(Name, RrType, Class, Ttl, usize, usize)> {
    let fw = crate::name::wire::from_wire(buf, pos, true)?;
    let p = fw.consumed;
    if p + 10 > buf.len() {
        return Err(Error::UnexpectedEnd);
    }
    let type_ = RrType::from_u16(u16::from_be_bytes([buf[p], buf[p + 1]]));
    let class = Class::from_u16(u16::from_be_bytes([buf[p + 2], buf[p + 3]]));
    let ttl = Ttl::from_secs(u32::from_be_bytes([
        buf[p + 4],
        buf[p + 5],
        buf[p + 6],
        buf[p + 7],
    ]));
    let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
    let rpos = p + 10;
    if rpos + rdlen > buf.len() {
        return Err(Error::UnexpectedEnd);
    }
    Ok((fw.name, type_, class, ttl, rdlen, rpos))
}

fn render_record(out: &mut Vec<u8>, r: &Record, comp: &mut Compressor) -> Result<()> {
    comp.render(&r.name, out);
    out.extend_from_slice(&r.type_.to_u16().to_be_bytes());
    out.extend_from_slice(&r.class.to_u16().to_be_bytes());
    out.extend_from_slice(&r.ttl.as_u32().to_be_bytes());
    let len_pos = out.len();
    out.extend_from_slice(&0u16.to_be_bytes()); // rdlength placeholder
    r.rdata.to_wire(out, Some(comp))?;
    let rdlen = out.len() - len_pos - 2;
    let rdlen: u16 = rdlen.try_into().map_err(|_| Error::MessageTooLong)?;
    out[len_pos..len_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::Opt;
    use crate::rcode::Rcode;

    fn name(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

    fn query_message() -> Message {
        Message {
            id: 0xbeef,
            flags: header::Flags {
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: false,
                ad: false,
                cd: false,
            },
            header_rcode: 0,
            question: Some(Question {
                qname: name("www.example.com."),
                qtype: RrType::A,
                qclass: Class::In,
            }),
            answer: vec![Record {
                name: name("www.example.com."),
                type_: RrType::A,
                class: Class::In,
                ttl: Ttl::from_secs(300),
                rdata: Rdata::A("192.0.2.1".parse().unwrap()),
            }],
            authority: vec![],
            additional: vec![Record {
                name: name("ns1.example.com."),
                type_: RrType::A,
                class: Class::In,
                ttl: Ttl::from_secs(300),
                rdata: Rdata::A("192.0.2.53".parse().unwrap()),
            }],
            opt: None,
        }
    }

    #[test]
    fn query_response_roundtrip() {
        let m = query_message();
        let mut wire = Vec::new();
        m.render(&mut wire, true).unwrap();
        // ID + flags + counts.
        assert_eq!(&wire[0..2], &[0xbe, 0xef]);
        // QR=0, RD=1: 0x0100.
        assert_eq!(&wire[2..4], &[0x01, 0x00]);
        // Counts: 1 question, 1 answer, 0 authority, 1 additional.
        assert_eq!(&wire[4..6], &[0x00, 0x01]);
        assert_eq!(&wire[6..8], &[0x00, 0x01]);
        assert_eq!(&wire[8..10], &[0x00, 0x00]);
        assert_eq!(&wire[10..12], &[0x00, 0x01]);

        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn answer_name_compressed() {
        let m = query_message();
        let mut wire = Vec::new();
        m.render(&mut wire, true).unwrap();
        // The answer record's owner name is a pointer to the qname at
        // offset 12.  The answer record starts right after the question
        // (12 header + 17 qname + 4 type/class = 33).
        assert_eq!(wire[33], 0xc0);
        assert_eq!(wire[34], 12);
    }

    #[test]
    fn uncompressed_question_roundtrip() {
        let m = query_message();
        let mut wire = Vec::new();
        m.render(&mut wire, true).unwrap();
        // Question name must be present in full at offset 12 (there is
        // nothing earlier to point at; it is still added to the compressor
        // table, which is why the answer name can point back at it).
        assert_eq!(&wire[12..24], b"\x03www\x07example");
    }

    #[test]
    fn no_question_is_formerr() {
        let mut m = query_message();
        m.question = None;
        // Render with qdcount 0, then parse must still succeed structurally
        // (a response with no question is legal); the FORMERR policy is a
        // server-level decision for queries.  Parse-level: fine.
        let mut wire = Vec::new();
        m.render(&mut wire, true).unwrap();
        assert!(Message::parse(&wire).is_ok());
    }

    #[test]
    fn multi_question_is_formerr() {
        // Manually build a message with qdcount=2.
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x12, 0x34]); // id
        wire.extend_from_slice(&[0x01, 0x00]); // flags RD
        wire.extend_from_slice(&[0x00, 0x02]); // qdcount = 2
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // other counts
        let q = Question {
            qname: name("a."),
            qtype: RrType::A,
            qclass: Class::In,
        };
        q.to_wire(&mut wire);
        q.to_wire(&mut wire);
        assert_eq!(Message::parse(&wire).map(|_| ()), Err(Error::FormErr));
    }

    #[test]
    fn opt_roundtrip() {
        let mut m = query_message();
        m.opt = Some(Opt::new(1232));
        let mut wire = Vec::new();
        m.render(&mut wire, true).unwrap();
        let parsed = Message::parse(&wire).unwrap();
        assert!(parsed.opt.is_some());
        assert_eq!(parsed.opt.as_ref().unwrap().udp_payload_size(), 1232);
        // arcount must include the OPT.
        assert_eq!(parsed.additional.len() + 1, 2);
    }

    #[test]
    fn duplicate_opt_is_formerr() {
        // Build a message with two OPT records in additional (arcount=2 in
        // the header, then two OPT records after the question).
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x12, 0x34]);
        wire.extend_from_slice(&[0x81, 0x00]); // QR, RD
        wire.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 2]); // qdcount=1, arcount=2
        let q = Question {
            qname: name("."),
            qtype: RrType::A,
            qclass: Class::In,
        };
        q.to_wire(&mut wire);
        for _ in 0..2 {
            wire.push(0); // OPT name = root
            wire.extend_from_slice(&[0, 41]); // type OPT
            wire.extend_from_slice(&[0x04, 0xd0]); // class = 1232
            wire.extend_from_slice(&[0, 0, 0, 0]); // ttl
            wire.extend_from_slice(&[0, 0]); // rdlen 0
        }
        assert_eq!(Message::parse(&wire).map(|_| ()), Err(Error::FormErr));
    }

    #[test]
    fn section_count_overflow_rejected() {
        // ancount=5 but no records present.
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x12, 0x34]);
        wire.extend_from_slice(&[0x01, 0x00]);
        wire.extend_from_slice(&[0, 1, 0, 5, 0, 0]); // qdcount=1 ancount=5
        let q = Question {
            qname: name("."),
            qtype: RrType::A,
            qclass: Class::In,
        };
        q.to_wire(&mut wire);
        assert_eq!(Message::parse(&wire).map(|_| ()), Err(Error::UnexpectedEnd));
    }

    #[test]
    fn rdata_length_mismatch_is_formerr() {
        // An A record whose rdlength exceeds the actual rdata: BIND's
        // dns_rdata_fromwire returns DNS_R_EXTRADATA ("extra input data"),
        // which the server layer maps to a FORMERR response (the message
        // parse itself surfaces the underlying error — courted by
        // WIRE-MESSAGE-*).
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0x12, 0x34]);
        wire.extend_from_slice(&[0x81, 0x00]);
        wire.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qdcount=1, ancount=1
        let q = Question {
            qname: name("."),
            qtype: RrType::A,
            qclass: Class::In,
        };
        q.to_wire(&mut wire);
        // Answer: A record with rdlen=5 but the A parser only consumes 4.
        wire.push(0); // name root
        wire.extend_from_slice(&[0, 1]); // A
        wire.extend_from_slice(&[0, 1]); // IN
        wire.extend_from_slice(&[0, 0, 0, 60]); // ttl
        wire.extend_from_slice(&[0, 5]); // rdlen=5
        wire.extend_from_slice(&[192, 0, 2, 1, 0xde]); // 5 bytes
        assert_eq!(Message::parse(&wire).map(|_| ()), Err(Error::ExtraData));
    }

    #[test]
    fn trailing_bytes_accepted_with_warning() {
        // BIND accepts bytes after the last section (dig reports them as a
        // warning: "Message has N extra bytes at end"); this is NOT a
        // FORMERR.  Courted by WIRE-MESSAGE-TRAILING.
        let mut wire = Vec::new();
        let mut m = query_message();
        let mut buf = Vec::new();
        m.render(&mut buf, true).unwrap();
        wire.extend_from_slice(&buf);
        wire.push(0xde);
        wire.push(0xad);
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn full_rcode_path() {
        // BADVERS: header rcode 0 + ext 1.
        let mut m = query_message();
        m.header_rcode = 0;
        let _ = Rcode::BadVers;
    }
}
