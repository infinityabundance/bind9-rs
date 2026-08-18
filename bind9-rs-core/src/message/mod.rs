//! DNS message structure and the parse/render paths.
//!
//! Parse behavior mirrors `dns_message_parse` (lib/dns/message.c, 9.20.26)
//! and is courted byte-for-byte by `WIRE-MESSAGE-*`.  The observable model
//! is BIND's:
//!
//! - sections hold *names* in first-seen order, each with *rrsets*
//!   (class + type + covers), each rrset with a TTL (minimized across its
//!   rdata) and an rdata list — records sharing a name merge into one name
//!   node, records sharing name+class+type(+covers) merge into one rrset,
//!   and a singleton type (CNAME/SOA/DNAME/OPT/RESINFO) with differing
//!   rdata is FORMERR;
//! - a second question is FORMERR unless it shares the first question's
//!   name but a different type/class (BIND appends it — courted);
//! - update/notify questions with class NONE/ANY are FORMERR; the class
//!   must be consistent across all questions;
//! - OPT must be owned by `.`, live in the additional section, and be the
//!   first OPT; TSIG must be last in the additional section with class ANY;
//!   SIG(0) must be last with owner `.` — violations are FORMERR/BADTSIG/
//!   BADSIG0 and (under best-effort) degrade to `DNS_R_RECOVERABLE`;
//! - RRSIG covers may not be a meta type; NSEC3 owners must have a
//!   base32hex first label; question-only types (IXFR/AXFR/MAILA/MAILB/ANY)
//!   are FORMERR outside the question section;
//! - a record whose class is not the type's native class parses as the
//!   RFC 3597 generic form (BIND's class-gated `dns_rdata_fromwire`);
//! - hard errors (`ISC_R_UNEXPECTEDEND`, malformed names, `DNS_R_OPTERR`,
//!   `DNS_R_BADOWNERNAME`, ...) fail the parse outright.
//!
//! Rendering mirrors `dns_message_renderbegin`/`rendersection`/`renderend`:
//! the question name enters the compression table first (later names
//! compress against it), the additional section renders in BIND's class-IN
//! pass order (A/AAAA, then RRSIG/DNSKEY, then the rest), the OPT is
//! rendered last with the extended rcode folded into its TTL, and a TC
//! message carrying an OPT drops everything but the question before the
//! OPT (renderend's reset path).  An extended rcode without an OPT is
//! FORMERR.
//!
//! [`Message::parse`] applies dig's flags (PRESERVEORDER | BESTEFFORT |
//! IGNORETRUNCATION) and swallows `DNS_R_RECOVERABLE`; [`Message::parse_full`]
//! reports it; [`Message::parse_strict`] uses no options.

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
use crate::rdata::{Rdata, UnknownRdata};
use crate::rrtype::RrType;
use crate::ttl::Ttl;

/// One resource record in a message section — the flattened view dig
/// prints (each rdata of an rrset, carrying the rrset TTL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub type_: RrType,
    pub class: Class,
    pub ttl: Ttl,
    pub rdata: Rdata,
}

/// One RRset attached to a name (BIND `dns_rdataset_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrset {
    pub class: Class,
    pub type_: RrType,
    /// The covered type for RRSIG/SIG records (0 otherwise).
    pub covers: u16,
    /// The rrset TTL, minimized across the rdata (BIND `getsection`).
    pub ttl: u32,
    /// True for question rdatasets (`DNS_RDATASETATTR_QUESTION`).
    pub question: bool,
    pub rdata: Vec<Rdata>,
}

/// A name node in a section with its rrsets (BIND `dns_name_t` in a
/// section list).  Names appear in first-seen order; a later record with an
/// equal (case-insensitive) name merges into the existing node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRrsets {
    pub name: Name,
    pub rrsets: Vec<Rrset>,
}

/// Section indices used by this crate's parser (the wire order: question,
/// answer, authority, additional).
pub const SECTION_QUESTION: usize = 0;
pub const SECTION_ANSWER: usize = 1;
pub const SECTION_AUTHORITY: usize = 2;
pub const SECTION_ADDITIONAL: usize = 3;

/// The parse outcome code (BIND `dns_message_parse`'s success-family
/// return values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseStatus {
    /// `ISC_R_SUCCESS`.
    Success,
    /// `DNS_R_RECOVERABLE`: best-effort parsing saw at least one malformed
    /// record but produced a usable message.
    Recoverable,
}

/// Parser options (BIND `DNS_MESSAGEPARSE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseOptions {
    /// `DNS_MESSAGEPARSE_BESTEFFORT`: malformed records set a problem flag
    /// instead of failing; the parse returns `DNS_R_RECOVERABLE`.
    pub best_effort: bool,
    /// `DNS_MESSAGEPARSE_PRESERVEORDER`: every record keeps its own name
    /// node and rrset — no merging, no TTL minimization, no singleton or
    /// question-only checks (dig's flag).
    pub preserve_order: bool,
    /// `DNS_MESSAGEPARSE_IGNORETRUNCATION`: an `ISC_R_UNEXPECTEDEND` in a
    /// section degrades to `DNS_R_RECOVERABLE` with the partial structure.
    pub ignore_truncation: bool,
}

/// dig's parse flags (dighost.c: PRESERVEORDER | BESTEFFORT |
/// IGNORETRUNCATION unless dns64 is in play).
pub const DIG_PARSE_OPTIONS: ParseOptions = ParseOptions {
    best_effort: true,
    preserve_order: true,
    ignore_truncation: true,
};

/// BIND `DNS_MESSAGE_FLAG_MASK`.
pub const MESSAGE_FLAG_MASK: u16 = 0x8ff0;
/// BIND `DNS_MESSAGE_OPCODE_MASK`.
pub const MESSAGE_OPCODE_MASK: u16 = 0x7800;
/// BIND `DNS_MESSAGE_OPCODE_SHIFT`.
pub const MESSAGE_OPCODE_SHIFT: u16 = 11;
/// BIND `DNS_MESSAGE_RCODE_MASK`.
pub const MESSAGE_RCODE_MASK: u16 = 0x000f;
/// BIND `DNS_MESSAGEFLAG_QR`.
pub const FLAG_QR: u16 = 0x8000;
/// BIND `DNS_MESSAGEFLAG_TC`.
pub const FLAG_TC: u16 = 0x0200;

/// A parsed DNS message, modeled on BIND's `dns_message_t` (the probe
/// transcript is generated from [`Message::sections`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: Id,
    pub flags: header::Flags,
    /// The 4-bit header rcode (the extended rcode rides in EDNS).
    pub header_rcode: u8,
    /// The merged 12-bit rcode: header rcode plus the OPT extended-rcode
    /// bits (BIND `msg->rcode` after `getsection` folds `opt->ttl` in).
    pub rcode: u16,
    /// The raw flags word masked to BIND's `DNS_MESSAGE_FLAG_MASK`
    /// (0x8ff0: QR AA TC RD RA Z AD CD).
    pub raw_flags: u16,
    /// The four section counts from the header (BIND `msg->counts`).
    pub counts: [u16; 4],
    /// The first question (dig's view); the full question section lives in
    /// [`Message::sections`].
    pub question: Option<Question>,
    /// Flattened answer records (dig's view; each rdata of every rrset).
    pub answer: Vec<Record>,
    /// Flattened authority records.
    pub authority: Vec<Record>,
    /// Flattened additional records (the OPT is excluded, as in BIND).
    pub additional: Vec<Record>,
    /// The EDNS OPT, captured out of the additional section (BIND models it
    /// separately; it is not listed in `additional`).
    pub opt: Option<Opt>,
    /// The section model (names with merged rrsets) — the source of truth
    /// for the WIRE-MESSAGE court transcript.
    pub sections: [Vec<NameRrsets>; 4],
    /// The TSIG record's owner name, when present.
    pub tsig: Option<Name>,
    /// The SIG(0) record's owner name, when present.
    pub sig0: Option<Name>,
}

impl Message {
    /// Parse with dig's flags and swallow `DNS_R_RECOVERABLE` (the caller
    /// gets the message either way, as dig does).
    pub fn parse(buf: &[u8]) -> Result<Message> {
        let (m, _) = Self::parse_full(buf, DIG_PARSE_OPTIONS)?;
        Ok(m)
    }

    /// Parse with the fuzz-harness flags (`DNS_MESSAGEPARSE_BESTEFFORT`
    /// only) — the WIRE-MESSAGE court's configuration.
    pub fn parse_besteffort(buf: &[u8]) -> Result<(Message, ParseStatus)> {
        Self::parse_full(
            buf,
            ParseOptions {
                best_effort: true,
                preserve_order: false,
                ignore_truncation: false,
            },
        )
    }

    /// Parse with no options: any malformed record fails the parse.
    pub fn parse_strict(buf: &[u8]) -> Result<Message> {
        let (m, status) = Self::parse_full(buf, ParseOptions::default())?;
        debug_assert_eq!(status, ParseStatus::Success);
        Ok(m)
    }

    /// Parse with explicit options.  On `DNS_R_RECOVERABLE` the message is
    /// returned with [`ParseStatus::Recoverable`]; hard errors are `Err`.
    pub fn parse_full(buf: &[u8], options: ParseOptions) -> Result<(Message, ParseStatus)> {
        let mut parser = Parser {
            buf,
            options,
            seen_problem: false,
        };
        let m = parser.parse()?;
        let status = if parser.seen_problem {
            ParseStatus::Recoverable
        } else {
            ParseStatus::Success
        };
        Ok((m, status))
    }

    /// Render the message.  `compression` enables name compression; names
    /// are added to the compression table either way (BIND behavior).
    pub fn render(&self, out: &mut Vec<u8>, compression: bool) -> Result<()> {
        // renderbegin reserves the header; renderend patches it in.
        out.extend_from_slice(&[0u8; 12]);

        // Rendered section counts (BIND msg->counts updated by
        // rendersection; renderbegin zeroes them).
        let mut counts = [0u16; 4];

        let mut comp = Compressor::new();
        comp.set_permitted(compression);
        render_section(self, out, &mut comp, SECTION_QUESTION, &mut counts)?;
        render_section(self, out, &mut comp, SECTION_ANSWER, &mut counts)?;
        render_section(self, out, &mut comp, SECTION_AUTHORITY, &mut counts)?;
        render_section(self, out, &mut comp, SECTION_ADDITIONAL, &mut counts)?;

        // renderend.
        if self.rcode & !MESSAGE_RCODE_MASK != 0 && self.opt.is_none() {
            return Err(Error::FormErr);
        }
        // TC with an OPT (or keys — the probe path only has OPT): drop
        // everything but the question and re-render it from a fresh
        // compression table (dns_message_renderend's reset path).
        if self.opt.is_some() && self.raw_flags & FLAG_TC != 0 {
            out.truncate(12);
            counts = [0u16; 4];
            let mut comp2 = Compressor::new();
            comp2.set_permitted(compression);
            render_section(self, out, &mut comp2, SECTION_QUESTION, &mut counts)?;
            comp = comp2;
        }
        if let Some(o) = &self.opt {
            // Patch the extended rcode into the OPT TTL (BIND renderend:
            // ttl &= ~0xff000000; ttl |= (rcode << 20) & 0xff000000).
            let ttl = (o.raw_ttl() & 0x00ff_ffff) | (((self.rcode as u32) << 20) & 0xff00_0000);
            o.render_with_ttl(out, ttl, Some(&mut comp))?;
            counts[SECTION_ADDITIONAL] += 1;
        }

        // dns_message_renderheader: id, opcode|rcode|flags, counts.
        let h = Header {
            id: self.id,
            flags: self.flags,
            rcode_low: (self.rcode & MESSAGE_RCODE_MASK) as u8,
            qdcount: counts[SECTION_QUESTION],
            ancount: counts[SECTION_ANSWER],
            nscount: counts[SECTION_AUTHORITY],
            arcount: counts[SECTION_ADDITIONAL],
        };
        let mut header_buf = Vec::new();
        header::render(&h, &mut header_buf);
        out[..12].copy_from_slice(&header_buf);
        Ok(())
    }

    /// Build a message from flattened parts (dig's query builder); the
    /// section model is derived so rendering behaves identically.
    #[must_use]
    pub fn build(
        id: Id,
        flags: header::Flags,
        header_rcode: u8,
        question: Option<Question>,
        answer: Vec<Record>,
        authority: Vec<Record>,
        additional: Vec<Record>,
        opt: Option<Opt>,
    ) -> Message {
        let raw_flags = flags.to_word(header_rcode) & MESSAGE_FLAG_MASK;
        let mut sections: [Vec<NameRrsets>; 4] = Default::default();
        if let Some(q) = &question {
            sections[SECTION_QUESTION].push(NameRrsets {
                name: q.qname.clone(),
                rrsets: vec![Rrset {
                    class: q.qclass,
                    type_: q.qtype,
                    covers: 0,
                    ttl: 0,
                    question: true,
                    rdata: Vec::new(),
                }],
            });
        }
        let mut push = |records: Vec<Record>, section: usize| {
            for r in records {
                let section_list = &mut sections[section];
                let ni = section_list
                    .iter()
                    .position(|n| n.name.rdatacompare(&r.name) == std::cmp::Ordering::Equal);
                match ni {
                    None => {
                        section_list.push(NameRrsets {
                            name: r.name.clone(),
                            rrsets: vec![Rrset {
                                class: r.class,
                                type_: r.type_,
                                covers: 0,
                                ttl: r.ttl.as_u32(),
                                question: false,
                                rdata: vec![r.rdata],
                            }],
                        });
                    }
                    Some(ni) => {
                        let n = &mut section_list[ni];
                        let ri = n
                            .rrsets
                            .iter()
                            .position(|rr| rr.class == r.class && rr.type_ == r.type_);
                        match ri {
                            None => n.rrsets.push(Rrset {
                                class: r.class,
                                type_: r.type_,
                                covers: 0,
                                ttl: r.ttl.as_u32(),
                                question: false,
                                rdata: vec![r.rdata],
                            }),
                            Some(ri) => {
                                let ttl = n.rrsets[ri].ttl.min(r.ttl.as_u32());
                                n.rrsets[ri].ttl = ttl;
                                n.rrsets[ri].rdata.push(r.rdata);
                            }
                        }
                    }
                }
            }
        };
        push(answer, SECTION_ANSWER);
        push(authority, SECTION_AUTHORITY);
        push(additional, SECTION_ADDITIONAL);

        let total_rdata = |section: &[NameRrsets]| -> u16 {
            section
                .iter()
                .flat_map(|n| n.rrsets.iter())
                .map(|rr| {
                    if rr.question {
                        1
                    } else {
                        rr.rdata.len().max(1) as u16
                    }
                })
                .sum()
        };
        let counts = [
            total_rdata(&sections[SECTION_QUESTION]),
            total_rdata(&sections[SECTION_ANSWER]),
            total_rdata(&sections[SECTION_AUTHORITY]),
            total_rdata(&sections[SECTION_ADDITIONAL]) + u16::from(opt.is_some()),
        ];
        let answer = flatten_view(&sections[SECTION_ANSWER]);
        let authority = flatten_view(&sections[SECTION_AUTHORITY]);
        let additional = flatten_view(&sections[SECTION_ADDITIONAL]);
        Message {
            id,
            flags,
            header_rcode,
            rcode: u16::from(header_rcode),
            raw_flags,
            counts,
            question,
            answer,
            authority,
            additional,
            opt,
            sections,
            tsig: None,
            sig0: None,
        }
    }
}

/// The merged-rdata flattened view of a section (dig's `Vec<Record>`).
fn flatten_view(section: &[NameRrsets]) -> Vec<Record> {
    let mut out = Vec::new();
    for n in section {
        for rr in &n.rrsets {
            if rr.question {
                continue;
            }
            for r in &rr.rdata {
                out.push(Record {
                    name: n.name.clone(),
                    type_: rr.type_,
                    class: rr.class,
                    ttl: Ttl::from_secs(rr.ttl),
                    rdata: r.clone(),
                });
            }
        }
    }
    out
}

/// Render one section (BIND `dns_message_rendersection`, options 0).  The
/// additional section uses the class-IN pass ordering: A/AAAA on pass 1,
/// RRSIG/DNSKEY on pass 2, everything else on pass 3.
fn render_section(
    msg: &Message,
    out: &mut Vec<u8>,
    comp: &mut Compressor,
    section: usize,
    counts: &mut [u16; 4],
) -> Result<()> {
    let passes: usize = if section == SECTION_ADDITIONAL { 3 } else { 1 };
    let mut rendered: Vec<(usize, usize)> = Vec::new(); // (name idx, rrset idx)
    for pass in (1..=passes).rev() {
        for (ni, n) in msg.sections[section].iter().enumerate() {
            for (ri, rr) in n.rrsets.iter().enumerate() {
                if rendered.contains(&(ni, ri)) {
                    continue;
                }
                if section == SECTION_ADDITIONAL && wrong_priority(rr, pass) {
                    continue;
                }
                render_rrset(out, comp, &n.name, rr)?;
                rendered.push((ni, ri));
                counts[section] += if rr.question {
                    1
                } else {
                    rr.rdata.len() as u16
                };
            }
        }
    }
    Ok(())
}

/// BIND `wrong_priority` (class IN only): A/AAAA need pass 3, RRSIG/DNSKEY
/// pass 2, everything else pass 1; a rrset is "wrong" when its required
/// pass is below the current one.
fn wrong_priority(rr: &Rrset, pass: usize) -> bool {
    if rr.class != Class::In {
        return false;
    }
    let pass_needed = match rr.type_ {
        RrType::A | RrType::Aaaa => 3,
        RrType::Rrsig | RrType::Dnskey => 2,
        _ => 1,
    };
    pass_needed < pass
}

/// Render one rrset (BIND `dns_rdataset_towiresorted` with no ordering
/// function, `question` flag honored).  BIND re-renders the owner name,
/// type, class and TTL before *each* rdata, so an rrset with several rdata
/// becomes several wire records.
fn render_rrset(out: &mut Vec<u8>, comp: &mut Compressor, name: &Name, rr: &Rrset) -> Result<()> {
    if rr.question {
        // Question rdatasets render as name + type + class only, once per
        // rrset regardless of the (empty) rdata list (BIND `towiresorted`
        // with `count = 1`).
        comp.render(name, out);
        out.extend_from_slice(&rr.type_.to_u16().to_be_bytes());
        out.extend_from_slice(&rr.class.to_u16().to_be_bytes());
        return Ok(());
    }
    for r in &rr.rdata {
        comp.render(name, out);
        out.extend_from_slice(&rr.type_.to_u16().to_be_bytes());
        out.extend_from_slice(&rr.class.to_u16().to_be_bytes());
        out.extend_from_slice(&rr.ttl.to_be_bytes());
        let len_pos = out.len();
        out.extend_from_slice(&0u16.to_be_bytes()); // rdlength placeholder
        r.to_wire(out, Some(comp))?;
        let rdlen = out.len() - len_pos - 2;
        let rdlen: u16 = rdlen.try_into().map_err(|_| Error::MessageTooLong)?;
        out[len_pos..len_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
    Ok(())
}

struct Parser<'a> {
    buf: &'a [u8],
    options: ParseOptions,
    /// Any DO_ERROR recorded (BIND's `seen_problem`, message-wide).
    seen_problem: bool,
}

impl<'a> Parser<'a> {
    fn parse(&mut self) -> Result<Message> {
        let buf = self.buf;
        if buf.len() < 12 {
            return Err(Error::UnexpectedEnd);
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let tmpflags = u16::from_be_bytes([buf[2], buf[3]]);
        let opcode = ((tmpflags & MESSAGE_OPCODE_MASK) >> MESSAGE_OPCODE_SHIFT) as u8;
        let header_rcode = (tmpflags & MESSAGE_RCODE_MASK) as u8;
        let raw_flags = tmpflags & MESSAGE_FLAG_MASK;
        let counts = [
            u16::from_be_bytes([buf[4], buf[5]]),
            u16::from_be_bytes([buf[6], buf[7]]),
            u16::from_be_bytes([buf[8], buf[9]]),
            u16::from_be_bytes([buf[10], buf[11]]),
        ];
        let mut pos = 12usize;

        let mut sections: [Vec<NameRrsets>; 4] = Default::default();
        let mut rdclass_set = false;
        let mut rdclass = Class::In;
        let mut tkey_question = false;
        let mut opt: Option<Opt> = None;
        let mut tsig: Option<Name> = None;
        let mut sig0: Option<Name> = None;
        let mut merged_rcode = u16::from(header_rcode);
        let mut first_question: Option<Question> = None;

        let mut question_problem = false;
        if let Err(e) = self.parse_questions(
            &mut pos,
            opcode,
            counts[0],
            &mut sections,
            &mut rdclass_set,
            &mut rdclass,
            &mut tkey_question,
            &mut first_question,
            &mut question_problem,
        ) {
            if self.options.ignore_truncation && e == Error::UnexpectedEnd {
                self.seen_problem = true;
                return Ok(self.finish(
                    id,
                    tmpflags,
                    opcode,
                    header_rcode,
                    raw_flags,
                    counts,
                    first_question,
                    sections,
                    opt,
                    tsig,
                    sig0,
                    merged_rcode,
                ));
            }
            return Err(e);
        }
        if question_problem {
            self.seen_problem = true;
        }

        for section in [SECTION_ANSWER, SECTION_AUTHORITY, SECTION_ADDITIONAL] {
            let mut local_problem = false;
            let r = self.parse_section(
                &mut pos,
                section,
                counts[section],
                opcode,
                &mut rdclass_set,
                &mut rdclass,
                tkey_question,
                &mut sections,
                &mut opt,
                &mut tsig,
                &mut sig0,
                &mut merged_rcode,
                &mut local_problem,
            );
            match r {
                Err(e) if self.options.ignore_truncation && e == Error::UnexpectedEnd => {
                    self.seen_problem = true;
                    break;
                }
                Err(e) => return Err(e),
                Ok(()) => {
                    if local_problem {
                        self.seen_problem = true;
                    }
                }
            }
        }

        Ok(self.finish(
            id,
            tmpflags,
            opcode,
            header_rcode,
            raw_flags,
            counts,
            first_question,
            sections,
            opt,
            tsig,
            sig0,
            merged_rcode,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        id: Id,
        tmpflags: u16,
        opcode: u8,
        header_rcode: u8,
        raw_flags: u16,
        counts: [u16; 4],
        first_question: Option<Question>,
        sections: [Vec<NameRrsets>; 4],
        opt: Option<Opt>,
        tsig: Option<Name>,
        sig0: Option<Name>,
        merged_rcode: u16,
    ) -> Message {
        let _ = opcode;
        let flags = header::Flags::from_word(tmpflags);
        let question = first_question;
        let answer = flatten_view(&sections[SECTION_ANSWER]);
        let authority = flatten_view(&sections[SECTION_AUTHORITY]);
        let additional = flatten_view(&sections[SECTION_ADDITIONAL]);
        Message {
            id,
            flags,
            header_rcode,
            rcode: merged_rcode,
            raw_flags,
            counts,
            question,
            answer,
            authority,
            additional,
            opt,
            sections,
            tsig,
            sig0,
        }
    }

    /// Record a best-effort problem (BIND `DO_ERROR`): with best_effort the
    /// flag is set and parsing continues; otherwise the error fails the
    /// parse immediately.
    fn do_error(&mut self, code: Error, local_problem: &mut bool) -> Result<()> {
        if self.options.best_effort {
            *local_problem = true;
            Ok(())
        } else {
            Err(code)
        }
    }

    /// The question section (BIND `getquestions`).
    #[allow(clippy::too_many_arguments)]
    fn parse_questions(
        &mut self,
        pos: &mut usize,
        opcode: u8,
        qd: u16,
        sections: &mut [Vec<NameRrsets>; 4],
        rdclass_set: &mut bool,
        rdclass: &mut Class,
        tkey_question: &mut bool,
        first_question: &mut Option<Question>,
        local_problem: &mut bool,
    ) -> Result<()> {
        let buf = self.buf;
        let count = qd;
        for _ in 0..count {
            // getname (compression allowed).
            let fw = crate::name::wire::from_wire(buf, *pos, true)?;
            let mut name = fw.name;
            *pos = fw.consumed;

            // Name dedup: a later question with the same name reuses the
            // first occurrence; a distinct name with a non-empty section is
            // FORMERR (the name is still appended — BIND appends then
            // records the problem).
            let section = &mut sections[SECTION_QUESTION];
            let found = section
                .iter()
                .position(|n| n.name.rdatacompare(&name) == std::cmp::Ordering::Equal);
            match found {
                None => {
                    if !section.is_empty() {
                        self.do_error(Error::FormErr, local_problem)?;
                    }
                    section.push(NameRrsets {
                        name: name.clone(),
                        rrsets: Vec::new(),
                    });
                }
                Some(i) => {
                    name = section[i].name.clone();
                }
            }

            // Type and class.
            if *pos + 4 > buf.len() {
                return Err(Error::UnexpectedEnd);
            }
            let qtype = RrType::from_u16(u16::from_be_bytes([buf[*pos], buf[*pos + 1]]));
            let qclass = Class::from_u16(u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]));
            *pos += 4;

            // Notify and update messages need to specify the data class.
            if (opcode == 4 || opcode == 5) && (qclass == Class::None || qclass == Class::Any) {
                self.do_error(Error::FormErr, local_problem)?;
            }
            // The class must be consistent across the message.
            if !*rdclass_set {
                *rdclass = qclass;
                *rdclass_set = true;
            } else if *rdclass != qclass {
                self.do_error(Error::FormErr, local_problem)?;
            }
            if qtype == RrType::Tkey {
                *tkey_question = true;
            }
            if first_question.is_none() {
                *first_question = Some(Question {
                    qname: name.clone(),
                    qtype,
                    qclass,
                });
            }

            // New question rdataset; a second question with the same
            // name+class+type is FORMERR (BIND "Can't ask the same question
            // twice"); a different type/class on the same name appends.
            let ni = section
                .iter()
                .position(|n| n.name.rdatacompare(&name) == std::cmp::Ordering::Equal)
                .expect("question name present");
            let rrsets = &mut section[ni].rrsets;
            if rrsets
                .iter()
                .any(|rr| rr.class == qclass && rr.type_ == qtype && rr.covers == 0)
            {
                self.do_error(Error::FormErr, local_problem)?;
            }
            rrsets.push(Rrset {
                class: qclass,
                type_: qtype,
                covers: 0,
                ttl: 0,
                question: true,
                rdata: Vec::new(),
            });
        }
        Ok(())
    }

    /// One non-question section (BIND `getsection`).
    #[allow(clippy::too_many_arguments)]
    fn parse_section(
        &mut self,
        pos: &mut usize,
        section: usize,
        count: u16,
        opcode: u8,
        rdclass_set: &mut bool,
        rdclass: &mut Class,
        tkey_question: bool,
        sections: &mut [Vec<NameRrsets>; 4],
        opt: &mut Option<Opt>,
        tsig: &mut Option<Name>,
        sig0: &mut Option<Name>,
        merged_rcode: &mut u16,
        local_problem: &mut bool,
    ) -> Result<()> {
        let buf = self.buf;
        for count_idx in 0..u32::from(count) {
            let mut skip_name_search = false;
            let mut skip_type_search = false;
            let mut isedns = false;
            let mut issigzero = false;
            let mut istsig = false;

            // getname.
            let fw = crate::name::wire::from_wire(buf, *pos, true)?;
            let name = fw.name;
            *pos = fw.consumed;

            // Enough bytes for type/class/ttl/rdlen.
            if *pos + 10 > buf.len() {
                return Err(Error::UnexpectedEnd);
            }
            let rdtype = RrType::from_u16(u16::from_be_bytes([buf[*pos], buf[*pos + 1]]));
            let rec_class = Class::from_u16(u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]));

            // Establish the message class from the first record if there
            // was no question (OPT/TSIG/TKEY are exempt — their class is
            // not the data class).
            if !*rdclass_set
                && rdtype != RrType::Opt
                && rdtype != RrType::Tsig
                && rdtype != RrType::Tkey
            {
                *rdclass = rec_class;
                *rdclass_set = true;
            }

            // Class consistency (update opcode exempt; meta records
            // exempt; ANY exempt).
            if opcode != 5
                && rdtype != RrType::Tsig
                && rdtype != RrType::Opt
                && rdtype != RrType::Key
                && rdtype != RrType::Sig
                && rdtype != RrType::Tkey
                && *rdclass != Class::Any
                && *rdclass != rec_class
            {
                self.do_error(Error::FormErr, local_problem)?;
            }
            // KEY must match the message class unless this is a TKEY query.
            if opcode != 5
                && !tkey_question
                && rdtype == RrType::Key
                && *rdclass != Class::Any
                && *rdclass != rec_class
            {
                self.do_error(Error::FormErr, local_problem)?;
            }

            // TSIG: additional, class ANY, and the last record.
            if rdtype == RrType::Tsig {
                if section != SECTION_ADDITIONAL
                    || rec_class != Class::Any
                    || count_idx != u32::from(count) - 1
                {
                    self.do_error(Error::BadTsig, local_problem)?;
                } else {
                    skip_name_search = true;
                    skip_type_search = true;
                    istsig = true;
                }
            } else if rdtype == RrType::Opt {
                // OPT: owner ".", additional section, first OPT.
                if !name.is_absolute()
                    || !name.as_wire_slice().is_empty()
                    || section != SECTION_ADDITIONAL
                    || opt.is_some()
                {
                    self.do_error(Error::FormErr, local_problem)?;
                } else {
                    skip_name_search = true;
                    skip_type_search = true;
                    isedns = true;
                }
            } else if rdtype == RrType::Tkey {
                // TKEY must be in the additional section for a query, the
                // answer section for a response (unless Win2000).
                let tkeysection = if buf[3] & 0x80 != 0 {
                    SECTION_ANSWER
                } else {
                    SECTION_ADDITIONAL
                };
                if section != tkeysection && section != SECTION_ANSWER {
                    self.do_error(Error::FormErr, local_problem)?;
                }
            }

            // ttl + rdlength.
            let ttl =
                u32::from_be_bytes([buf[*pos + 4], buf[*pos + 5], buf[*pos + 6], buf[*pos + 7]]);
            let rdlen = u16::from_be_bytes([buf[*pos + 8], buf[*pos + 9]]) as usize;
            *pos += 10;
            if buf.len() - *pos < rdlen {
                return Err(Error::UnexpectedEnd);
            }
            let end = *pos + rdlen;

            // getrdata → dns_rdata_fromwire (class-aware dispatch).
            if rdtype == RrType::Opt && isedns {
                // The first well-placed OPT: validated, captured separately
                // (the rdata is not part of any section).
                let o = Opt::from_wire(rec_class.to_u16(), ttl, &buf[*pos..end])?;
                *merged_rcode |= (u16::from(o.ext_rcode())) << 4;
                *opt = Some(o);
                *pos = end;
                continue;
            }
            let mut rdata = if opcode == 5 && update_section(section, rec_class) {
                // DynDNS meta-RR (RFC 2136 prerequisite/update record):
                // rdlength must be 0, and the rdata is empty with BIND's
                // DNS_RDATA_UPDATE flag (totext and towire produce
                // nothing).
                if rdlen != 0 {
                    return Err(Error::FormErr);
                }
                *pos = end;
                Rdata::UpdateMeta(rdtype)
            } else {
                // BIND parses a class-NONE record in the UPDATE section
                // (AUTHORITY) with the message class.
                let effective =
                    if opcode == 5 && section == SECTION_AUTHORITY && rec_class == Class::None {
                        *rdclass
                    } else {
                        rec_class
                    };
                let raw = buf[*pos..end].to_vec();
                let parsed = Rdata::from_wire_class(rdtype, effective, buf, pos, end)?;
                *pos = end;
                if rrtype_native_class(rdtype, rec_class) {
                    parsed
                } else {
                    // The class-gated totext would render the generic form.
                    let mut p = 0;
                    let u = UnknownRdata::from_wire(&raw, &mut p, raw.len())?.with_type(rdtype);
                    Rdata::Unknown(u)
                }
            };
            let _ = &mut rdata;

            // RRSIG / SIG covers.
            let mut covers: u16 = 0;
            if rdtype == RrType::Rrsig {
                if let Rdata::Rrsig(r) = &rdata {
                    covers = r.covered;
                    // A signature can only cover a real rdata type.
                    if covers == 0 || RrType::from_u16(covers).is_meta() {
                        self.do_error(Error::FormErr, local_problem)?;
                    }
                }
            } else if rdtype == RrType::Sig {
                if let Rdata::Sig(r) = &rdata {
                    covers = r.covered;
                    if covers == 0 {
                        // SIG(0) must be last in the additional section
                        // with owner ".".
                        if section != SECTION_ADDITIONAL
                            || count_idx != u32::from(count) - 1
                            || !name.as_wire_slice().is_empty()
                        {
                            self.do_error(Error::BadSig0, local_problem)?;
                        } else {
                            skip_name_search = true;
                            skip_type_search = true;
                            issigzero = true;
                        }
                    } else if *rdclass != Class::Any && *rdclass != rec_class {
                        self.do_error(Error::FormErr, local_problem)?;
                    }
                }
            }

            // NSEC3 owner-name check (hard error).
            if rdtype == RrType::Nsec3 && !crate::rdata::nsec3_owner_ok(&name) {
                return Err(Error::BadOwnerName);
            }

            // Name append / dedup.
            let section_list = &mut sections[section];
            let ni: Option<usize>;
            if self.options.preserve_order || opcode == 5 || skip_name_search {
                if !isedns && !istsig && !issigzero {
                    section_list.push(NameRrsets {
                        name: name.clone(),
                        rrsets: Vec::new(),
                    });
                    ni = Some(section_list.len() - 1);
                } else {
                    ni = None; // not stored in the section
                }
            } else {
                let found = section_list
                    .iter()
                    .position(|n| n.name.rdatacompare(&name) == std::cmp::Ordering::Equal);
                match found {
                    None => {
                        section_list.push(NameRrsets {
                            name: name.clone(),
                            rrsets: Vec::new(),
                        });
                        ni = Some(section_list.len() - 1);
                    }
                    Some(i) => ni = Some(i),
                }
            }

            // Rdataset attach.
            if let Some(ni) = ni {
                let rrset = Rrset {
                    class: rec_class,
                    type_: rdtype,
                    covers,
                    ttl,
                    question: false,
                    rdata: Vec::new(),
                };
                let n = &mut section_list[ni];
                if isedns || istsig || issigzero {
                    // Not added to the section tables.
                } else if self.options.preserve_order || opcode == 5 || skip_type_search {
                    n.rrsets.push(rrset);
                    n.rrsets.last_mut().expect("just pushed").rdata.push(rdata);
                } else {
                    // Question-only types are FORMERR outside the question
                    // section (checked before the rrset-merge logic, so an
                    // empty rrset list still records the problem).
                    if matches!(
                        rdtype,
                        RrType::Ixfr | RrType::Axfr | RrType::Mailb | RrType::Maila | RrType::Any
                    ) {
                        self.do_error(Error::FormErr, local_problem)?;
                    }
                    if n.rrsets.is_empty() {
                        n.rrsets.push(rrset);
                        n.rrsets.last_mut().expect("just pushed").rdata.push(rdata);
                    } else {
                        let ri = n.rrsets.iter().position(|rr| {
                            rr.class == rec_class && rr.type_ == rdtype && rr.covers == covers
                        });
                        match ri {
                            None => {
                                n.rrsets.push(rrset);
                                n.rrsets.last_mut().expect("just pushed").rdata.push(rdata);
                            }
                            Some(ri) => {
                                // Singleton types must have identical rdata
                                // (BIND: DNS_R_FORMERR via dns_rdata_compare).
                                if matches!(
                                    rdtype,
                                    RrType::Cname
                                        | RrType::Soa
                                        | RrType::Dname
                                        | RrType::Opt
                                        | RrType::Resinfo
                                ) {
                                    if let Some(first) = n.rrsets[ri].rdata.first() {
                                        if first.bind_compare(&rdata) != std::cmp::Ordering::Equal {
                                            self.do_error(Error::FormErr, local_problem)?;
                                        }
                                    }
                                }
                                // Minimize the TTL across the rdata.
                                let old = n.rrsets[ri].ttl;
                                if ttl < old {
                                    n.rrsets[ri].ttl = ttl;
                                }
                                n.rrsets[ri].rdata.push(rdata);
                            }
                        }
                    }
                }
            }

            // Pseudo-record bookkeeping.
            if issigzero {
                *sig0 = Some(name);
            } else if istsig {
                // BIND marks TSIG names nocompress (they never re-render
                // through the message path, but the attribute is part of
                // the model).
                let n = name.with_nocompress(true);
                *tsig = Some(n);
            }
        }
        Ok(())
    }
}

/// BIND `update(section, rdclass)` with the section enum aliases
/// (DNS_SECTION_PREREQUISITE == DNS_SECTION_ANSWER, DNS_SECTION_UPDATE ==
/// DNS_SECTION_AUTHORITY): a class ANY/NONE record in the answer section or
/// a class ANY record in the authority section is a DynDNS meta-RR.
fn update_section(section: usize, rdclass: Class) -> bool {
    match section {
        1 => rdclass == Class::Any || rdclass == Class::None,
        2 => rdclass == Class::Any,
        _ => false,
    }
}

/// Whether BIND has a concrete rdata implementation for `type_` in this
/// class (the class-gated `dns_rdata_fromwire`/`totext` dispatch).
fn rrtype_native_class(type_: RrType, class: Class) -> bool {
    crate::rdata::rrtype_native_class(type_, class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::Rdata;
    use std::net::Ipv4Addr;

    fn n(s: &str) -> Name {
        Name::from_text(s, Some(&Name::root())).unwrap()
    }

    /// The wire form of `s` including the root octet.
    fn nw(s: &str) -> Vec<u8> {
        let mut out = n(s).as_wire_slice().to_vec();
        out.push(0);
        out
    }

    fn hexd(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn q(labels: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = n(labels).as_wire_slice().to_vec();
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
        out
    }

    fn hdr(qd: u16, an: u16, ns: u16, ar: u16, flags: u16, id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&qd.to_be_bytes());
        out.extend_from_slice(&an.to_be_bytes());
        out.extend_from_slice(&ns.to_be_bytes());
        out.extend_from_slice(&ar.to_be_bytes());
        out
    }

    fn rr(name: Vec<u8>, rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = name;
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&rclass.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn a_rr(name: Vec<u8>, ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        rr(name, 1, 1, ttl, &ip)
    }

    fn parse_ok(buf: &[u8]) -> Message {
        let (m, st) = Message::parse_besteffort(buf).unwrap();
        assert_eq!(st, ParseStatus::Success);
        m
    }

    fn parse_rec(buf: &[u8]) -> Message {
        let (m, st) = Message::parse_besteffort(buf).unwrap();
        assert_eq!(st, ParseStatus::Recoverable);
        m
    }

    #[test]
    fn header_fields_and_rcode_merge() {
        // BADVERS wire: header rcode 0, OPT ext-rcode 1 -> merged 16.
        let wire = hexd("1234000000000000000000010000291000010000000000");
        let m = parse_ok(&wire);
        assert_eq!(m.id, 0x1234);
        assert_eq!(m.rcode, 16);
        assert_eq!(m.header_rcode, 0);
        assert_eq!(m.raw_flags, 0);
        assert_eq!(m.counts, [0, 0, 0, 1]);
        assert!(m.opt.is_some());
    }

    #[test]
    fn short_message_is_unexpected_end() {
        assert!(Message::parse_besteffort(&[]).is_err());
        assert!(Message::parse_besteffort(&[0; 11]).is_err());
    }

    #[test]
    fn two_questions_same_name_same_type_recoverable() {
        let wire = hdr(2, 0, 0, 0, 0, 0x1234)
            .into_iter()
            .chain(q("example.com", 1, 1))
            .chain(q("example.com", 1, 1))
            .collect::<Vec<_>>();
        let m = parse_rec(&wire);
        // BIND appends the duplicate question rdataset and records the
        // problem; both question rrsets are present (courted).
        assert_eq!(m.sections[0][0].rrsets.len(), 2);
        // The render emits the first question in full and the second as a
        // compression pointer; the reparse recovers and merges again.
        let mut out = Vec::new();
        m.render(&mut out, true).unwrap();
        let (m2, st2) = Message::parse_besteffort(&out).unwrap();
        assert_eq!(st2, ParseStatus::Recoverable);
        assert_eq!(m2, m);
    }

    #[test]
    fn two_questions_same_name_different_type_success() {
        let wire = hdr(2, 0, 0, 0, 0, 0x1234)
            .into_iter()
            .chain(q("example.com", 1, 1))
            .chain(q("example.com", 28, 1))
            .collect::<Vec<_>>();
        let m = parse_ok(&wire);
        assert_eq!(m.sections[0][0].rrsets.len(), 2);
        assert_eq!(m.sections[0][0].rrsets[0].type_, RrType::A);
        assert_eq!(m.sections[0][0].rrsets[1].type_, RrType::Aaaa);
    }

    #[test]
    fn update_notify_question_class_rules() {
        // update (5) with class NONE is recoverable.
        let wire = hdr(1, 0, 0, 0, 5 << 11, 0x1234)
            .into_iter()
            .chain(q("example.com", 1, 254))
            .collect::<Vec<_>>();
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
        // notify (4) with class ANY is recoverable.
        let wire = hdr(1, 0, 0, 0, 4 << 11, 0x1234)
            .into_iter()
            .chain(q("example.com", 1, 255))
            .collect::<Vec<_>>();
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
    }

    #[test]
    fn rrsets_merge_and_minimize_ttl() {
        let mut wire = hdr(1, 3, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(a_rr(nw("example.com"), 300, [192, 0, 2, 1]));
        wire.extend(a_rr(vec![0xc0, 0x0c], 100, [192, 0, 2, 2]));
        wire.extend(a_rr(vec![0xc0, 0x0c], 200, [192, 0, 2, 3]));
        let m = parse_ok(&wire);
        let sec = &m.sections[SECTION_ANSWER][0];
        assert_eq!(sec.rrsets.len(), 1);
        assert_eq!(sec.rrsets[0].rdata.len(), 3);
        assert_eq!(sec.rrsets[0].ttl, 100);
        // The flattened view carries the minimized TTL.
        assert_eq!(m.answer.len(), 3);
        assert!(m.answer.iter().all(|r| r.ttl.as_u32() == 100));
    }

    #[test]
    fn singleton_conflict_is_recoverable() {
        let mut wire = hdr(1, 2, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(rr(nw("example.com"), 5, 1, 300, &nw("x.example.com")));
        wire.extend(rr(vec![0xc0, 0x0c], 5, 1, 300, &nw("y.example.com")));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
        // Identical singleton rdata merges (case-insensitive).
        let mut wire2 = hdr(1, 2, 0, 0, 0x8180, 0x1234);
        wire2.extend(q("example.com", 1, 1));
        wire2.extend(rr(nw("example.com"), 5, 1, 300, &nw("X.Example.Com")));
        wire2.extend(rr(vec![0xc0, 0x0c], 5, 1, 300, &nw("x.example.com")));
        let m = parse_ok(&wire2);
        assert_eq!(m.sections[SECTION_ANSWER][0].rrsets[0].rdata.len(), 2);
    }

    #[test]
    fn question_only_type_in_answer_recoverable() {
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(rr(vec![0xc0, 0x0c], 251, 1, 300, &[]));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
    }

    #[test]
    fn opt_placement_rules() {
        // OPT outside the additional section is recoverable.
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(hexd("0000291000000000000000"));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
        // A second OPT is recoverable; the first is captured.
        let mut wire = hdr(1, 0, 0, 2, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(hexd("0000291000000000000000"));
        wire.extend(hexd("0000291000000000000000"));
        let (m, st) = Message::parse_besteffort(&wire).unwrap();
        assert_eq!(st, ParseStatus::Recoverable);
        assert!(m.opt.is_some());
    }

    #[test]
    fn opt_option_validation() {
        // LLQ with the wrong length is a hard OPTERR.
        let wire =
            hexd("123400000000000000000001000029100000000000000e0001000a000000000000000000000000");
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Err(Error::Opterr)
        ));
        // Truncated option header is a hard UNEXPECTEDEND.
        let wire = hexd("123400000000000000000001000029100000000000000100");
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Err(Error::UnexpectedEnd)
        ));
    }

    #[test]
    fn tsig_placement() {
        let tsig = hexd(
            "0000fa00ff00000000001d0b686d61632d73686132353600030405060708012c0000123400000000",
        );
        // Last in additional, class ANY: success.
        let mut wire = hdr(1, 0, 0, 1, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(&tsig);
        let (m, st) = Message::parse_besteffort(&wire).unwrap();
        assert_eq!(st, ParseStatus::Success);
        assert!(m.tsig.is_some());
        // Not last: recoverable (BADTSIG).
        let mut wire = hdr(1, 0, 0, 2, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(&tsig);
        wire.extend(a_rr(vec![0xc0, 0x0c], 300, [192, 0, 2, 1]));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
    }

    #[test]
    fn rrsig_covers_meta_recoverable() {
        let rrsig = hexd("0029080200000e1000000064000000643039076578616d706c6503636f6d0001");
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(rr(vec![0xc0, 0x0c], 46, 1, 3600, &rrsig));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Ok((_, ParseStatus::Recoverable))
        ));
    }

    #[test]
    fn nsec3_owner_check_hard() {
        // owner "example.com." (not base32hex) -> BADOWNERNAME.
        let nsec3 = hexd("0100000000141111111111111111111111111111111111111111000160");
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(rr(vec![0xc0, 0x0c], 50, 1, 3600, &nsec3));
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Err(Error::BadOwnerName)
        ));
    }

    #[test]
    fn update_meta_class_rules() {
        // update + class NONE A with rdlen 4 -> hard FORMERR (prerequisite
        // records must have empty rdata).
        let mut wire = hdr(1, 1, 0, 0, 5 << 11, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(a_rr(vec![0xc0, 0x0c], 300, [192, 0, 2, 1]));
        // patch the class to NONE (the rr name is the c00c pointer, so the
        // class sits after pointer(2) + type(2)).
        let off = 12 + q("example.com", 1, 1).len() + 2 + 2;
        wire[off] = 0;
        wire[off + 1] = 254;
        assert!(matches!(
            Message::parse_besteffort(&wire),
            Err(Error::FormErr)
        ));
        // rdlen 0 -> the empty update meta rdata parses.
        let mut wire = hdr(1, 1, 0, 0, 5 << 11, 0x1234);
        wire.extend(q("example.com", 1, 1));
        let mut r = Vec::new();
        r.extend(vec![0xc0, 0x0c]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&254u16.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        wire.extend(&r);
        let m = parse_ok(&wire);
        assert_eq!(
            m.sections[SECTION_ANSWER][0].rrsets[0].rdata[0].to_text(),
            ""
        );
    }

    #[test]
    fn render_roundtrip_with_compression() {
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("www.example.com", 1, 1));
        wire.extend(a_rr(vec![0xc0, 0x0c], 300, [192, 0, 2, 1]));
        let m = parse_ok(&wire);
        let mut out = Vec::new();
        m.render(&mut out, true).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn render_tc_with_opt_drops_sections() {
        // TC + OPT: renderend resets everything but the question.
        let mut wire = hdr(1, 1, 0, 1, 0x8180 | 0x0200, 0x1234);
        wire.extend(q("example.com", 1, 1));
        wire.extend(a_rr(vec![0xc0, 0x0c], 300, [192, 0, 2, 1]));
        wire.extend(hexd("0000291000000000000000"));
        let m = parse_ok(&wire);
        let mut out = Vec::new();
        m.render(&mut out, true).unwrap();
        let re = parse_ok(&out);
        assert_eq!(re.counts[1], 0); // no answer records
        assert_eq!(re.counts[3], 1); // just the OPT
    }

    #[test]
    fn extended_rcode_without_opt_renders_formerr() {
        let mut wire = hdr(1, 0, 0, 0, 0, 0x1234);
        wire.extend(q("example.com", 1, 1));
        let m = parse_ok(&wire);
        let mut m2 = m.clone();
        m2.rcode = 0x100;
        let mut out = Vec::new();
        assert!(matches!(m2.render(&mut out, true), Err(Error::FormErr)));
    }

    #[test]
    fn unknown_class_records_render_generic() {
        // A class-5 A record parses as the generic RFC 3597 form (the
        // question carries the same class so the class check passes).
        let mut wire = hdr(1, 1, 0, 0, 0x8180, 0x1234);
        wire.extend(q("example.com", 1, 5));
        let mut r = Vec::new();
        r.extend(vec![0xc0, 0x0c]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&5u16.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[192, 0, 2, 1]);
        wire.extend(&r);
        let m = parse_ok(&wire);
        assert_eq!(
            m.sections[SECTION_ANSWER][0].rrsets[0].rdata[0].to_text(),
            "\\# 4 C0000201"
        );
        let _ = Rdata::A(Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn question_section_renders_without_rdata() {
        let wire = hdr(1, 0, 0, 0, 0x0100, 0xbeef)
            .into_iter()
            .chain(q("www.example.com", 1, 1))
            .collect::<Vec<_>>();
        let m = parse_ok(&wire);
        let mut out = Vec::new();
        m.render(&mut out, true).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn name_merge_is_case_insensitive() {
        let mut wire = hdr(1, 2, 0, 0, 0x8180, 0x1234);
        wire.extend(q("Www.Example.Com", 1, 1));
        let n1 = nw("Www.Example.Com");
        wire.extend(a_rr(n1, 300, [192, 0, 2, 1]));
        wire.extend(a_rr(vec![0xc0, 0x0c], 100, [192, 0, 2, 2]));
        let m = parse_ok(&wire);
        assert_eq!(m.sections[SECTION_ANSWER].len(), 1);
        assert_eq!(m.sections[SECTION_ANSWER][0].rrsets[0].rdata.len(), 2);
        // The first spelling is kept.
        assert_eq!(
            m.sections[SECTION_ANSWER][0].name.to_text(),
            "Www.Example.Com."
        );
    }

    #[test]
    fn dig_parse_swallows_recoverable() {
        // dig's parse flags: recoverable parses return Ok.
        let wire = hdr(2, 0, 0, 0, 0, 0x1234)
            .into_iter()
            .chain(q("example.com", 1, 1))
            .chain(q("example.com", 1, 1))
            .collect::<Vec<_>>();
        assert!(Message::parse(&wire).is_ok());
    }
}
