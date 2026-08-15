//! `bind9-core` — DNS semantics and protocol machinery (§4.2).
//!
//! Everything in this crate is about DNS itself.  The module hierarchy is
//! grouped by concern:
//!
//! ```text
//! name/            names and labels: text, wire, comparison, compression
//! rdata/           the RDATA framework and individual type implementations
//! message/         header, question, wire parse/render
//! edns/            EDNS, OPT, cookies, ECS, EDE (as they land)
//! presentation/    masterfile lexer/parser
//! zone/            zone databases, trees, journals, transfers (later phases)
//! resolver/        the recursive state machine (later phases)
//! cache/           cache hierarchy (later phases)
//! dnssec/          validation and signing (later phases)
//! ```
//!
//! The full intended taxonomy is documented in
//! `docs/architecture/module-layout.md`; modules appear here only once they
//! contain real implementation — scaffolding is not claimed as implemented
//! (§66).
//!
//! Protocol invariants must be obvious in this crate (§4.2): wire parsing is
//! defensive, no unchecked indexing, no arithmetic overflow, no unbounded
//! recursion, bounded allocations, compression loops rejected, no
//! attacker-controlled memory amplification.

#![forbid(unsafe_code)]

/// DNS classes (IN, CH, HS, NONE, ANY, ...).
pub mod class;
/// EDNS machinery.
pub mod edns;
/// Shared error taxonomy, modeled on the DNS/ISC result codes whose
/// observable behavior we must reproduce.
pub mod error;
/// DNS message structure: header, question, sections.
pub mod message;
/// DNS names and labels.
pub mod name;
/// Master file presentation: lexer, parser, $directives.
pub mod presentation;
/// Response codes, including the extended-rcode path through EDNS.
pub mod rcode;
/// The RDATA framework and concrete type implementations.
pub mod rdata;
/// DNS RR types, including unknown types.
pub mod rrtype;
/// RFC 1982 serial number arithmetic as BIND implements it.
pub mod serial;
/// TTL handling and the rules that govern cache lifetimes.
pub mod ttl;
/// Wire-level helpers shared across modules.
pub mod wire;

pub use error::{Error, Result};
