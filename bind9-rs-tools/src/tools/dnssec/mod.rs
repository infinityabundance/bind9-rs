//! The DNSSEC tool family (§23): keygen, signzone, verify, dsfromkey, cds,
//! importkey, keyfromlabel, revoke, settime, ksr — each implemented
//! individually while sharing validated modules (key file formats, key
//! naming, timing syntax, algorithm aliases, KSK/ZSK/CSK semantics).
//!
//! Cryptography is never invented (spec §25): audited primitives only,
//! while conserving BIND-facing behavior.  The family is treated as major
//! infrastructure, not a checkbox (§23).

pub mod cds;
pub mod dsfromkey;
pub mod importkey;
pub mod keyfromlabel;
pub mod keygen;
pub mod ksr;
pub mod revoke;
pub mod settime;
pub mod signzone;
pub mod verify;
