//! LMDB (BIND: catalog zones, runtime-zone persistence, `dns_lmdb`).  On-disk page-level interoperability is the courted contract (§24, §25): C LMDB creates → Rust opens/modifies → C LMDB reopens, and reverse (§38).
//!
//! Status: ARCHAEOLOGY — the C surface is archived in the doxygen atlas
//! (`forensics/atlas/doxygen/`); implementation and courts land per §64.
