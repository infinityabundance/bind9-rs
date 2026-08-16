//! Every BIND 9 utility, historical and current (§2).
//!
//! Each tool is its own module with its own binary target (`src/bin/`),
//! sharing machinery through [`crate::common`] and protocol semantics
//! through `bind9-rs-core`.  Tools are never formatting wrappers around one
//! another (addendum §18): `host`, `nslookup`, `delv` and `mdig` each
//! preserve their own artifact behavior even where BIND historically shares
//! implementation machinery.
//!
//! The authoritative inventory of which tools exist, when they appeared,
//! changed or were removed is the evidence-derived utility manifest
//! ([`crate::historical::manifest`]); `tools/` mirrors that manifest.

pub mod arpaname;
pub mod ddns_confgen;
pub mod delv;
pub mod dig;
pub mod dnssec;
pub mod dnstap_read;
pub mod host;
pub mod mdig;
pub mod named_checkconf;
pub mod named_checkzone;
pub mod named_compilezone;
pub mod named_journalprint;
pub mod named_makejournal;
pub mod named_nzd2nzf;
pub mod named_rrchecker;
pub mod named_wireformat;
pub mod nsec3hash;
pub mod nslookup;
pub mod nsupdate;
pub mod rndc;
pub mod rndc_confgen;
pub mod tsig_keygen;
