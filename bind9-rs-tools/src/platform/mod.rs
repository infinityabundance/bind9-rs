//! OS-specific behavior and the audited unsafe boundary (§1 `platform/`).
//!
//! This module is the ONLY place in `bind9-rs-tools` where `unsafe` is
//! contemplated (addendum §49): every unsafe site requires an explicit
//! invariant, scope justification, tests, Miri/sanitizer/fuzz coverage where
//! meaningful, and an unsafe-inventory entry.  The tools' production code is
//! safe Rust; platform mechanics (TTY termios, capabilities, filesystem
//! modes, signals) terminate here.
//!
//! `bind9-rs-platform` owns the *server* OS boundary; this module covers the
//! *tool* boundary (terminals, key-file permissions, `resolv.conf`,
//! local-timezone rendering, process behavior).

pub mod capabilities;
pub mod filesystem;
pub mod linux;
pub mod networking;
pub mod terminal;
pub mod unix;
pub mod unsafe_boundary;
