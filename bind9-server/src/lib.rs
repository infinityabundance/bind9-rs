//! `bind9-server` — the `named` runtime (§4.3).
//!
//! `named` behavior is a lifecycle, not merely "receive packet, answer".
//! Startup, configuration semantics, zones, listeners, the query pipeline,
//! transfers, updates, DNSSEC maintenance, the control channel, reload and
//! reconfiguration, logging, statistics, and graceful shutdown are modeled
//! here as explicit state machines (§52) and courted against the oracle.
//!
//! Phase 3+ in the implementation order (§63): authoritative serving first,
//! then zone lifecycle, then recursion, then operational surface.

#![forbid(unsafe_code)]

/// Version identity strings modeled on `named -v` output.
pub mod version;

/// High-level runtime configuration entry point (Phase 3).
pub mod config;
