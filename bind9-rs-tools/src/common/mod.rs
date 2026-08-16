//! Shared machinery for every tool (§1 `common/`).
//!
//! Tools share protocol and semantic implementations; they equally share the
//! operational glue: argument parsing conventions, output rendering
//! (`dns_master_style` column layout), diagnostics, environment and
//! `resolv.conf` interpretation, filesystem habits, TTY behavior, time
//! formatting (including the local-date/`%Z` rendering dig relies on), and
//! version reporting.
//!
//! Each submodule is courted at the CLI boundary (CLI-* courts); the module
//! exists so the machinery is implemented once and shared, exactly as BIND
//! shares it across `dig`/`host`/`nslookup`/`delv` (dighost.c heritage).

pub mod cli;
pub mod compatibility;
pub mod diagnostics;
pub mod environment;
pub mod filesystem;
pub mod output;
pub mod resolver_config;
pub mod time;
pub mod tty;
pub mod versioning;
