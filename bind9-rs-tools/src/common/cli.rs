//! Shared CLI conventions: argument parsing helpers and the option
//! vocabulary (short options, `+options`, aliases, historical aliases,
//! abbreviations — §16, §32).  The exact grammar is per-tool; the shared
//! machinery here handles the common shape (e.g. `@server`, `-x`, batch
//! files, `.digrc`).
//!
//! Status: ARCHAEOLOGY — the dig-specific grammar lives in
//! `tools::dig::options`; this module is the consolidation target as the
//! tool family lands.
