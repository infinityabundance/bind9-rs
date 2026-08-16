//! Evidence-derived utility manifest and version history (§2, §8, §59).
//!
//! The manifest is generated, never hand-maintained as truth:
//! `scripts/archaeology/build-utility-index.sh` scans extracted BIND
//! release trees (every release line) and writes the machine-readable
//! utility history consumed here.

pub mod manifest;
