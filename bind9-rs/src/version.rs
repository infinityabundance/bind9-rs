//! Version reporting (§4.1).
//!
//! BIND's version surface is externally observable (`named -v`, `dig -v`,
//! the version.bind CH TXT record, `rndc status` version line).  The shapes
//! here are courted against the oracle (`CLI-VERSION-*`, `CHAOS-VERSION-*`);
//! the exact strings are *not* copied from BIND — bind9-rs reports its own
//! identity while reproducing the format so that parsers of version output
//! keep working.

/// The bind9-rs release string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The BIND compatibility target line (which BIND line this build courts
/// against).  Updated by the oracle bootstrap process (spec §81); recorded
/// in receipts.
pub const COMPAT_TARGET: &str = "9.20";

/// Render a `named -v`-style version line.
///
/// BIND shape: `BIND 9.20.0 (Extended Support Version) <id>` — one line,
/// version, parenthesized flavor, then the build id.  Court
/// `CLI-VERSION-NAMED` verifies placement/shape against the oracle; the
/// content is our own.
#[must_use]
pub fn named_version_line() -> String {
    format!("bind9-rs {VERSION} (native-rust-bind9-compat {COMPAT_TARGET})")
}

/// Render a `dig -v`-style version line.
#[must_use]
pub fn dig_version_line() -> String {
    format!("DiG {VERSION} (bind9-rs, BIND-compat target {COMPAT_TARGET})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let n = named_version_line();
        assert!(n.starts_with("bind9-rs "));
        assert!(n.contains('('));
        assert!(n.ends_with(')'));
        let d = dig_version_line();
        assert!(d.starts_with("DiG "));
    }
}
