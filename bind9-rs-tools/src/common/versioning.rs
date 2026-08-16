//! Version identity for the tools (§32: `dig -v` output is courted against
//! the oracle).  For the pinned BIND 9.20.26 profile the output is
//! byte-exact: `DiG 9.20.26`.

/// The bind9-rs release string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The BIND compatibility target (the pinned oracle release line).
pub const COMPAT_TARGET: &str = "9.20.26";

/// `dig -v`-style line: `DiG <version>`.
#[must_use]
pub fn dig_version_line() -> String {
    // Byte-exact BIND 9.20.26 surface (`dig -v` prints exactly this).
    format!("DiG {COMPAT_TARGET}")
}

/// `dig -v` second line.
#[must_use]
pub fn dig_version_line2() -> String {
    format!(
        "built with rustc {} ({})",
        rustc_version(),
        std::env::consts::OS
    )
}

/// A compact rustc identification.
#[must_use]
pub fn rustc_version() -> String {
    option_env!("RUSTC_VERSION")
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dig_banner_shape() {
        let l = dig_version_line();
        assert!(l.starts_with("DiG "));
    }
}
