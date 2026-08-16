//! `named` version reporting (Phase 7 surface; shape courted from Phase 2).
//!
//! The `named -v` and `named -V` outputs are externally consumed by
//! packaging scripts and monitoring (court `CLI-VERSION-NAMED`).  Shape
//! matches BIND; content is bind9-rs's own identity.

/// The bind9-rs release string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The BIND compatibility target line.
pub const COMPAT_TARGET: &str = "9.20";

/// `named -v`-style one-line version.
#[must_use]
pub fn version_line() -> String {
    format!("bind9-rs {VERSION} (native-rust-bind9-compat {COMPAT_TARGET})")
}

/// `named -V`-style verbose version block.
#[must_use]
pub fn version_block() -> String {
    // BIND's -V prints: BIND version, compiler, libraries, threads, and
    // build options.  The shape is courted; the values are our own.
    format!(
        "{}\ncompiled by {} {}\nlinked to {}\n",
        version_line(),
        rustc_version(),
        std::env::consts::OS,
        version_line()
    )
}

/// A compact rustc identification (real values, stable shape).
#[must_use]
pub fn rustc_version() -> String {
    format!(
        "rustc {} ({})",
        option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        std::env::consts::ARCH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_shape() {
        let l = version_line();
        assert!(l.starts_with("bind9-rs "));
        let b = version_block();
        assert!(b.contains('\n'));
    }
}
