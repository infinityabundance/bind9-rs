//! Compatibility profiles (§58).
//!
//! Historical behavior is *preserved as knowledge and tests* everywhere; it
//! becomes *runtime* behavior only through an explicit profile backed by
//! evidence (courts + version-delta records).  The archive understands all
//! history; the production binary implements selected historical modes.
//!
//! A profile is only introduced when there is a real use case and evidence —
//! no profile exists purely because the archaeology is interesting.

/// A runtime compatibility profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Default modern behavior, targeting the current BIND stable line.
    Current,
    /// BIND 9.20 behavior.
    Bind9_20,
    /// BIND 9.18 behavior.
    Bind9_18,
    /// BIND 9.16 behavior.
    Bind9_16,
}

impl Profile {
    /// The default profile for a fresh installation.
    #[must_use]
    pub const fn default_profile() -> Self {
        Profile::Current
    }

    /// Whether this profile is implemented as a runtime mode yet.  Profiles
    /// appear in the enum as the archaeology documents them, but runtime
    /// parity gates on `forensics/receipts/` evidence (see
    /// `docs/compatibility/parity-ledger.md`).
    #[must_use]
    pub const fn runtime_supported(self) -> bool {
        matches!(self, Profile::Current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_current() {
        assert_eq!(Profile::default_profile(), Profile::Current);
        assert!(Profile::Current.runtime_supported());
    }
}
