//! Time sources.
//!
//! BIND's observable timing behavior (TTL aging, SOA refresh schedules,
//! DNSSEC signature validity windows, serve-stale) depends on the system
//! clock.  The platform crate exposes a `Clock` abstraction so that the
//! resolver/zone state machines can be courted with deterministic time
//! (§26, §45): production uses `SystemClock`, tests and virtual-time courts
//! use `TestClock`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A monotone clock in seconds (BIND's `isc_time_seconds`).
pub trait Clock: Send + Sync {
    /// Current time as seconds since the Unix epoch.
    fn now_secs(&self) -> u64;
}

/// The real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// A controllable clock for deterministic tests and virtual-time courts.
///
/// Starts at a caller-chosen epoch (default: the Unix epoch) and advances
/// only via [`TestClock::advance`].  Shared between threads when wrapped in
/// `Arc`.
#[derive(Debug, Default)]
pub struct TestClock {
    now: AtomicU64,
}

impl TestClock {
    #[must_use]
    pub fn new(epoch_secs: u64) -> Self {
        TestClock {
            now: AtomicU64::new(epoch_secs),
        }
    }

    /// Advance the clock; returns the new time.
    pub fn advance(&self, by: Duration) -> u64 {
        self.now.fetch_add(by.as_secs(), Ordering::SeqCst) + by.as_secs()
    }

    /// Set the clock to an absolute value.
    pub fn set(&self, secs: u64) {
        self.now.store(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// A clock that is frozen at a fixed time.
#[derive(Debug, Clone, Copy)]
pub struct FrozenClock(pub u64);

impl Clock for FrozenClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_roughly_now() {
        let now = SystemClock.now_secs();
        let approx = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(approx) < 2);
    }

    #[test]
    fn test_clock_controllable() {
        let c = TestClock::new(1_000_000);
        assert_eq!(c.now_secs(), 1_000_000);
        let t = c.advance(Duration::from_secs(3600));
        assert_eq!(t, 1_003_600);
        assert_eq!(c.now_secs(), 1_003_600);
        c.set(42);
        assert_eq!(c.now_secs(), 42);
    }
}
