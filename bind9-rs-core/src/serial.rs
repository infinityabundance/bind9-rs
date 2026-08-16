//! RFC 1982 serial number arithmetic, as BIND implements it.
//!
//! BIND's observable rules (zone serial handling, journaling, IXFR):
//! - `serial_gt(a, b)` — "a is greater than b" in serial space: true iff
//!   `(a - b) % 2^32` is nonzero and < 2^31.  Equal serials are NOT greater.
//! - `serial_lt` is the inverse.
//! - The zone serial that "is greater than" all others is
//!   `(current + 1) % 2^32` when the current serial is < 2^32 - 1 ... BIND
//!   computes the next serial as `current + 1` (wrapping at 2^32).
//!
//! These exact semantics matter for dynamic update SOA bumps, IXFR deltas and
//! NOTIFY comparisons; the arithmetic here is the substrate every later
//! phase courts against.

/// Compare two serials under RFC 1982: returns `true` if `a` is *greater*
/// than `b` in serial space.
///
/// This is the exact predicate BIND uses (`dns_serial_gt`):
/// `a != b && ((a - b) & 0xffffffff) < 0x80000000` — i.e. the unsigned
/// difference is in the upper half of the space but not exactly 2^31.
#[must_use]
pub const fn serial_gt(a: u32, b: u32) -> bool {
    // Difference computed with wrapping (u32 subtraction); the RFC's "serial
    // arithmetic" is exactly this wrapping subtraction.
    let diff = a.wrapping_sub(b);
    diff != 0 && (diff as u32) < 0x8000_0000
}

/// `a` is *less* than `b` in serial space: `b` is greater than `a`.
#[must_use]
pub const fn serial_lt(a: u32, b: u32) -> bool {
    serial_gt(b, a)
}

/// Add to a serial, wrapping modulo 2^32 (RFC 1982 addition).
#[must_use]
pub const fn serial_add(a: u32, n: u32) -> u32 {
    a.wrapping_add(n)
}

/// The "next" serial after `a` (wrapping).
#[must_use]
pub const fn next_serial(a: u32) -> u32 {
    a.wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_1982_vectors() {
        // RFC 1982 §3.2 worked examples.
        assert!(serial_gt(1, 0));
        assert!(serial_gt(2, 1));
        assert!(serial_gt(2, 0));
        assert!(!serial_gt(0, 0));
        assert!(!serial_gt(0, 1));
        assert!(!serial_gt(1, 2));
        // The midpoint is not greater (indeterminate per RFC).
        assert!(!serial_gt(0x8000_0000, 0));
        assert!(!serial_gt(0, 0x8000_0000));
    }

    #[test]
    fn wrap_behavior() {
        // After wrapping, a serial just past the wrap is greater than the max.
        assert!(serial_gt(1, u32::MAX));
        assert!(serial_gt(u32::MAX, u32::MAX - 1));
        assert!(!serial_gt(u32::MAX, 1));
        assert_eq!(next_serial(u32::MAX), 0);
    }

    #[test]
    fn lt_mirror() {
        assert!(serial_lt(0, 1));
        assert!(serial_lt(1, 2));
        assert!(!serial_lt(1, 1));
        assert!(!serial_lt(2, 1));
    }
}
