//! Randomness and entropy.
//!
//! The OS CSPRNG via the audited `getrandom` crate — the same source BIND
//! uses (getrandom(2) / getentropy).  Used for: DNS COOKIE server secrets,
//! TSIG/TKEY nonces, random session IDs, and deterministic test seeds
//! (where a fixed seed is explicitly requested).

use getrandom::getrandom as _getrandom;

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// Failure means the operating system refused entropy, which is not
/// recoverable for cookie/TSIG material; callers that can fall back to a
/// lower-security source must not use this function.
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), EntropyError> {
    _getrandom(buf).map_err(|e| EntropyError { source: e })
}

/// Fill a u64 from the CSPRNG.
pub fn fill_u64() -> Result<u64, EntropyError> {
    let mut b = [0u8; 8];
    fill_bytes(&mut b)?;
    Ok(u64::from_ne_bytes(b))
}

/// An entropy failure.  `source` is the underlying OS error.
#[derive(Debug)]
pub struct EntropyError {
    source: getrandom::Error,
}

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entropy failure: {}", self.source)
    }
}

impl std::error::Error for EntropyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_entropy() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_bytes(&mut a).unwrap();
        fill_bytes(&mut b).unwrap();
        // Two 64-byte draws colliding is astronomically unlikely.
        assert_ne!(a, b);
        assert!(!a.iter().all(|&x| x == 0));
    }

    #[test]
    fn u64_works() {
        let _ = fill_u64().unwrap();
    }
}
