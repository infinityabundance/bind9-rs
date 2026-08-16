//! Evidence hashing (§45, §46).
//!
//! Receipts and manifests carry SHA-256 digests of inputs, outputs, sources
//! and environment observations.  `sha2` is the deliberately chosen, audited
//! hash implementation.

use sha2::{Digest, Sha256};

/// Hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_of(&h.finalize())
}

/// Hex SHA-256 of a file's contents.
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_of(&h.finalize()))
}

fn hex_of(d: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(d.len() * 2);
    for &b in d {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256 of "abc".
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn file_hashing() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("bind9rs-hash-test-{}", std::process::id()));
        std::fs::write(&p, b"hello").unwrap();
        assert_eq!(sha256_file(&p).unwrap(), sha256_hex(b"hello"));
        std::fs::remove_file(&p).unwrap();
    }
}
