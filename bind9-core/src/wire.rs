//! Wire-level helpers shared across modules.

pub mod hex {
    //! Hex encode/decode for presentation forms and test fixtures.

    /// Decode a hex string (even length, lowercase or uppercase digits).
    pub fn from_hex(s: &[u8]) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in s.chunks_exact(2) {
            let hi = nibble(pair[0])?;
            let lo = nibble(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn nibble(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    }

    /// Encode bytes to lowercase hex.
    #[must_use]
    pub fn to_hex(data: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(data.len() * 2);
        for &b in data {
            out.push(DIGITS[(b >> 4) as usize] as char);
            out.push(DIGITS[(b & 0x0f) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::hex::{from_hex, to_hex};

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(from_hex(b"DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(from_hex(b"abc").is_err());
        assert!(from_hex(b"zz").is_err());
        assert!(from_hex(b"").unwrap().is_empty());
    }
}
