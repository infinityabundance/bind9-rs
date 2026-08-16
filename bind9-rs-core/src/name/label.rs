//! A DNS label: 1..=63 octets (BIND `dns_label_t` view).

use super::MAX_LABEL;

/// A single DNS label, borrowed from a [`super::Name`].
///
/// The wire form of a label is a length octet followed by the label octets;
/// `Label` holds the *body* (without the length octet).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label<'a> {
    body: &'a [u8],
}

impl<'a> Label<'a> {
    /// Construct from a wire-form label slice (length octet + body).
    /// Panics if the slice is empty or the length octet exceeds the slice —
    /// callers are internal iterators over validated names.
    #[must_use]
    pub(crate) fn from_slice(wire: &'a [u8]) -> Self {
        assert!(!wire.is_empty(), "empty label wire slice");
        let len = wire[0] as usize;
        assert!(
            len <= MAX_LABEL && 1 + len <= wire.len(),
            "invalid label wire slice"
        );
        Label {
            body: &wire[1..1 + len],
        }
    }

    /// The label body octets (without the length octet).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.body
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

impl<'a> core::fmt::Debug for Label<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Label({:?})", String::from_utf8_lossy(self.body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_from_wire() {
        let wire = [3u8, b'a', b'b', b'c'];
        let l = Label::from_slice(&wire);
        assert_eq!(l.as_bytes(), b"abc");
        assert_eq!(l.len(), 3);
    }

    #[test]
    #[should_panic]
    fn bad_length_panics() {
        let wire = [5u8, b'a', b'b'];
        let _ = Label::from_slice(&wire);
    }
}
