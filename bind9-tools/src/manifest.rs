//! Historical utility manifest (§4.4).
//!
//! The authoritative table is generated from evidence: for every BIND 9
//! release line, which executables shipped, when they appeared, changed,
//! were renamed, deprecated or removed.  The generator lives in
//! `scripts/archaeology/build-utility-index.sh` and writes
//! `forensics/archaeology/utility-index.json`; the generator scans upstream
//! source trees (`bin/` layouts) plus CHANGES/release-notes archaeology.
//!
//! The static table here is the *known-from-spec* seed list; `first_known`
//! fields are filled from evidence as archaeology lands.  A utility with
//! `None` is listed in the manifest but not yet archaeologically dated —
//! never claimed to be dated.

/// A shipped BIND 9 utility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utility {
    /// Executable name.
    pub name: &'static str,
    /// First release line where evidence places it (None = undated).
    pub first_known: Option<&'static str>,
    /// Last release line where evidence places it (None = still shipping).
    pub last_known: Option<&'static str>,
    /// Short note on status/renames where archaeology has something to say.
    pub note: &'static str,
}

/// The seed manifest (spec §4.4 list).  Version dating is archaeology
/// output; the schema is the contract.
pub const UTILITIES: &[Utility] = &[
    Utility {
        name: "dig",
        first_known: None,
        last_known: None,
        note: "core query tool",
    },
    Utility {
        name: "host",
        first_known: None,
        last_known: None,
        note: "simple query tool",
    },
    Utility {
        name: "nslookup",
        first_known: None,
        last_known: None,
        note: "legacy query tool",
    },
    Utility {
        name: "delv",
        first_known: None,
        last_known: None,
        note: "DNSSEC lookup/validation tool",
    },
    Utility {
        name: "mdig",
        first_known: None,
        last_known: None,
        note: "multi-query dig",
    },
    Utility {
        name: "nsupdate",
        first_known: None,
        last_known: None,
        note: "dynamic update client",
    },
    Utility {
        name: "rndc",
        first_known: None,
        last_known: None,
        note: "control client",
    },
    Utility {
        name: "rndc-confgen",
        first_known: None,
        last_known: None,
        note: "rndc key generator",
    },
    Utility {
        name: "named-checkconf",
        first_known: None,
        last_known: None,
        note: "config checker",
    },
    Utility {
        name: "named-checkzone",
        first_known: None,
        last_known: None,
        note: "zone checker",
    },
    Utility {
        name: "named-compilezone",
        first_known: None,
        last_known: None,
        note: "zone compiler (raw format)",
    },
    Utility {
        name: "named-journalprint",
        first_known: None,
        last_known: None,
        note: "journal dumper",
    },
    Utility {
        name: "arpaname",
        first_known: None,
        last_known: None,
        note: "IP -> in-addr/ip6.arpa names",
    },
    Utility {
        name: "tsig-keygen",
        first_known: None,
        last_known: None,
        note: "TSIG key generator",
    },
    Utility {
        name: "ddns-confgen",
        first_known: None,
        last_known: None,
        note: "ddns key/sample generator",
    },
    Utility {
        name: "dnssec-keygen",
        first_known: None,
        last_known: None,
        note: "DNSSEC key generator",
    },
    Utility {
        name: "dnssec-signzone",
        first_known: None,
        last_known: None,
        note: "zone signer",
    },
    Utility {
        name: "dnssec-verify",
        first_known: None,
        last_known: None,
        note: "zone signature verifier",
    },
    Utility {
        name: "dnssec-dsfromkey",
        first_known: None,
        last_known: None,
        note: "DS from DNSKEY",
    },
    Utility {
        name: "dnssec-importkey",
        first_known: None,
        last_known: None,
        note: "import key into key dir",
    },
    Utility {
        name: "dnssec-revoke",
        first_known: None,
        last_known: None,
        note: "revoke a key",
    },
    Utility {
        name: "dnssec-settime",
        first_known: None,
        last_known: None,
        note: "key timing metadata",
    },
    Utility {
        name: "dnssec-cds",
        first_known: None,
        last_known: None,
        note: "CDS/CDNSKEY -> DS update",
    },
    Utility {
        name: "dnssec-keyfromlabel",
        first_known: None,
        last_known: None,
        note: "key from PKCS#11 label",
    },
    Utility {
        name: "named",
        first_known: None,
        last_known: None,
        note: "the name server daemon",
    },
];

/// Look up a utility by name.
#[must_use]
pub fn find(name: &str) -> Option<&'static Utility> {
    UTILITIES.iter().find(|u| u.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_no_duplicates() {
        let mut names: Vec<&str> = UTILITIES.iter().map(|u| u.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), UTILITIES.len());
    }

    #[test]
    fn lookup() {
        assert!(find("dig").is_some());
        assert!(find("nonexistent-tool").is_none());
    }
}
