//! `probe-name-compare` — bind9-rs side of the `CORE-NAME-COMPARE-*`
//! courts.  Mirrors `forensics/oracle/probes/probe_name_compare.c`:
//! lines of `name1|name2`, output `OK <compare> <namereln> <nlabels>
//! <subdomain> <isequal> <rdatacompare>` or `ERR <result-text>`.
//!
//! The `<compare>` value reproduces `dns_name_fullcompare`'s raw order:
//! the lowercmp byte difference (-1/0/1) of the first differing label,
//! else the label-length difference, else the label-count difference
//! (l1 - l2, which is NOT normalized — e.g. `".|example.com."` yields -2).

use bind9_core::name::Name;
use std::cmp::Ordering;
use std::io::{BufRead, Write};

fn main() {
    let root = Name::root();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap_or_default();
        if line.is_empty() {
            continue;
        }
        let Some((a, b)) = line.split_once('|') else {
            let _ = writeln!(out, "ERR bad input");
            continue;
        };
        let Ok(n1) = Name::from_text(a, Some(&root)) else {
            let _ = writeln!(out, "ERR name1");
            continue;
        };
        let Ok(n2) = Name::from_text(b, Some(&root)) else {
            let _ = writeln!(out, "ERR name2");
            continue;
        };
        let cmp = raw_order(&n1, &n2);
        let (rel, nlabels) = fullcompare(&n1, &n2);
        let subdomain = if n1.is_subdomain(&n2) { 1 } else { 0 };
        // dns_name_equal is case-insensitive (compare == 0), unlike
        // PartialEq on the stored bytes.
        let isequal = if n1.compare(&n2) == Ordering::Equal {
            1
        } else {
            0
        };
        let rdcmp = ord(&n1.rdatacompare(&n2));
        let _ = writeln!(
            out,
            "OK {cmp} {rel} {nlabels} {subdomain} {isequal} {rdcmp}"
        );
    }
}

fn ord(o: &Ordering) -> i8 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// BIND's label list including the root label (empty body) for absolute
/// names.
fn labels_including_root(n: &Name) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = n.labels().map(|l| l.as_bytes()).collect();
    if n.is_absolute() {
        v.push(&[]);
    }
    v
}

/// BIND's raw order value from `dns_name_fullcompare`.
fn raw_order(a: &Name, b: &Name) -> i32 {
    let a_labels = labels_including_root(a);
    let b_labels = labels_including_root(b);
    let l1 = a_labels.len() as i32;
    let l2 = b_labels.len() as i32;
    let common = l1.min(l2) as usize;
    for k in 0..common {
        let la = a_labels[l1 as usize - 1 - k];
        let lb = b_labels[l2 as usize - 1 - k];
        // cdiff is the label-length difference (the length octets, which
        // are < 64 and unaffected by tolower).
        let cdiff = la.len() as i32 - lb.len() as i32;
        // isc_ascii_lowercmp over the shared prefix: -1/0/+1.
        let n = la.len().min(lb.len());
        let mut diff = 0i32;
        for i in 0..n {
            let x = la[i].to_ascii_lowercase();
            let y = lb[i].to_ascii_lowercase();
            if x != y {
                diff = if x < y { -1 } else { 1 };
                break;
            }
        }
        if diff != 0 {
            return diff;
        }
        if cdiff != 0 {
            return cdiff;
        }
    }
    l1 - l2
}

/// Mirror of `dns_name_fullcompare`: returns (namereln, nlabels) where
/// namereln: 0=none 1=contains 2=subdomain 3=equal 4=commonancestor, and
/// nlabels is the number of common significant labels (counted from the
/// root; includes the root label).
fn fullcompare(a: &Name, b: &Name) -> (u8, usize) {
    // dns_name_fullcompare compares case-insensitively: "equal" means the
    // compare order is 0, not byte equality.
    if a.compare(b) == Ordering::Equal {
        return (3, a.label_count());
    }
    if a.is_subdomain(b) {
        return (2, b.label_count());
    }
    if b.is_subdomain(a) {
        return (1, a.label_count());
    }
    // Neither contains the other: count common labels from the root; a
    // positive count means commonancestor.  Absolute names share the root
    // label, which BIND counts.
    let a_labels: Vec<&[u8]> = a.labels().map(|l| l.as_bytes()).collect();
    let b_labels: Vec<&[u8]> = b.labels().map(|l| l.as_bytes()).collect();
    let mut common = 0usize;
    let mut i = a_labels.len();
    let mut j = b_labels.len();
    loop {
        if i == 0 || j == 0 {
            break;
        }
        i -= 1;
        j -= 1;
        // BIND compares labels case-insensitively (isc_ascii_lowercmp).
        if !eq_ci(a_labels[i], b_labels[j]) {
            break;
        }
        common += 1;
    }
    if a.is_absolute() && b.is_absolute() {
        common += 1; // the shared root label
    }
    if common > 0 {
        (4, common)
    } else {
        (0, 0)
    }
}

/// Case-insensitive ASCII label equality.
fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}
