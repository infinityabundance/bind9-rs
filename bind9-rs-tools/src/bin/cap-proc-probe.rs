//! cap-proc-probe — Rust mirror of `forensics/oracle/probes/
//! probe-libcap-proc.c` for the CAP-PROC courts.  Prints the
//! process-observable libcap surface and must be run in the SAME
//! environment as the C probe (same container → same kernel state).
//!
//! Usage: cap-proc-probe

use bind9_rs_tools::compat::libcap::*;

fn dump_cap(c: &CapState) {
    for i in 0..64i32 {
        let mut any = false;
        for f in [CapFlag::Effective, CapFlag::Permitted, CapFlag::Inheritable] {
            if c.get_flag(i, f) == Ok(CapFlagValue::Set) {
                any = true;
            }
        }
        if any {
            print!("cap{i}");
            if c.get_flag(i, CapFlag::Effective) == Ok(CapFlagValue::Set) {
                print!("e");
            }
            if c.get_flag(i, CapFlag::Permitted) == Ok(CapFlagValue::Set) {
                print!("p");
            }
            if c.get_flag(i, CapFlag::Inheritable) == Ok(CapFlagValue::Set) {
                print!("i");
            }
            print!(" ");
        }
    }
    println!();
}

fn main() {
    match cap_get_proc() {
        Ok(c) => {
            print!("cap_get_proc: ");
            dump_cap(&c);
        }
        Err(e) => {
            eprintln!("cap_get_proc: errno {}", e.0);
            std::process::exit(1);
        }
    }

    print!("cap_get_bound:");
    for i in 0..64i32 {
        match cap_get_bound(i) {
            Ok(r) => print!(" {i}={r}"),
            Err(_) => break,
        }
    }
    println!();

    print!("cap_get_ambient:");
    for i in 0..64i32 {
        match cap_get_ambient(i) {
            Ok(r) => print!(" {i}={r}"),
            Err(_) => break,
        }
    }
    println!();

    println!("cap_get_mode = {}", cap_get_mode() as u32);
    println!("cap_get_secbits = {}", cap_get_secbits().unwrap_or(0));
    println!("cap_max_bits = {}", cap_max_bits());

    match cap_iab_get_proc() {
        Ok(iab) => println!("cap_iab_get_proc = [{}]", cap_iab_to_text(&iab)),
        Err(_) => println!("cap_iab_get_proc = [(null)]"),
    }
}
