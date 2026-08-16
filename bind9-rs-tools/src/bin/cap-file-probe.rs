//! cap-file-probe — Rust mirror of `forensics/oracle/probes/
//! probe-libcap-file.c` for the CAP-FILE four-corner courts (§38).  Runs in
//! the same container as the C probe on the same /tmp directory.
//!
//! Usage: cap-file-probe <self-file> <other-file>

use bind9_rs_tools::compat::libcap::*;
use std::process::exit;

fn dump_state_of(r: CapResult<CapState>) {
    // mirror the C probe: dump_state(NULL) prints "  (null)"
    let c = match r {
        Ok(c) => c,
        Err(_) => {
            println!("  (null)");
            return;
        }
    };
    print!("  ");
    for i in 0..64i32 {
        let mut any = false;
        for f in [CapFlag::Effective, CapFlag::Permitted, CapFlag::Inheritable] {
            if c.get_flag(i, f) == Ok(CapFlagValue::Set) {
                any = true;
            }
        }
        if any {
            print!("{}", cap_to_name(i));
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
    println!("(rootid={})", cap_get_nsowner(&c));
}

fn dump_xattr(path: &str) {
    match cap_get_file(path) {
        Ok(c) => {
            if let Ok((raw, _)) = bind9_rs_tools::compat::libcap::vfs_save_for_probe(&c) {
                print!("  xattr({}):", raw.len());
                for b in &raw {
                    print!(" {b:02x}");
                }
                println!();
            }
        }
        Err(e) => println!("  xattr: (error {})", e.0),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <self> <other>", args[0]);
        exit(2);
    }
    let self_path = &args[1];
    let other = &args[2];

    // the files must exist (cap_set_file opens O_PATH|O_NOFOLLOW); like the
    // C probe's open(O_CREAT|O_WRONLY) this must NOT truncate an existing
    // file — the other side's warm-up caps must survive for the cross-read.
    for p in [self_path, other] {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(p)
            .expect("create file");
    }

    let mut c = CapState::empty();
    let caps = [cap::NET_BIND_SERVICE];
    c.set_flag(CapFlag::Permitted, &caps, CapFlagValue::Set)
        .unwrap();
    c.set_flag(CapFlag::Effective, &caps, CapFlagValue::Set)
        .unwrap();
    let r = cap_set_file(self_path, Some(&c));
    println!("cap_set_file(self) = {}", if r.is_ok() { 0 } else { -1 });
    dump_state_of(cap_get_file(self_path));
    dump_xattr(self_path);

    println!("cross-read:");
    dump_state_of(cap_get_file(other));
    dump_xattr(other);

    // symlink rejection
    let link = "/tmp/fcap-link";
    if std::os::unix::fs::symlink(self_path, link).is_ok() {
        let r = cap_set_file(link, Some(&c));
        let errno = r.err().map_or(0, |e| e.0);
        println!(
            "cap_set_file(symlink) = {} errno={}",
            if r.is_ok() { 0 } else { -1 },
            errno
        );
        let _ = std::fs::remove_file(link);
    }

    let r = cap_set_file(self_path, None);
    println!(
        "cap_set_file(self,NULL) = {}",
        if r.is_ok() { 0 } else { -1 }
    );
    dump_xattr(self_path);

    c.clear();
    c.set_flag(CapFlag::Permitted, &caps, CapFlagValue::Set)
        .unwrap();
    cap_set_nsowner(&mut c, 1000);
    let r = cap_set_file(self_path, Some(&c));
    println!(
        "cap_set_file(v3 rootid) = {}",
        if r.is_ok() { 0 } else { -1 }
    );
    dump_state_of(cap_get_file(self_path));
    dump_xattr(self_path);
}
