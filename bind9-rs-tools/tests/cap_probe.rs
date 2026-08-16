//! cap-probe — the Rust mirror of `forensics/oracle/probes/probe-libcap.c`
//! (§37 C probe courts).  Prints the same deterministic lines as the C probe
//! so the court can diff oracle vs rust byte-for-byte.
//!
//! Run (court harness): `cargo test -p bind9-rs-tools --test cap_probe -- --nocapture`

use bind9_rs_tools::compat::libcap::*;

fn p_text(txt: &str) {
    match cap_from_text(txt) {
        Err(e) => println!("from_text({txt}) -> NULL errno={}", e.0),
        Ok(c) => {
            let (out, len) = cap_to_text(&c);
            println!("from_text({txt}) -> [{out}] len={len}");
        }
    }
}

fn p_name(name: &str) {
    match cap_from_name(name) {
        Ok(v) => println!("cap_from_name({name}) -> 0 v={v}"),
        Err(_) => println!("cap_from_name({name}) -> -1 v=-1"),
    }
}

fn dump_ext(c: &CapState) {
    let sz = cap_size(c);
    println!("cap_size = {sz}");
    let mut buf = [0u8; 128];
    if let Ok(n) = cap_copy_ext(&mut buf, c) {
        print!("cap_copy_ext -> {n} bytes:");
        for (i, b) in buf.iter().enumerate() {
            if i >= n || i >= 32 {
                break;
            }
            print!(" {b:02x}");
        }
        println!();
    }
}

#[test]
fn cap_probe_output() {
    println!("cap_max_bits = {}", cap_max_bits());

    p_text("cap_kill=ep");
    p_text("cap_kill=ep cap_net_bind_service+i");
    p_text("=ep");
    p_text("all=eip");
    p_text("=ep cap_net_raw+p");
    p_text("cap_chown,cap_net_bind_service+eip");
    p_text("5=ep");
    p_text("cap_kill=ep cap_kill+ip");
    p_text("cap_kill=ep cap_kill-i");
    p_text("=eip cap_kill-e");
    p_text("cap_kill+ep");
    p_text("= cap_kill+ep");
    p_text("!cap_kill");
    p_text("cap_kill=");
    p_text("cap_kill= cap_net_raw+ep");
    p_text("cap_kill+");
    p_text("=ep ");
    p_text("cap_unknownname+ep");
    p_text("cap_kill==ep");
    p_text("cap_kill=eip,");
    p_text("41+ep");
    p_text("cap_kill=ep,");

    for name in [
        "chown",
        "cap_chown",
        "CAP_CHOWN",
        "ChOwN",
        "12",
        "0x2",
        "kill",
        "cap_kill",
        "nonsense",
        "41",
        "64",
        "chownx",
        "chow",
    ] {
        p_name(name);
    }

    println!("cap_to_name(0) = {}", cap_to_name(0));
    println!("cap_to_name(12) = {}", cap_to_name(12));
    println!("cap_to_name(41) = {}", cap_to_name(41));
    println!("cap_to_name(64) = {}", cap_to_name(64));
    println!("cap_to_name(-1) = {}", cap_to_name(-1));

    let mut a = CapState::empty();
    let mut b = CapState::empty();
    let caps = [cap::CHOWN, cap::NET_BIND_SERVICE];
    println!("cap_compare(empty,empty) = {}", a.compare(&b));
    a.set_flag(CapFlag::Effective, &caps, CapFlagValue::Set)
        .unwrap();
    println!("cap_compare(a,a) = {}", a.compare(&a));
    println!("cap_compare(a,b) = {}", a.compare(&b));
    b.set_flag(CapFlag::Effective, &caps, CapFlagValue::Set)
        .unwrap();
    b.set_flag(CapFlag::Permitted, &caps[..1], CapFlagValue::Set)
        .unwrap();
    println!("cap_compare(a,b) = {}", a.compare(&b));
    let v = a.get_flag(cap::CHOWN, CapFlag::Effective).unwrap();
    println!("get_flag(chown,eff) = {}", v as i32);
    let v = a.get_flag(cap::CHOWN, CapFlag::Permitted).unwrap();
    println!("get_flag(chown,perm) = {}", v as i32);
    let bad = a.set_flag(CapFlag::Effective, &[500], CapFlagValue::Set);
    println!("set_flag(500) ret = {}", if bad.is_ok() { 0 } else { -1 });
    let r = a.set_flag(CapFlag::Effective, &[], CapFlagValue::Set);
    println!(
        "set_flag(0 values) ret = {} errno={}",
        if r.is_err() { -1 } else { 0 },
        r.err().map_or(0, |e| e.0)
    );
    a.clear();
    let v = a.get_flag(cap::CHOWN, CapFlag::Effective).unwrap();
    println!("after clear, get_flag(chown,eff) = {}", v as i32);
    let mut c = CapState::empty();
    c.fill_flag(CapFlag::Effective, &b, CapFlag::Permitted)
        .unwrap();
    let v = c.get_flag(cap::CHOWN, CapFlag::Effective).unwrap();
    println!("fill_flag(perm->eff) chown = {}", v as i32);
    c.fill(CapFlag::Inheritable, CapFlag::Effective).unwrap();
    let v = c.get_flag(cap::CHOWN, CapFlag::Inheritable).unwrap();
    println!("fill(inh<-eff) chown = {}", v as i32);

    let mut e = CapState::empty();
    e.set_flag(CapFlag::Effective, &caps, CapFlagValue::Set)
        .unwrap();
    dump_ext(&e);
    e.clear();
    dump_ext(&e);
    e.set_flag(CapFlag::Permitted, &[63], CapFlagValue::Set)
        .unwrap();
    dump_ext(&e);

    let mut f = CapState::empty();
    f.set_flag(CapFlag::Effective, &caps[..1], CapFlagValue::Set)
        .unwrap();
    f.set_flag(CapFlag::Inheritable, &caps[..1], CapFlagValue::Set)
        .unwrap();
    let mut ext = [0u8; 64];
    cap_copy_ext(&mut ext, &f).unwrap();
    let g = cap_copy_int(&ext).unwrap();
    println!("copy_int compare = {}", f.compare(&g));
    ext[0] ^= 0xff;
    let g = cap_copy_int(&ext);
    println!(
        "copy_int badmagic -> {} errno={}",
        if g.is_ok() { "OK?!" } else { "NULL" },
        g.err().map_or(0, |e| e.0)
    );
    let mut tiny = [0u8; 4];
    let ssz = cap_copy_ext(&mut tiny, &f);
    match ssz {
        Ok(_) => println!("copy_ext too small -> 0"),
        Err(e) => println!("copy_ext too small -> -1 errno={}", e.0),
    }

    let mut iab = CapIab::new();
    println!("iab init to_text = [{}]", cap_iab_to_text(&iab));
    iab.set_vector(CapIabVector::Inh, cap::CHOWN, CapFlagValue::Set)
        .unwrap();
    println!("iab inh chown to_text = [{}]", cap_iab_to_text(&iab));
    iab.set_vector(CapIabVector::Amb, cap::NET_RAW, CapFlagValue::Set)
        .unwrap();
    println!("iab amb net_raw to_text = [{}]", cap_iab_to_text(&iab));
    iab.set_vector(CapIabVector::Bound, cap::SYS_ADMIN, CapFlagValue::Set)
        .unwrap();
    println!("iab bound sys_admin to_text = [{}]", cap_iab_to_text(&iab));
    let iab2 = cap_iab_from_text("^cap_chown cap_kill !cap_net_raw");
    println!(
        "iab from_text -> [{}]",
        match &iab2 {
            Ok(x) => cap_iab_to_text(x),
            Err(_) => "(null)".to_string(),
        }
    );

    println!("cap_get_mode = {}", cap_get_mode() as u32);
    println!(
        "cap_mode_name(0..4) = {} {} {} {} {}",
        cap_mode_name(CapMode::Uncertain),
        cap_mode_name(CapMode::NoPriv),
        cap_mode_name(CapMode::Pure1eInit),
        cap_mode_name(CapMode::Pure1e),
        cap_mode_name(CapMode::Hybrid)
    );
    println!("cap_get_secbits = {}", cap_get_secbits().unwrap_or(0));
}
