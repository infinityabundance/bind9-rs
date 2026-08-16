//! maxminddb-probe — Rust mirror of `forensics/oracle/probes/
//! probe-maxminddb.c` for the MMDB courts (§33, §37).  Runs in the same
//! oracle-libmaxminddb-1.13.3 container against the same pinned test-data
//! tree; stdout must be byte-identical.
//!
//! Usage: maxminddb-probe <test-data-dir>

use bind9_rs_tools::compat::maxminddb::*;
use std::net::IpAddr;
use std::process::exit;

fn typname(t: u32) -> &'static str {
    match t {
        MMDB_DATA_TYPE_EXTENDED => "extended",
        MMDB_DATA_TYPE_POINTER => "pointer",
        MMDB_DATA_TYPE_UTF8_STRING => "utf8_string",
        MMDB_DATA_TYPE_DOUBLE => "double",
        MMDB_DATA_TYPE_BYTES => "bytes",
        MMDB_DATA_TYPE_UINT16 => "uint16",
        MMDB_DATA_TYPE_UINT32 => "uint32",
        MMDB_DATA_TYPE_MAP => "map",
        MMDB_DATA_TYPE_INT32 => "int32",
        MMDB_DATA_TYPE_UINT64 => "uint64",
        MMDB_DATA_TYPE_UINT128 => "uint128",
        MMDB_DATA_TYPE_ARRAY => "array",
        MMDB_DATA_TYPE_CONTAINER => "container",
        MMDB_DATA_TYPE_END_MARKER => "end_marker",
        MMDB_DATA_TYPE_BOOLEAN => "boolean",
        MMDB_DATA_TYPE_FLOAT => "float",
        _ => "unknown",
    }
}

fn render_entry(out: &mut String, d: &EntryData) {
    out.push_str(&format!(
        "type={} has_data={} ",
        typname(d.type_id),
        if d.has_data { 1 } else { 0 }
    ));
    // data_size is only defined for strings, bytes, map/array headers,
    // boolean and pointers (maxminddb.h); for the numeric types the C's
    // lookup_path_in_map leaves it as uninitialized stack residue, so both
    // probes render "-" (harness policy, MMDB-0001).
    match d.type_id {
        MMDB_DATA_TYPE_UTF8_STRING
        | MMDB_DATA_TYPE_BYTES
        | MMDB_DATA_TYPE_MAP
        | MMDB_DATA_TYPE_ARRAY
        | MMDB_DATA_TYPE_BOOLEAN
        | MMDB_DATA_TYPE_POINTER => {
            out.push_str(&format!("data_size={} ", d.data_size));
        }
        _ => out.push_str("data_size=- "),
    }
    out.push_str(&format!("off={} next={} val=", d.offset, d.offset_to_next));
    render_value(out, d);
    out.push('\n');
}

/// glibc gmtime rendering of the build epoch (mmdblookup dump_meta format).
fn format_epoch(epoch: u64) -> String {
    let t = epoch as i64;
    // glibc's gmtime handles essentially the whole i64 range via era math;
    // the "out of range" case mirrors tm == NULL (only for values outside
    // the representable range, which the era math below also rejects).
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    if !(y >= -9999 && y <= 9999) {
        return "out of range".to_string();
    }
    let h = secs / 3600;
    let mi = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn dump_meta(mmdb: &Mmdb) -> String {
    let mut out = String::new();
    out.push_str("  Database metadata\n");
    out.push_str(&format!(
        "    Node count:    {}\n",
        mmdb.metadata.node_count
    ));
    out.push_str(&format!(
        "    Record size:   {} bits\n",
        mmdb.metadata.record_size
    ));
    out.push_str(&format!(
        "    IP version:    IPv{}\n",
        mmdb.metadata.ip_version
    ));
    out.push_str(&format!(
        "    Binary format: {}.{}\n",
        mmdb.metadata.binary_format_major_version, mmdb.metadata.binary_format_minor_version
    ));
    out.push_str(&format!(
        "    Build epoch:   {} ({})\n",
        mmdb.metadata.build_epoch,
        format_epoch(mmdb.metadata.build_epoch)
    ));
    out.push_str(&format!(
        "    Type:          {}\n",
        mmdb.metadata.database_type
    ));
    out.push_str("    Languages:     ");
    for (i, l) in mmdb.metadata.languages.iter().enumerate() {
        out.push_str(l);
        if i < mmdb.metadata.languages.len() - 1 {
            out.push(' ');
        }
    }
    out.push_str("\n    Description:\n");
    for d in &mmdb.metadata.descriptions {
        out.push_str(&format!("      {}:   {}\n", d.language, d.description));
    }
    out.push('\n');
    out
}

fn write_file_bytes(path: &str, bytes: &[u8]) {
    std::fs::write(path, bytes).ok();
}

fn lookup_one(mmdb: &Mmdb, ip: &str) {
    let (r, gai_error, mmdb_error) = mmdb_lookup_string(mmdb, ip);
    println!(
        "  lookup {}: found={} netmask={} gai={} mmdb_err={}",
        ip,
        if r.found_entry { 1 } else { 0 },
        r.netmask,
        gai_error,
        mmdb_error
    );
    if !r.found_entry {
        return;
    }
    let paths: &[&[&str]] = &[
        &["city", "names", "en"],
        &["country", "names", "en"],
        &["subdivisions", "0", "names", "en"],
        &["location", "latitude"],
        &["location", "longitude"],
        &["location", "accuracy_radius"],
        &["traits", "network"],
        &["postal", "code"],
        &["registered_country", "iso_code"],
        &["nope"],
        &["city", "nope"],
        &["subdivisions", "-1", "names", "en"],
        &["subdivisions", "9"],
        &["subdivisions", "x"],
    ];
    for p in paths {
        let mut d = EntryData::default();
        let status = mmdb_aget_value(mmdb, r.entry_offset, p, &mut d);
        let head = format!(
            "    path{}:",
            p.iter().map(|e| format!(" {e}")).collect::<String>()
        );
        if status != MMDB_SUCCESS {
            println!("{} status={} {}", head, status, mmdb_strerror(status));
        } else {
            print!("{} ", head);
            let mut s = String::new();
            render_entry(&mut s, &d);
            print!("{s}");
        }
    }
    let mut list: Vec<EntryData> = Vec::new();
    let status = mmdb_get_entry_data_list(mmdb, r.entry_offset, &mut list);
    if status != MMDB_SUCCESS {
        println!(
            "    get_entry_data_list: {} {}",
            status,
            mmdb_strerror(status)
        );
        return;
    }
    println!("    dump:");
    let mut out = String::new();
    let dstatus = mmdb_dump_entry_data_list(&mut out, &list, 0);
    print!("{out}");
    println!("    dump_status={dstatus}");
}

fn decoder_fields(mmdb: &Mmdb, ip: &str) {
    let (r, gai_error, mmdb_error) = mmdb_lookup_string(mmdb, ip);
    println!(
        "  decoder {}: found={} netmask={} gai={} mmdb_err={}",
        ip,
        if r.found_entry { 1 } else { 0 },
        r.netmask,
        gai_error,
        mmdb_error
    );
    if !r.found_entry {
        return;
    }
    let fields = [
        "utf8_string",
        "double",
        "bytes",
        "uint16",
        "uint32",
        "map",
        "int32",
        "uint64",
        "uint128",
        "array",
        "boolean",
        "float",
    ];
    for f in fields {
        let mut d = EntryData::default();
        let status = mmdb_aget_value(mmdb, r.entry_offset, &[f], &mut d);
        if status != MMDB_SUCCESS {
            println!("    {f}: status={status}");
        } else {
            print!("    {f}: ");
            let mut s = String::new();
            render_entry(&mut s, &d);
            print!("{s}");
        }
    }
    let mut list: Vec<EntryData> = Vec::new();
    let status = mmdb_get_entry_data_list(mmdb, r.entry_offset, &mut list);
    println!("    list_status={status}");
    if status == MMDB_SUCCESS {
        println!("    dump:");
        let mut out = String::new();
        let dstatus = mmdb_dump_entry_data_list(&mut out, &list, 0);
        print!("{out}");
        println!("    dump_status={dstatus}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <test-data-dir>", args[0]);
        exit(2);
    }
    let tdir = &args[1];

    println!("== version ==\n{}", mmdb_lib_version());

    println!("== strerror ==");
    for c in 0..=11 {
        println!("{c}: {}", mmdb_strerror(c));
    }
    println!("999: {}", mmdb_strerror(999));

    write_file_bytes("/tmp/mmdb-empty", b"");
    write_file_bytes("/tmp/mmdb-garbage", b"this is not a maxmind db file at all");
    {
        let city = format!("{tdir}/GeoIP2-City-Test.mmdb");
        let content = std::fs::read(&city).unwrap_or_default();
        let trunc: Vec<u8> = content.iter().take(500).copied().collect();
        write_file_bytes("/tmp/mmdb-trunc", &trunc);
    }
    println!("== open errors ==");
    for f in [
        "/tmp/mmdb-nonexistent",
        "/tmp/mmdb-empty",
        "/tmp/mmdb-garbage",
        "/tmp/mmdb-trunc",
    ] {
        match mmdb_open(f, MMDB_MODE_MMAP) {
            Ok(m) => {
                println!("{f}: {} {}", MMDB_SUCCESS, mmdb_strerror(MMDB_SUCCESS));
                drop(m);
            }
            Err(status) => println!("{f}: {status} {}", mmdb_strerror(status)),
        }
    }

    // ---- GeoIP2-City-Test.mmdb ----
    {
        let db = format!("{tdir}/GeoIP2-City-Test.mmdb");
        match mmdb_open(&db, MMDB_MODE_MMAP) {
            Ok(mmdb) => {
                println!(
                    "== open GeoIP2-City-Test.mmdb ==\n{} {}",
                    MMDB_SUCCESS,
                    mmdb_strerror(MMDB_SUCCESS)
                );
                println!("== metadata ==");
                print!("{}", dump_meta(&mmdb));
                let mut mlist: Vec<EntryData> = Vec::new();
                let mstatus = mmdb_get_metadata_as_entry_data_list(&mmdb, &mut mlist);
                println!("== metadata list ==\nstatus={mstatus}");
                if mstatus == MMDB_SUCCESS {
                    let mut out = String::new();
                    let dstatus = mmdb_dump_entry_data_list(&mut out, &mlist, 0);
                    print!("{out}");
                    println!("dump_status={dstatus}");
                }

                println!("== read_node ==");
                for n in 0u32..3 {
                    match mmdb_read_node(&mmdb, n) {
                        Ok(node) => println!(
                            "node {n}: status={MMDB_SUCCESS} left={} lt={} le={} right={} rt={} re={}",
                            node.left_record,
                            node.left_record_type,
                            node.left_record_offset,
                            node.right_record,
                            node.right_record_type,
                            node.right_record_offset
                        ),
                        Err(s) => println!("node {n}: status={s}"),
                    }
                }
                match mmdb_read_node(&mmdb, mmdb.metadata.node_count) {
                    Ok(_) => println!("node==count: status={MMDB_SUCCESS}"),
                    Err(s) => println!("node==count: status={s}"),
                }

                println!("== lookups ==");
                let ips = [
                    "81.2.69.142",
                    "81.2.69.143",
                    "81.2.69.144",
                    "2001:218::1",
                    "2001:218::",
                    "2a00:1450:4001:815::200e",
                    "::ffff:81.2.69.142",
                    "0.0.0.0",
                    "255.255.255.255",
                    "e900::",
                    "10.0.0.1",
                ];
                for ip in ips {
                    lookup_one(&mmdb, ip);
                }

                println!("== gai errors ==");
                let bads = [
                    "not an ip",
                    "",
                    "1.2.3",
                    "1.2.3.4.5",
                    "256.1.1.1",
                    "01.2.3.4",
                    "1.2.3.x",
                    "0x7f.1",
                    "1.2.3.4.5.6",
                    "010.0.0.1",
                    "0x7f.0.0.1",
                    "1.2.3.4 ",
                    "1.2.3.4. ",
                    "09.0.0.1",
                    "0x.1",
                    "1..2",
                    ".1.2.3",
                    "1.2.3.",
                    "4294967295",
                    "4294967296",
                    "1.2.3.256",
                    "0xffffffff",
                    "0x100000000",
                    "1.2.3.4 xyz",
                    "1.2.3.4\t",
                    " 1.2.3.4",
                    "+1.2.3.4",
                    "0x1f.0x1",
                    "0377.0.0.1",
                    "1:2:3:4:5:6:7",
                    "1::2::3",
                    "::ffff:1.2.3.256",
                    "1:2:3:4:5:6:7:8:9",
                    "fe80::1%",
                    "fe80::1%eth0",
                    "fe80::1%nonexistentzz",
                    "fe80::1%3",
                    "fe80::1%0",
                    "fe80::1%99999999999999999999",
                    "1.2.3.4%eth0",
                    "%",
                ];
                for b in bads {
                    let (_r, gai, me) = mmdb_lookup_string(&mmdb, b);
                    // mirror the C probe: resolve directly and render the
                    // address glibc chose (inet_ntop format)
                    let (_g2, addr) = mmdb_resolve(b);
                    let addrstr = match addr {
                        Some(IpAddr::V4(v4)) => v4.to_string(),
                        Some(IpAddr::V6(v6)) => v6.to_string(),
                        None => "-".to_string(),
                    };
                    println!("  {b} -> gai={gai} mmdb_err={me} addr={addrstr}");
                }
            }
            Err(status) => {
                println!(
                    "== open GeoIP2-City-Test.mmdb ==\n{status} {}",
                    mmdb_strerror(status)
                );
                exit(1);
            }
        }
    }

    // ---- decoder db ----
    {
        let db = format!("{tdir}/MaxMind-DB-test-decoder.mmdb");
        match mmdb_open(&db, MMDB_MODE_MMAP) {
            Ok(mmdb) => {
                println!(
                    "== open MaxMind-DB-test-decoder.mmdb ==\n{} {}",
                    MMDB_SUCCESS,
                    mmdb_strerror(MMDB_SUCCESS)
                );
                println!("== decoder ==");
                decoder_fields(&mmdb, "::1.1.1.1");
                decoder_fields(&mmdb, "::4.5.6.7");
                decoder_fields(&mmdb, "::0.0.0.0");
                decoder_fields(&mmdb, "e900::");
            }
            Err(status) => {
                println!(
                    "== open MaxMind-DB-test-decoder.mmdb ==\n{status} {}",
                    mmdb_strerror(status)
                );
            }
        }
    }

    // ---- ipv4 db + ipv6 lookup ----
    {
        let db = format!("{tdir}/MaxMind-DB-test-ipv4-24.mmdb");
        match mmdb_open(&db, MMDB_MODE_MMAP) {
            Ok(mmdb) => {
                println!(
                    "== open MaxMind-DB-test-ipv4-24.mmdb ==\n{} {}",
                    MMDB_SUCCESS,
                    mmdb_strerror(MMDB_SUCCESS)
                );
                let (r, gai_error, mmdb_error) = mmdb_lookup_string(&mmdb, "::1");
                println!(
                    "== ipv6-in-ipv4 ==\nfound={} netmask={} gai={} mmdb_err={} {}",
                    if r.found_entry { 1 } else { 0 },
                    r.netmask,
                    gai_error,
                    mmdb_error,
                    mmdb_strerror(mmdb_error)
                );
            }
            Err(status) => {
                println!(
                    "== open MaxMind-DB-test-ipv4-24.mmdb ==\n{status} {}",
                    mmdb_strerror(status)
                );
            }
        }
    }

    // ---- corrupt databases ----
    {
        let db = format!("{tdir}/MaxMind-DB-test-broken-pointers-24.mmdb");
        match mmdb_open(&db, MMDB_MODE_MMAP) {
            Ok(mmdb) => {
                println!(
                    "== open broken-pointers-24 ==\n{} {}",
                    MMDB_SUCCESS,
                    mmdb_strerror(MMDB_SUCCESS)
                );
                let (r, gai_error, mmdb_error) = mmdb_lookup_string(&mmdb, "1.1.1.16");
                println!(
                    "lookup 1.1.1.16: found={} gai={} mmdb_err={}",
                    if r.found_entry { 1 } else { 0 },
                    gai_error,
                    mmdb_error
                );
                if r.found_entry {
                    let mut list: Vec<EntryData> = Vec::new();
                    let s = mmdb_get_entry_data_list(&mmdb, r.entry_offset, &mut list);
                    println!("get_entry_data_list: {s} {}", mmdb_strerror(s));
                }
                let (r, gai_error, mmdb_error) = mmdb_lookup_string(&mmdb, "1.1.1.32");
                println!(
                    "lookup 1.1.1.32: found={} gai={} mmdb_err={} {}",
                    if r.found_entry { 1 } else { 0 },
                    gai_error,
                    mmdb_error,
                    mmdb_strerror(mmdb_error)
                );
            }
            Err(status) => {
                println!(
                    "== open broken-pointers-24 ==\n{status} {}",
                    mmdb_strerror(status)
                );
            }
        }
    }
    {
        let db = format!("{tdir}/MaxMind-DB-test-broken-search-tree-24.mmdb");
        match mmdb_open(&db, MMDB_MODE_MMAP) {
            Ok(mmdb) => {
                println!(
                    "== open broken-search-tree-24 ==\n{} {}",
                    MMDB_SUCCESS,
                    mmdb_strerror(MMDB_SUCCESS)
                );
                let (_r, gai_error, mmdb_error) = mmdb_lookup_string(&mmdb, "1.1.1.1");
                println!(
                    "lookup 1.1.1.1: gai={gai_error} mmdb_err={mmdb_error} {}",
                    mmdb_strerror(mmdb_error)
                );
            }
            Err(status) => {
                println!(
                    "== open broken-search-tree-24 ==\n{status} {}",
                    mmdb_strerror(status)
                );
            }
        }
    }

    // ---- bad-data corpus ----
    {
        let baddata = [
            "libmaxminddb-deep-nesting.mmdb",
            "libmaxminddb-deep-array-nesting.mmdb",
            "libmaxminddb-oversized-array.mmdb",
            "libmaxminddb-oversized-map.mmdb",
            "libmaxminddb-offset-integer-overflow.mmdb",
            "libmaxminddb-empty-array-last-in-metadata.mmdb",
            "libmaxminddb-empty-map-last-in-metadata.mmdb",
            "libmaxminddb-corrupt-search-tree.mmdb",
            "libmaxminddb-uint64-max-epoch.mmdb",
        ];
        println!("== bad-data ==");
        for name in baddata {
            let db = format!("{tdir}/bad-data/{name}");
            match mmdb_open(&db, MMDB_MODE_MMAP) {
                Ok(mmdb) => {
                    println!(
                        "open {name}: {} {}",
                        MMDB_SUCCESS,
                        mmdb_strerror(MMDB_SUCCESS)
                    );
                    let mut list: Vec<EntryData> = Vec::new();
                    let s = mmdb_get_metadata_as_entry_data_list(&mmdb, &mut list);
                    println!("  metadata list: {s} {}", mmdb_strerror(s));
                    if s == MMDB_SUCCESS {
                        let mut out = String::new();
                        let dstatus = mmdb_dump_entry_data_list(&mut out, &list, 0);
                        print!("{out}");
                        println!("  dump_status={dstatus}");
                    }
                }
                Err(status) => {
                    println!("open {name}: {status} {}", mmdb_strerror(status));
                }
            }
        }
    }

    println!("== done ==");
}
