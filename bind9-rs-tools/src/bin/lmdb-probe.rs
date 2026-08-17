//! `lmdb-probe` — Rust mirror of `forensics/oracle/probes/probe-lmdb.c` for
//! the LMDB-0001 court (§24, §25, §38).
//!
//! Exercises the `mdb_*` surface BIND 9.20.26 uses (catalog zones, runtime-zone
//! persistence, `dns_lmdb`) plus the on-disk page-level interoperability
//! contract: a deterministic op sequence per phase and a structured page dump
//! of the main db and the freeDB.
//!
//! The page dump parses data.mdb DIRECTLY (MDB_page/MDB_node/MDB_db/MDB_meta
//! layouts are part of the on-disk contract) and prints pgno/flags/lower/
//! upper/node keys/data sizes — NOT raw bytes, so the C's uninitialized
//! overflow-page tails are excluded (see the manifest's nondeterminism
//! policy).  The dump therefore makes the whole tree structure observable:
//! split points, node order, sub-page regions, sub-DB records, freeDB
//! records.
//!
//! stdout must be byte-identical to the C probe; pid/tid are masked in the
//! reader-list output.  Runs against the same `/tmp/lmdb_work` tree as the C
//! probe (each side rebuilds its own copy).

use std::os::unix::fs::FileExt;

use bind9_rs_tools::compat::lmdb::{cursor_op, flags, Env, Error, Txn};

const PAGEHDRSZ: u16 = 16;
#[allow(dead_code)] // the full on-disk flag set (mdb.c), documented here
const P_BRANCH: u8 = 0x01;
#[allow(dead_code)]
const P_LEAF: u8 = 0x02;
const P_OVERFLOW: u8 = 0x04;
#[allow(dead_code)]
const P_META: u8 = 0x08;
#[allow(dead_code)]
const P_DIRTY: u8 = 0x10;
const P_LEAF2: u8 = 0x20;
#[allow(dead_code)]
const P_SUBP: u8 = 0x40;
#[allow(dead_code)]
const F_BIGDATA: u16 = 0x01;
const F_SUBDATA: u16 = 0x02;
const F_DUPDATA: u16 = 0x04;
const P_INVALID: u64 = u64::MAX;

/* ------------------------------------------------------------------ */
/* on-disk format (mdb.c: PAGEHDRSZ etc. — part of the file contract)  */
/* ------------------------------------------------------------------ */

fn rd64(p: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(p[off..off + 8].try_into().unwrap())
}

fn rd32(p: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(p[off..off + 4].try_into().unwrap())
}

fn rd16(p: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes(p[off..off + 2].try_into().unwrap())
}

/// `struct mdb_db` (48 bytes on disk).
#[derive(Clone, Copy)]
#[allow(dead_code)] // full on-disk layout, mirroring the C probe's struct
struct Db {
    pad: u32,
    flags: u16,
    depth: u16,
    branch: u64,
    leaf: u64,
    overflow: u64,
    entries: u64,
    root: u64,
}

fn parse_db(p: &[u8]) -> Db {
    Db {
        pad: rd32(p, 0),
        flags: rd16(p, 4),
        depth: rd16(p, 6),
        branch: rd64(p, 8),
        leaf: rd64(p, 16),
        overflow: rd64(p, 24),
        entries: rd64(p, 32),
        root: rd64(p, 40),
    }
}

/// `struct mdb_meta` (136 bytes on disk): meta begins at file offset 16.
struct Meta {
    txnid: u64,
    last_pg: u64,
    mapsize: u64,
    main: Db,
    free: Db,
}

fn parse_meta(page: &[u8]) -> Meta {
    let m = &page[PAGEHDRSZ as usize..];
    Meta {
        txnid: rd64(m, 128),
        last_pg: rd64(m, 120),
        mapsize: rd64(m, 16),
        main: parse_db(&m[72..]),
        free: parse_db(&m[24..]),
    }
}

struct Reader {
    file: std::fs::File,
    psize: u64,
}

impl Reader {
    fn pread_full(&self, pgno: u64, buf: &mut [u8]) -> bool {
        let mut off = pgno * self.psize;
        let mut n = 0;
        while n < buf.len() {
            match self.file.read_at(&mut buf[n..], off) {
                Ok(0) => return false,
                Ok(k) => {
                    n += k;
                    off += k as u64;
                }
                Err(_) => return false,
            }
        }
        true
    }
}

fn read_meta(r: &Reader, psize: u64) -> Meta {
    let mut p = [0u8; 4096];
    r.pread_full(0, &mut p[..psize as usize]);
    let m0 = parse_meta(&p);
    r.pread_full(1, &mut p[..psize as usize]);
    let m1 = parse_meta(&p);
    if m0.txnid > m1.txnid {
        m0
    } else {
        m1
    }
}

/* ------------------------------------------------------------------ */
/* output helpers                                                      */
/* ------------------------------------------------------------------ */

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn rcstr<T>(rc: &Result<T, Error>) -> String {
    match rc {
        Ok(_) => " rc=0 (Successful return: 0)".to_string(),
        Err(e) => format!(" rc={} ({})", e.code(), e.strerror()),
    }
}

fn rccode(rc: &Result<(), Error>) -> i32 {
    match rc {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

fn banner(s: &str) {
    println!("== {s}");
}

/* ------------------------------------------------------------------ */
/* deterministic op helpers                                            */
/* ------------------------------------------------------------------ */

fn doput(txn: &mut Txn, dbi: u32, ks: &str, vs: &str, fl: u32) {
    print!("put {ks}");
    print!("{}", rcstr(&txn.put(dbi, ks.as_bytes(), vs.as_bytes(), fl)));
    println!();
}

fn doget(txn: &mut Txn, dbi: u32, ks: &str) {
    print!("get {ks}");
    match txn.get(dbi, ks.as_bytes()) {
        Ok(v) => print!(" -> {}", hex(&v)),
        Err(e) => print!(" rc={} ({})", e.code(), e.strerror()),
    }
    println!();
}

fn dodel(txn: &mut Txn, dbi: u32, ks: &str) {
    print!("del {ks}");
    print!("{}", rcstr(&txn.del(dbi, ks.as_bytes(), None)));
    println!();
}

/* ------------------------------------------------------------------ */
/* structured page dump (direct file parse)                            */
/* ------------------------------------------------------------------ */

fn dump_dups_region(sub: &[u8], _region: usize) {
    let n = (rd16(sub, 12) - PAGEHDRSZ) >> 1;
    print!(" subpage nkeys={n}");
    if sub[10] & P_LEAF2 != 0 {
        let ksize = rd16(sub, 8) as usize;
        print!(" pad={ksize}");
        for i in 0..n {
            let off = PAGEHDRSZ as usize + i as usize * ksize;
            print!("({})", hex(&sub[off..off + ksize]));
        }
    } else {
        for i in 0..n {
            let off = rd16(sub, PAGEHDRSZ as usize + i as usize * 2) as usize;
            let node = &sub[off..];
            let ksize = rd16(node, 6) as usize;
            print!("({})", hex(&node[8..8 + ksize]));
        }
    }
    println!();
}

fn dump_node(r: &Reader, pg: &[u8], i: usize, depth: usize) {
    let off = rd16(pg, PAGEHDRSZ as usize + i * 2) as usize;
    let node = &pg[off..];
    let ksize = rd16(node, 6) as usize;
    let flags = rd16(node, 4);
    let lo = rd16(node, 0) as u32;
    let hi = rd16(node, 2) as u32;
    let dsz = (lo as usize) | ((hi as usize) << 16);
    print!(" node[{i}] key={}", hex(&node[8..8 + ksize]));
    print!(" ksize={ksize} dsz={dsz} flags=0x{flags:02x}");
    if pg[10] & P_BRANCH != 0 {
        let child = lo as u64 | ((hi as u64) << 16) | ((flags as u64) << 32);
        print!(" child={child}");
    } else if flags & F_DUPDATA != 0 {
        let data = &node[8 + ksize..];
        if flags & F_SUBDATA != 0 {
            let db = parse_db(data);
            print!(" subdb entries={} root={}", db.entries, db.root);
            println!();
            if db.root != P_INVALID {
                println!("{}  subdb depth={}", " ".repeat(depth * 2), db.depth);
                dump_pg(r, db.root, depth + 1);
            }
            return;
        }
        dump_dups_region(data, dsz);
        return;
    }
    println!();
}

fn dump_pg(r: &Reader, pgno: u64, depth: usize) {
    let mut pg = vec![0u8; r.psize as usize];
    if !r.pread_full(pgno, &mut pg) {
        return;
    }
    let n = (rd16(&pg, 12) - PAGEHDRSZ) >> 1;
    println!(
        "{}page pgno={} flags=0x{:02x} lower={} upper={} nkeys={}{}",
        " ".repeat(depth * 2),
        rd64(&pg, 0),
        rd16(&pg, 10),
        rd16(&pg, 12),
        rd16(&pg, 14),
        n,
        if pg[10] & P_OVERFLOW != 0 {
            " overflow"
        } else {
            ""
        }
    );
    if pg[10] & P_OVERFLOW != 0 {
        println!(
            "{}  overflow pages={}",
            " ".repeat(depth * 2),
            rd32(&pg, 12)
        );
        return;
    }
    if pg[10] & P_LEAF2 != 0 {
        let ksize = rd16(&pg, 8) as usize;
        print!("{}  pad={ksize}", " ".repeat(depth * 2));
        for i in 0..n {
            let off = PAGEHDRSZ as usize + i as usize * ksize;
            print!(" key[{i}]={}", hex(&pg[off..off + ksize]));
        }
        println!();
        return;
    }
    for i in 0..n {
        print!("{}", " ".repeat(depth * 2));
        dump_node(r, &pg, i as usize, depth);
        if pg[10] & P_BRANCH != 0 {
            let off = rd16(&pg, PAGEHDRSZ as usize + i as usize * 2) as usize;
            let node = &pg[off..];
            let child = rd16(node, 0) as u64
                | ((rd16(node, 2) as u64) << 16)
                | ((rd16(node, 4) as u64) << 32);
            dump_pg(r, child, depth + 1);
        }
    }
}

fn dump_db(r: &Reader, db: &Db, label: &str) {
    println!(
        "== dump {label} entries={} depth={} leaf={} branch={} overflow={}",
        db.entries, db.depth, db.leaf, db.branch, db.overflow
    );
    if db.root != P_INVALID {
        dump_pg(r, db.root, 1);
    } else {
        println!("  (empty)");
    }
}

fn dump_all(r: &Reader, psize: u64) {
    let m = read_meta(r, psize);
    println!(
        "== meta txnid={} last_pg={} mapsize={}",
        m.txnid, m.last_pg, m.mapsize
    );
    dump_db(r, &m.main, "main");
    dump_db(r, &m.free, "free");
}

/* ------------------------------------------------------------------ */
/* phases                                                              */
/* ------------------------------------------------------------------ */

fn phase_basic(dir: &str) {
    let path = format!("{dir}/basic");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase basic");
    let mut env = Env::create().unwrap();
    print!("env_create{}", rcstr(&Ok(())));
    println!();
    env.set_mapsize(1 << 20).unwrap();
    print!("env_open{}", rcstr(&env.open(&path, 0, 0o664)));
    println!();

    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    doput(&mut txn, dbi, "key1", "value1", 0);
    doput(&mut txn, dbi, "key2", "value2", 0);
    doput(&mut txn, dbi, "key0", "value0", 0);
    doput(&mut txn, dbi, "key1", "valueX", 0); /* overwrite */
    doput(&mut txn, dbi, "key1", "valueY", flags::NOOVERWRITE); /* KEYEXIST */
    doget(&mut txn, dbi, "key0");
    doget(&mut txn, dbi, "key1");
    doget(&mut txn, dbi, "key2");
    doget(&mut txn, dbi, "nokey");
    let st = txn.stat(dbi).unwrap();
    println!(
        "stat entries={} depth={} leaf={} branch={} overflow={} psize={}",
        st.entries, st.depth, st.leaf_pages, st.branch_pages, st.overflow_pages, st.psize
    );
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: st.psize as u64,
    };
    dump_all(&r, st.psize as u64);

    /* reopen and validate */
    env.close();
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    doget(&mut txn, dbi, "key1");
    dodel(&mut txn, dbi, "key1");
    doget(&mut txn, dbi, "key1");
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} depth={}", st.entries, st.depth);
    print!("commit{}", rcstr(&txn.commit()));
    println!();
    env.close();
}

fn phase_named(dir: &str) {
    let path = format!("{dir}/named");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase named dbs");
    let mut env = Env::create().unwrap();
    env.set_maxdbs(8).unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    let rc = txn.dbi_open(Some("subdb"), flags::CREATE);
    match &rc {
        Ok(sub) => print!("dbi_open subdb{} dbi={sub}", rcstr(&Ok(()))),
        Err(e) => print!("dbi_open subdb rc={} ({})", e.code(), e.strerror()),
    }
    println!();
    let sub = rc.unwrap();
    doput(&mut txn, sub, "s1", "sv1", 0);
    doput(&mut txn, dbi, "mainkey", "mainval", 0);
    doget(&mut txn, sub, "s1");
    let st = txn.stat(sub).unwrap();
    println!("stat sub entries={} depth={}", st.entries, st.depth);
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* reopen the named db from a fresh txn */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let rc = txn.dbi_open(Some("subdb"), 0);
    match &rc {
        Ok(sub) => print!("dbi_open subdb ro{} dbi={sub}", rcstr(&Ok(()))),
        Err(e) => print!("dbi_open subdb ro rc={} ({})", e.code(), e.strerror()),
    }
    println!();
    let sub = rc.unwrap();
    doget(&mut txn, sub, "s1");
    print!(
        "dbi_open subdb again{}",
        rcstr(&txn.dbi_open(Some("subdb"), flags::CREATE))
    );
    println!();
    print!("drop subdb{}", rcstr(&txn.drop(sub, true)));
    println!();
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let mut txn = env.txn_begin(None, 0).unwrap();
    print!("dbi_open dropped{}", rcstr(&txn.dbi_open(Some("subdb"), 0)));
    println!();
    txn.abort();
    env.close();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: 4096,
    };
    dump_all(&r, 4096);
}

fn phase_overflow(dir: &str) {
    let path = format!("{dir}/overflow");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase overflow");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();

    let big: Vec<u8> = (0..9000).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
    print!("put big 9000{}", rcstr(&txn.put(dbi, b"big", &big, 0)));
    println!();
    let v = txn.get(dbi, b"big").unwrap();
    print!(
        "get big -> {} bytes, first={} last={}",
        v.len(),
        hex(&v[..16]),
        hex(&v[v.len() - 16..])
    );
    println!();
    let med: Vec<u8> = (0..3000).map(|i| ((i * 13 + 1) & 0xff) as u8).collect();
    print!("put med1 3000{}", rcstr(&txn.put(dbi, b"med1", &med, 0)));
    println!();
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} overflow={}", st.entries, st.overflow_pages);
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* overwrite: same size, then shrink */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    let big2: Vec<u8> = (0..9000).map(|i| (255i32 - i as i32) as u8).collect();
    print!(
        "put big same size{}",
        rcstr(&txn.put(dbi, b"big", &big2, 0))
    );
    println!();
    print!(
        "put big shrink 1000{}",
        rcstr(&txn.put(dbi, b"big", &big2[..1000], 0))
    );
    println!();
    let v = txn.get(dbi, b"big").unwrap();
    print!("get big -> {} bytes first={}", v.len(), hex(&v[..8]));
    println!();
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: st.psize as u64,
    };
    dump_all(&r, st.psize as u64);

    /* delete the overflow keys to exercise the free list */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    dodel(&mut txn, dbi, "big");
    dodel(&mut txn, dbi, "med1");
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} overflow={}", st.entries, st.overflow_pages);
    print!("commit{}", rcstr(&txn.commit()));
    println!();
    env.close();
}

fn phase_dups(dir: &str) {
    let path = format!("{dir}/dups");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase dupsort");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    print!(
        "dbi_open dupsort{}",
        rcstr(&txn.dbi_open(None, flags::DUPSORT | flags::CREATE))
    );
    println!();
    let dbi = txn.dbi_open(None, 0).unwrap();

    doput(&mut txn, dbi, "k", "b", 0);
    doput(&mut txn, dbi, "k", "a", 0);
    doput(&mut txn, dbi, "k", "c", 0);
    doput(&mut txn, dbi, "k", "a", flags::NODUPDATA); /* -> KEYEXIST */
    doput(&mut txn, dbi, "j", "z", 0);
    doput(&mut txn, dbi, "k", "a", 0); /* dup already present: no-op */
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} depth={}", st.entries, st.depth);

    let mut cur = txn.cursor_open(dbi).unwrap();
    print!("cursor_open{}", rcstr(&Ok(())));
    println!();
    let mut k = Vec::new();
    let mut v = Vec::new();
    let _ = cur.get(cursor_op::FIRST, &mut k, &mut v);
    print!("first k={} d={}", hex(&k), hex(&v));
    println!();
    let _ = cur.get(cursor_op::NEXT, &mut k, &mut v);
    print!("next k={} d={}", hex(&k), hex(&v));
    println!();
    let _ = cur.get(cursor_op::NEXT_DUP, &mut k, &mut v);
    print!("next_dup k={} d={}", hex(&k), hex(&v));
    println!();
    let _ = cur.get(cursor_op::NEXT, &mut k, &mut v);
    print!("next k={} d={}", hex(&k), hex(&v));
    println!();
    let _ = cur.get(cursor_op::NEXT_NODUP, &mut k, &mut v);
    print!("next_nodup k={} d={}", hex(&k), hex(&v));
    println!();
    let _ = cur.get(cursor_op::PREV, &mut k, &mut v);
    print!("prev k={} d={}", hex(&k), hex(&v));
    println!();
    let cnt = cur.count().unwrap();
    print!("count={cnt}{}", rcstr(&Ok(())));
    println!();
    v = b"b".to_vec();
    let rc = cur.get(cursor_op::GET_BOTH, &mut k, &mut v);
    print!("get_both b{} d={}", rcstr(&rc), hex(&v));
    println!();
    v = b"z".to_vec();
    let rc = cur.get(cursor_op::GET_BOTH, &mut k, &mut v);
    print!("get_both z{}", rcstr(&rc));
    println!();
    let _ = cur.get(cursor_op::FIRST_DUP, &mut k, &mut v);
    print!("first_dup d={}", hex(&v));
    println!();
    let _ = cur.get(cursor_op::LAST_DUP, &mut k, &mut v);
    print!("last_dup d={}", hex(&v));
    println!();
    drop(cur);
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* delete dups: sub-page shrink */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    print!("del k/b{}", rcstr(&txn.del(dbi, b"k", Some(b"b"))));
    println!();
    print!("del k/c{}", rcstr(&txn.del(dbi, b"k", Some(b"c"))));
    println!();
    doget(&mut txn, dbi, "k");
    print!("del k all{}", rcstr(&txn.del(dbi, b"k", None)));
    println!();
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* many dups: sub-page -> sub-DB conversion */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..120 {
        let val = format!("dup{i:03}");
        doput(&mut txn, dbi, "many", &val, 0);
    }
    for i in 0..60 {
        let val = format!("dup{:03}", i * 2);
        doput(&mut txn, dbi, "even", &val, 0);
    }
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} depth={}", st.entries, st.depth);
    let v = txn.get(dbi, b"many").unwrap();
    println!("get many dsz={}", v.len());
    doget(&mut txn, dbi, "even");
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: st.psize as u64,
    };
    dump_all(&r, st.psize as u64);
    env.close();
}

fn phase_fixed(dir: &str) {
    let path = format!("{dir}/fixed");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase dupfixed");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    print!(
        "dbi_open dupfixed{}",
        rcstr(&txn.dbi_open(None, flags::DUPSORT | flags::DUPFIXED | flags::CREATE))
    );
    println!();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..8 {
        let val = format!("{:04}", (i * 7) % 8);
        doput(&mut txn, dbi, "f", &val, 0);
    }
    let st = txn.stat(dbi).unwrap();
    println!("stat entries={} depth={}", st.entries, st.depth);
    let v = txn.get(dbi, b"f").unwrap();
    println!("get f dsz={}", v.len());
    let mut cur = txn.cursor_open(dbi).unwrap();
    let mut k = Vec::new();
    let mut v = Vec::new();
    let _ = cur.get(cursor_op::FIRST, &mut k, &mut v);
    print!("first d={}", hex(&v));
    println!();
    let cnt = cur.count().unwrap();
    print!("count={cnt}{}", rcstr(&Ok(())));
    println!();
    drop(cur);
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: st.psize as u64,
    };
    dump_all(&r, st.psize as u64);
    env.close();
}

fn phase_many(dir: &str) {
    let path = format!("{dir}/many");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase many keys");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();

    for i in 0..400 {
        let key = format!("k{i:04}");
        let val = format!("v{i:04}");
        doput(&mut txn, dbi, &key, &val, 0);
    }
    let st = txn.stat(dbi).unwrap();
    println!(
        "stat entries={} depth={} leaf={} branch={}",
        st.entries, st.depth, st.leaf_pages, st.branch_pages
    );
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..400 {
        let key = format!("r{:04}", 399 - i);
        let val = format!("w{:04}", 399 - i);
        doput(&mut txn, dbi, &key, &val, 0);
    }
    let st = txn.stat(dbi).unwrap();
    println!(
        "stat entries={} depth={} leaf={} branch={}",
        st.entries, st.depth, st.leaf_pages, st.branch_pages
    );
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* cursor traversal */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    let mut cur = txn.cursor_open(dbi).unwrap();
    let mut k = Vec::new();
    let mut v = Vec::new();
    let mut rc = cur.get(cursor_op::FIRST, &mut k, &mut v);
    let mut n = 0;
    while rc.is_ok() && n < 500 {
        n += 1;
        rc = cur.get(cursor_op::NEXT, &mut k, &mut v);
    }
    println!("cursor first->next n={n} rc={}", rccode(&rc));
    let _ = cur.get(cursor_op::LAST, &mut k, &mut v);
    print!("last k={} d={}", hex(&k), hex(&v));
    println!();
    n = 0;
    rc = cur.get(cursor_op::PREV, &mut k, &mut v);
    while rc.is_ok() && n < 500 {
        n += 1;
        rc = cur.get(cursor_op::PREV, &mut k, &mut v);
    }
    println!("cursor last->prev n={n} rc={}", rccode(&rc));
    k = b"k0099".to_vec();
    rc = cur.get(cursor_op::SET, &mut k, &mut v);
    print!("set k0099{} d={}", rcstr(&rc), hex(&v));
    println!();
    k = b"k0099".to_vec();
    rc = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
    print!("set_range k0099{} k={}", rcstr(&rc), hex(&k));
    println!();
    k = b"k9999\0".to_vec();
    rc = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
    print!("set_range k9999{} k={}", rcstr(&rc), hex(&k));
    println!();
    k = b"z9999".to_vec();
    rc = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
    print!("set_range z9999{}", rcstr(&rc));
    println!();
    drop(cur);
    txn.abort();

    /* deletes: rebalance, node move, page merge, root collapse */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..200 {
        let key = format!("k{:04}", i * 2);
        dodel(&mut txn, dbi, &key);
    }
    let st = txn.stat(dbi).unwrap();
    println!(
        "stat after del entries={} depth={} leaf={} branch={}",
        st.entries, st.depth, st.leaf_pages, st.branch_pages
    );
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* freeDB reuse: re-insert what we deleted */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..200 {
        let key = format!("k{:04}", i * 2);
        let val = format!("nv{i:04}");
        doput(&mut txn, dbi, &key, &val, 0);
    }
    let st = txn.stat(dbi).unwrap();
    println!(
        "stat after reinsert entries={} depth={} leaf={} branch={}",
        st.entries, st.depth, st.leaf_pages, st.branch_pages
    );
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    /* drain the tree down to nothing: root collapse */
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..800 {
        let key = format!("{}{:04}", if i < 400 { 'k' } else { 'r' }, i % 400);
        dodel(&mut txn, dbi, &key);
    }
    let st = txn.stat(dbi).unwrap();
    println!("stat drained entries={} depth={}", st.entries, st.depth);
    print!("commit{}", rcstr(&txn.commit()));
    println!();

    let file = format!("{path}/data.mdb");
    let r = Reader {
        file: std::fs::File::open(&file).unwrap(),
        psize: st.psize as u64,
    };
    dump_all(&r, st.psize as u64);
    env.close();
}

fn phase_readers(dir: &str) {
    let path = format!("{dir}/readers");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase readers");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut w = env.txn_begin(None, 0).unwrap();
    let dbi = w.dbi_open(None, 0).unwrap();
    for i in 0..4 {
        let key = format!("k{i}");
        doput(&mut w, dbi, &key, "v", 0);
    }
    w.commit().unwrap();

    let mut r1 = env.txn_begin(None, flags::RDONLY).unwrap();
    print!("rdonly begin{}", rcstr(&Ok(())));
    println!();
    let r2res = env.txn_begin(None, flags::RDONLY);
    print!("rdonly begin2{}", rcstr(&r2res));
    println!();
    /* a failed handle must not be aborted (the C keeps r2 = NULL) */
    let mut r2 = if let Ok(t) = r2res { Some(t) } else { None };

    let rc = r1.put(dbi, b"k0", b"x", 0);
    print!("rdonly put{}", rcstr(&rc));
    println!();

    print!("reader_list{}", rcstr(&Ok(())));
    println!();
    /* the reader-list rows mask pid and tid; the deterministic txnid
     * column is kept (mirrors the C probe's strtol/strtoull masking). */
    let s = env.reader_list().unwrap();
    for line in s.lines() {
        if line.get(4..7) == Some("pid") {
            println!("{line}");
        } else {
            let mut toks = line.split_whitespace();
            let _pid = toks.next().unwrap();
            let _tid = toks.next().unwrap();
            let txnid = toks.next().unwrap();
            println!("reader pid=<pid> tid=<tid> txnid={txnid}");
        }
    }
    let (dead, _) = env.reader_check().unwrap();
    print!("reader_check dead={dead}{}", rcstr(&Ok(())));
    println!();

    r1.abort();
    if let Some(mut t) = r2 {
        t.abort();
    }
    /* the thread's reader slot is free again: a new read txn succeeds */
    let r2res = env.txn_begin(None, flags::RDONLY);
    print!("rdonly begin2 again{}", rcstr(&r2res));
    println!();
    if let Ok(mut r2) = r2res {
        doget(&mut r2, dbi, "k1");
        r2.abort();
    }
    env.close();
}

fn phase_copy(dir: &str) {
    let path = format!("{dir}/copy");
    std::fs::create_dir_all(&path).unwrap();
    banner("phase copy");
    let mut env = Env::create().unwrap();
    env.open(&path, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    for i in 0..100 {
        let key = format!("ck{i:03}");
        doput(&mut txn, dbi, &key, "cv", 0);
    }
    txn.commit().unwrap();

    /* the copy target is a directory (the env is a subdir env): the file
     * written is <target>/data.mdb */
    let cout = format!("{path}/cout");
    std::fs::create_dir_all(&cout).unwrap();
    print!(
        "copy compact{}",
        rcstr(&env.copy2(&cout, flags::CP_COMPACT))
    );
    println!();
    let file = format!("{cout}/data.mdb");
    let sz = std::fs::metadata(&file).unwrap().len();
    println!("copy size={sz}");
    {
        let f = std::fs::File::open(&file).unwrap();
        let mut hdr = [0u8; 4096];
        let _ = f.read_at(&mut hdr, 0);
        /* meta0 mm_dbs[0].md_pad */
        let psize = rd32(&hdr, 16 + 24) as u64;
        let r = Reader { file: f, psize };
        dump_all(&r, psize);
    }
    let cout2 = format!("{path}/cout2");
    std::fs::create_dir_all(&cout2).unwrap();
    print!("copy plain{}", rcstr(&env.copy(&cout2)));
    println!();
    let file2 = format!("{cout2}/data.mdb");
    let sz2 = std::fs::metadata(&file2).unwrap().len();
    println!("copy2 size={sz2}");
    env.close();

    /* reopen the compact copy and validate */
    let mut env = Env::create().unwrap();
    env.open(&cout, 0, 0o664).unwrap();
    let mut txn = env.txn_begin(None, 0).unwrap();
    let dbi = txn.dbi_open(None, 0).unwrap();
    let st = txn.stat(dbi).unwrap();
    println!("compact stat entries={} depth={}", st.entries, st.depth);
    /* the C passes mv_size=4 ("ck05") — a 4-byte probe against 5-byte keys */
    let v = txn.get(dbi, b"ck05");
    match &v {
        Ok(v) => {
            print!("compact get ck050{} d={}", rcstr(&Ok(())), hex(v));
        }
        Err(e) => {
            print!(
                "compact get ck050{} d=",
                rcstr(&Result::<(), Error>::Err(*e))
            );
        }
    }
    println!();
    txn.abort();
    env.close();
}

fn main() {
    let dir = "/tmp/lmdb_work";
    std::fs::create_dir_all(dir).unwrap();
    phase_basic(dir);
    phase_named(dir);
    phase_overflow(dir);
    phase_dups(dir);
    phase_fixed(dir);
    phase_many(dir);
    phase_readers(dir);
    phase_copy(dir);
}
