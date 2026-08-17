//! LMDB 0.9.35 (Lightning Memory-Mapped Database) — native Rust conservation
//! of the `mdb_*` surface BIND 9.20.26 uses (catalog zones, runtime-zone
//! persistence, `dns_lmdb`), plus the on-disk page-level interoperability
//! contract (§24, §25, §38): C LMDB creates → Rust opens/modifies → C LMDB
//! reopens, and reverse.
//!
//! Archaeology (pinned sources): `libraries/liblmdb/{mdb.c,midl.c,lmdb.h,
//! midl.h}`.  The B+tree engine, the copy-on-write page management, the
//! freelist (`me_pghead`/`mt_free_pgs` IDLs in the freeDB), the two-meta
//! rotation, the cursor stack, the sorted-duplicates sub-pages/sub-DBs, the
//! reader lock table and the compacting copy are transcribed 1:1; the
//! on-disk structures (`MDB_page`, `MDB_node`, `MDB_db`, `MDB_meta`, the
//! freeDB record layout, the lock-file layout) are byte-exact.
//!
//! Engine notes (deliberate, courted):
//! - The data file is accessed with positional `read_at`/`write_at` instead
//!   of `mmap`; the observable file content is identical.
//! - Overflow-page unused tails are uninitialized `malloc` memory in the C
//!   (`mdb_page_malloc`'s num>1 path); the Rust zeroes them.  The court
//!   therefore compares record readbacks and the structured page dump, not
//!   raw trailing garbage (see the manifest's nondeterminism policy).
//! - The lock file's pthread mutex bytes are left zeroed; an opener holding
//!   the exclusive lock re-initializes them (what the C does on first open),
//!   and only the `mti_*` fields and reader slots are read/written here.
//!
//! Status: Phase 5 (§64).  LMDB-0001 court green at 0 residuals.

pub mod flags {
    // Environment flags (lmdb.h:285).
    pub const FIXEDMAP: u32 = 0x01;
    pub const NOSUBDIR: u32 = 0x4000;
    pub const NOSYNC: u32 = 0x10000;
    pub const RDONLY: u32 = 0x20000;
    pub const NOMETASYNC: u32 = 0x40000;
    pub const WRITEMAP: u32 = 0x80000;
    pub const MAPASYNC: u32 = 0x100000;
    pub const NOTLS: u32 = 0x200000;
    pub const NOLOCK: u32 = 0x400000;
    pub const NORDAHEAD: u32 = 0x800000;
    pub const NOMEMINIT: u32 = 0x1000000;
    // Database flags (lmdb.h:312).
    pub const REVERSEKEY: u32 = 0x02;
    pub const DUPSORT: u32 = 0x04;
    pub const INTEGERKEY: u32 = 0x08;
    pub const DUPFIXED: u32 = 0x10;
    pub const INTEGERDUP: u32 = 0x20;
    pub const REVERSEDUP: u32 = 0x40;
    pub const CREATE: u32 = 0x40000;
    // Write flags (lmdb.h:332).
    pub const NOOVERWRITE: u32 = 0x10;
    pub const NODUPDATA: u32 = 0x20;
    pub const CURRENT: u32 = 0x40;
    pub const RESERVE: u32 = 0x10000;
    pub const APPEND: u32 = 0x20000;
    pub const APPENDDUP: u32 = 0x40000;
    pub const MULTIPLE: u32 = 0x80000;
    // Copy flags (lmdb.h:358).
    pub const CP_COMPACT: u32 = 0x01;
    // The freeDB record's md_flags also persists env flags (mdb.c:1095).
    pub const PERSISTENT_FLAGS: u32 = 0xffff & !0x8000;
    pub const VALID_FLAGS: u32 =
        REVERSEKEY | DUPSORT | INTEGERKEY | DUPFIXED | INTEGERDUP | REVERSEDUP | CREATE;
    // Env flags changeable at runtime (mdb.c:5045).
    pub const CHANGEABLE: u32 = NOSYNC | NOMETASYNC | MAPASYNC | NOMEMINIT;
    pub const CHANGELESS: u32 =
        FIXEDMAP | NOSUBDIR | RDONLY | WRITEMAP | NOTLS | NOLOCK | NORDAHEAD;
}

/// `MDB_cursor_op` (lmdb.h:366).
pub mod cursor_op {
    pub const FIRST: i32 = 0;
    pub const FIRST_DUP: i32 = 1;
    pub const GET_BOTH: i32 = 2;
    pub const GET_BOTH_RANGE: i32 = 3;
    pub const GET_CURRENT: i32 = 4;
    pub const GET_MULTIPLE: i32 = 5;
    pub const LAST: i32 = 6;
    pub const LAST_DUP: i32 = 7;
    pub const NEXT: i32 = 8;
    pub const NEXT_DUP: i32 = 9;
    pub const NEXT_MULTIPLE: i32 = 10;
    pub const NEXT_NODUP: i32 = 11;
    pub const PREV: i32 = 12;
    pub const PREV_DUP: i32 = 13;
    pub const PREV_NODUP: i32 = 14;
    pub const SET: i32 = 15;
    pub const SET_KEY: i32 = 16;
    pub const SET_RANGE: i32 = 17;
    pub const PREV_MULTIPLE: i32 = 18;
}

/// LMDB return codes (lmdb.h:403) plus the errno codes the C surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    Ok = 0,
    KeyExist = -30799,
    NotFound = -30798,
    PageNotFound = -30797,
    Corrupted = -30796,
    Panic = -30795,
    VersionMismatch = -30794,
    Invalid = -30793,
    MapFull = -30792,
    DbsFull = -30791,
    ReadersFull = -30790,
    TlsFull = -30789,
    TxnFull = -30788,
    CursorFull = -30787,
    PageFull = -30786,
    MapResized = -30785,
    Incompatible = -30784,
    BadRslot = -30783,
    BadTxn = -30782,
    BadValSize = -30781,
    BadDbi = -30780,
    /// Internal sentinel only: no root page yet (mdb.c's `MDB_NO_ROOT`),
    /// never surfaced by the public API.
    NoRoot = -30000,
    // errno values the C surfaces directly.
    Eperm = 1,
    Enoent = 2,
    Einr = 4,
    Eio = 5,
    Enomem = 12,
    Eacces = 13,
    Ebusy = 16,
    Einval = 22,
    Enospc = 28,
    Erofs = 30,
}

impl Error {
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// `mdb_strerror` text (mdb.c:1504).
    #[must_use]
    pub fn strerror(self) -> &'static str {
        match self {
            Error::Ok => "Successful return: 0",
            Error::KeyExist => "MDB_KEYEXIST: Key/data pair already exists",
            Error::NotFound => "MDB_NOTFOUND: No matching key/data pair found",
            Error::PageNotFound => "MDB_PAGE_NOTFOUND: Requested page not found",
            Error::Corrupted => "MDB_CORRUPTED: Located page was wrong type",
            Error::Panic => "MDB_PANIC: Update of meta page failed or environment had fatal error",
            Error::VersionMismatch => "MDB_VERSION_MISMATCH: Database environment version mismatch",
            Error::Invalid => "MDB_INVALID: File is not an LMDB file",
            Error::MapFull => "MDB_MAP_FULL: Environment mapsize limit reached",
            Error::DbsFull => "MDB_DBS_FULL: Environment maxdbs limit reached",
            Error::ReadersFull => "MDB_READERS_FULL: Environment maxreaders limit reached",
            Error::TlsFull => {
                "MDB_TLS_FULL: Thread-local storage keys full - too many environments open"
            }
            Error::TxnFull => {
                "MDB_TXN_FULL: Transaction has too many dirty pages - transaction too big"
            }
            Error::CursorFull => "MDB_CURSOR_FULL: Internal error - cursor stack limit reached",
            Error::PageFull => "MDB_PAGE_FULL: Internal error - page has no more space",
            Error::MapResized => {
                "MDB_MAP_RESIZED: Database contents grew beyond environment mapsize"
            }
            Error::Incompatible => {
                "MDB_INCOMPATIBLE: Operation and DB incompatible, or DB flags changed"
            }
            Error::BadRslot => "MDB_BAD_RSLOT: Invalid reuse of reader locktable slot",
            Error::BadTxn => "MDB_BAD_TXN: Transaction must abort, has a child, or is invalid",
            Error::BadValSize => {
                "MDB_BAD_VALSIZE: Unsupported size of key/DB name/data, or wrong DUPFIXED size"
            }
            Error::BadDbi => {
                "MDB_BAD_DBI: The specified DBI handle was closed/changed unexpectedly"
            }
            Error::NoRoot => "MDB_NO_ROOT: internal sentinel (never returned by the public API)",
            // The C's mdb_strerror surfaces strerror() text for errno codes.
            Error::Eperm => "Operation not permitted",
            Error::Enoent => "No such file or directory",
            Error::Einr => "Interrupted system call",
            Error::Eio => "Input/output error",
            Error::Enomem => "Cannot allocate memory",
            Error::Eacces => "Permission denied",
            Error::Ebusy => "Device or resource busy",
            Error::Einval => "Invalid argument",
            Error::Enospc => "No space left on device",
            Error::Erofs => "Read-only file system",
            _ => "Unknown error",
        }
    }

    /// Symbol name for the probe output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Error::Ok => "MDB_SUCCESS",
            Error::KeyExist => "MDB_KEYEXIST",
            Error::NotFound => "MDB_NOTFOUND",
            Error::PageNotFound => "MDB_PAGE_NOTFOUND",
            Error::Corrupted => "MDB_CORRUPTED",
            Error::Panic => "MDB_PANIC",
            Error::VersionMismatch => "MDB_VERSION_MISMATCH",
            Error::Invalid => "MDB_INVALID",
            Error::MapFull => "MDB_MAP_FULL",
            Error::DbsFull => "MDB_DBS_FULL",
            Error::ReadersFull => "MDB_READERS_FULL",
            Error::TlsFull => "MDB_TLS_FULL",
            Error::TxnFull => "MDB_TXN_FULL",
            Error::CursorFull => "MDB_CURSOR_FULL",
            Error::PageFull => "MDB_PAGE_FULL",
            Error::MapResized => "MDB_MAP_RESIZED",
            Error::Incompatible => "MDB_INCOMPATIBLE",
            Error::BadRslot => "MDB_BAD_RSLOT",
            Error::BadTxn => "MDB_BAD_TXN",
            Error::BadValSize => "MDB_BAD_VALSIZE",
            Error::BadDbi => "MDB_BAD_DBI",
            Error::NoRoot => "MDB_NO_ROOT",
            Error::Eperm => "EPERM",
            Error::Enoent => "ENOENT",
            Error::Einr => "EINTR",
            Error::Eio => "EIO",
            Error::Enomem => "ENOMEM",
            Error::Eacces => "EACCES",
            Error::Ebusy => "EBUSY",
            Error::Einval => "EINVAL",
            Error::Enospc => "ENOSPC",
            Error::Erofs => "EROFS",
        }
    }
}

impl From<i32> for Error {
    fn from(v: i32) -> Self {
        match v {
            0 => Error::Ok,
            -30799 => Error::KeyExist,
            -30798 => Error::NotFound,
            -30797 => Error::PageNotFound,
            -30796 => Error::Corrupted,
            -30795 => Error::Panic,
            -30794 => Error::VersionMismatch,
            -30793 => Error::Invalid,
            -30792 => Error::MapFull,
            -30791 => Error::DbsFull,
            -30790 => Error::ReadersFull,
            -30789 => Error::TlsFull,
            -30788 => Error::TxnFull,
            -30787 => Error::CursorFull,
            -30786 => Error::PageFull,
            -30785 => Error::MapResized,
            -30784 => Error::Incompatible,
            -30783 => Error::BadRslot,
            -30782 => Error::BadTxn,
            -30781 => Error::BadValSize,
            -30780 => Error::BadDbi,
            -30000 => Error::NoRoot,
            1 => Error::Eperm,
            2 => Error::Enoent,
            4 => Error::Einr,
            5 => Error::Eio,
            12 => Error::Enomem,
            13 => Error::Eacces,
            16 => Error::Ebusy,
            22 => Error::Einval,
            28 => Error::Enospc,
            30 => Error::Erofs,
            _ => Error::BadDbi,
        }
    }
}

/// `MDB_stat` (lmdb.h:456).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub psize: u32,
    pub depth: u32,
    pub branch_pages: u64,
    pub leaf_pages: u64,
    pub overflow_pages: u64,
    pub entries: u64,
}

/// `MDB_envinfo` (lmdb.h:467).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvInfo {
    pub mapaddr: u64,
    pub mapsize: u64,
    pub last_pgno: u64,
    pub last_txnid: u64,
    pub maxreaders: u32,
    pub numreaders: u32,
}

pub type Val = Vec<u8>;

pub const VERSION_STRING: &str = "LMDB 0.9.35: (Jan 27, 2026)";
pub const VERSION_MAJOR: i32 = 0;
pub const VERSION_MINOR: i32 = 9;
pub const VERSION_PATCH: i32 = 35;

pub const MDB_MAXKEYSIZE: usize = 511;

mod core;
pub use core::{Cursor, Env, Txn};

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("b9rs-lmdb-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn version_and_strerror() {
        assert_eq!(VERSION_STRING, "LMDB 0.9.35: (Jan 27, 2026)");
        assert_eq!(Error::KeyExist.code(), -30799);
        assert_eq!(
            Error::MapFull.strerror(),
            "MDB_MAP_FULL: Environment mapsize limit reached"
        );
    }

    #[test]
    fn basic_put_get_roundtrip() {
        let dir = tmpdir("basic");
        let mut env = Env::create().unwrap();
        env.set_mapsize(1 << 20).unwrap();
        env.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            txn.put(1, b"key1", b"value1", 0).unwrap();
            txn.put(1, b"key2", b"value2", 0).unwrap();
            assert_eq!(txn.get(1, b"key1").unwrap(), b"value1");
            assert_eq!(txn.get(1, b"key2").unwrap(), b"value2");
            assert_eq!(txn.get(1, b"nokey").unwrap_err(), Error::NotFound);
            let st = txn.stat(1).unwrap();
            assert_eq!(st.entries, 2);
            txn.commit().unwrap();
        }
        let mut env2 = Env::create().unwrap();
        env2.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env2.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            assert_eq!(txn.get(1, b"key1").unwrap(), b"value1");
            txn.del(1, b"key1", None).unwrap();
            assert_eq!(txn.get(1, b"key1").unwrap_err(), Error::NotFound);
            txn.commit().unwrap();
        }
        env2.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dupsort_and_cursor_ops() {
        let dir = tmpdir("dups");
        let mut env = Env::create().unwrap();
        env.set_mapsize(1 << 20).unwrap();
        env.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            let dbi = txn.dbi_open(None, flags::DUPSORT | flags::CREATE).unwrap();
            txn.put(dbi, b"k", b"b", 0).unwrap();
            txn.put(dbi, b"k", b"a", 0).unwrap();
            txn.put(dbi, b"k", b"c", 0).unwrap();
            let mut cur = txn.cursor_open(dbi).unwrap();
            let mut key = Vec::new();
            let mut data = Vec::new();
            cur.get(cursor_op::FIRST, &mut key, &mut data).unwrap();
            assert_eq!(
                (key.as_slice(), data.as_slice()),
                (b"k".as_slice(), b"a".as_slice())
            );
            cur.get(cursor_op::NEXT, &mut key, &mut data).unwrap();
            assert_eq!(data, b"b");
            cur.get(cursor_op::NEXT, &mut key, &mut data).unwrap();
            assert_eq!(data, b"c");
            assert_eq!(
                cur.get(cursor_op::NEXT, &mut key, &mut data).unwrap_err(),
                Error::NotFound
            );
            let n = cur.count().unwrap();
            assert_eq!(n, 3);
            txn.commit().unwrap();
        }
        env.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overflow_data() {
        let dir = tmpdir("ovf");
        let mut env = Env::create().unwrap();
        env.set_mapsize(1 << 20).unwrap();
        env.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            let big = vec![0xABu8; 5000];
            txn.put(1, b"big", &big, 0).unwrap();
            assert_eq!(txn.get(1, b"big").unwrap(), big);
            let st = txn.stat(1).unwrap();
            assert!(
                st.overflow_pages >= 2,
                "overflow_pages={}",
                st.overflow_pages
            );
            txn.commit().unwrap();
        }
        env.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn named_db_reopen_drop() {
        let dir = tmpdir("named");
        let mut env = Env::create().unwrap();
        env.set_maxdbs(8).unwrap();
        env.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            let main = txn.dbi_open(None, 0).unwrap();
            let sub = txn.dbi_open(Some("subdb"), flags::CREATE).unwrap();
            assert_eq!(sub, 2);
            txn.put(sub, b"s1", b"sv1", 0).unwrap();
            txn.put(main, b"mainkey", b"mainval", 0).unwrap();
            assert_eq!(txn.get(sub, b"s1").unwrap(), b"sv1");
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            let sub = txn.dbi_open(Some("subdb"), 0).unwrap();
            assert_eq!(txn.get(sub, b"s1").unwrap(), b"sv1", "reopen get s1");
            let sub2 = txn.dbi_open(Some("subdb"), flags::CREATE).unwrap();
            assert_eq!(sub, sub2);
            txn.drop(sub, true).unwrap();
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            assert_eq!(
                txn.dbi_open(Some("subdb"), 0).unwrap_err(),
                Error::NotFound,
                "reopen after drop"
            );
            txn.abort();
        }
        env.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn many_keys_delete_rebalance() {
        let dir = tmpdir("many");
        let mut env = Env::create().unwrap();
        env.open(dir.join("data.mdb").to_str().unwrap(), 0, 0o644)
            .unwrap();
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            for i in 0..400 {
                txn.put(
                    1,
                    format!("k{i:04}").as_bytes(),
                    format!("v{i:04}").as_bytes(),
                    0,
                )
                .unwrap();
            }
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            for i in 0..400 {
                txn.put(
                    1,
                    format!("r{:04}", 399 - i).as_bytes(),
                    format!("w{:04}", 399 - i).as_bytes(),
                    0,
                )
                .unwrap();
            }
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            let st = txn.stat(1).unwrap();
            assert_eq!(st.entries, 800, "entries={}", st.entries);
            // mirror the probe's traversal (aborted, no commit)
            {
                let mut cur = txn.cursor_open(1).unwrap();
                let mut k = Vec::new();
                let mut v = Vec::new();
                let mut rc = cur.get(cursor_op::FIRST, &mut k, &mut v);
                let mut n = 0;
                while rc.is_ok() && n < 500 {
                    n += 1;
                    rc = cur.get(cursor_op::NEXT, &mut k, &mut v);
                }
                assert_eq!(n, 500, "traversal n={n}");
                let _ = cur.get(cursor_op::LAST, &mut k, &mut v);
                let mut n = 0;
                rc = cur.get(cursor_op::PREV, &mut k, &mut v);
                while rc.is_ok() && n < 500 {
                    n += 1;
                    rc = cur.get(cursor_op::PREV, &mut k, &mut v);
                }
                assert_eq!(n, 500, "prev n={n}");
                k = b"k0099".to_vec();
                let _ = cur.get(cursor_op::SET, &mut k, &mut v);
                k = b"k0099".to_vec();
                let _ = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
                k = b"k9999\0".to_vec();
                let _ = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
                k = b"z9999".to_vec();
                let _ = cur.get(cursor_op::SET_RANGE, &mut k, &mut v);
            }
            txn.abort();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            // deletes: rebalance, node move, page merge, root collapse
            for i in 0..200 {
                txn.del(1, format!("k{:04}", i * 2).as_bytes(), None)
                    .unwrap_or_else(|e| panic!("del failed at i={i}: {e:?}"));
            }
            let st = txn.stat(1).unwrap();
            assert_eq!(st.entries, 600, "entries={}", st.entries);
            for i in 0..200 {
                let key = format!("k{:04}", i * 2 + 1);
                if txn.get(1, key.as_bytes()).is_err() {
                    panic!("post-delete missing odd {key}");
                }
            }
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            // freeDB reuse: re-insert what we deleted
            for i in 0..200 {
                txn.put(
                    1,
                    format!("k{:04}", i * 2).as_bytes(),
                    format!("nv{i:04}").as_bytes(),
                    0,
                )
                .unwrap_or_else(|e| panic!("reinsert put failed at i={i}: {e:?}"));
            }
            let st = txn.stat(1).unwrap();
            assert_eq!(st.entries, 800, "entries={}", st.entries);
            for i in 0..400 {
                let key = format!("k{i:04}");
                if txn.get(1, key.as_bytes()).is_err() {
                    panic!("post-reinsert missing {key}");
                }
            }
            for i in 0..400 {
                let key = format!("r{i:04}");
                if txn.get(1, key.as_bytes()).is_err() {
                    panic!("post-reinsert missing {key}");
                }
            }
            txn.commit().unwrap();
        }
        {
            let mut txn = env.txn_begin(None, 0).unwrap();
            txn.dbi_open(None, 0).unwrap();
            // drain the tree down to nothing: root collapse
            for i in 0..800 {
                let key = format!("{}{:04}", if i < 400 { 'k' } else { 'r' }, i % 400);
                if txn.del(1, key.as_bytes(), None).is_err() {
                    panic!("drain del failed at i={i} key={key}");
                }
            }
            let st = txn.stat(1).unwrap();
            assert_eq!(st.entries, 0, "entries={}", st.entries);
            txn.commit().unwrap();
        }
        env.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
