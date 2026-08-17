/*
 * probe-lmdb.c — oracle probe for the LMDB-0001 court (§24, §25, §38).
 *
 * Exercises the mdb_* surface BIND 9.20.26 uses (catalog zones, runtime-zone
 * persistence, dns_lmdb) plus the on-disk page-level interoperability
 * contract: a deterministic op sequence per phase and a structured page dump
 * of the main db and the freeDB.
 *
 * The page dump parses data.mdb DIRECTLY (MDB_page/MDB_node/MDB_db/MDB_meta
 * layouts are part of the on-disk contract) and prints pgno/flags/lower/
 * upper/node keys/data sizes — NOT raw bytes, so the C's uninitialized
 * overflow-page tails are excluded (see the manifest's nondeterminism
 * policy).  The dump therefore makes the whole tree structure observable:
 * split points, node order, sub-page regions, sub-DB records, freeDB
 * records.
 *
 * Every observable result is printed with the same format the Rust mirror
 * (bind9-rs-tools/src/bin/lmdb-probe.rs) reproduces; stdout must be
 * byte-identical.  pid/tid are masked in the reader-list output.
 *
 * Build: gcc -I/opt/dep/include -o cprobe probe-lmdb.c -L/opt/dep/lib -llmdb
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "lmdb.h"

/* ------------------------------------------------------------------ */
/* on-disk format (mdb.c: PAGEHDRSZ etc. — part of the file contract)  */
/* ------------------------------------------------------------------ */

#define PAGEHDRSZ 16
#define NODESIZE 10
#define P_BRANCH 0x01
#define P_LEAF 0x02
#define P_OVERFLOW 0x04
#define P_META 0x08
#define P_DIRTY 0x10
#define P_LEAF2 0x20
#define P_SUBP 0x40
#define F_BIGDATA 0x01
#define F_SUBDATA 0x02
#define F_DUPDATA 0x04
#define P_INVALID (~(uint64_t)0)

struct page_hdr {
    uint64_t pgno;
    uint16_t pad;
    uint16_t flags;
    uint16_t lower;
    uint16_t upper;
};

struct node_hdr {
    uint16_t lo;
    uint16_t hi;
    uint16_t flags;
    uint16_t ksize;
};

struct mdb_db {
    uint32_t pad;
    uint16_t flags;
    uint16_t depth;
    uint64_t branch_pages;
    uint64_t leaf_pages;
    uint64_t overflow_pages;
    uint64_t entries;
    uint64_t root;
};

struct mdb_meta {
    uint32_t magic;
    uint32_t version;
    uint64_t address;
    uint64_t mapsize;
    struct mdb_db dbs[2];
    uint64_t last_pg;
    uint64_t txnid;
};

static uint64_t rd64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}
static uint32_t rd32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}
static uint16_t rd16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

struct reader {
    int fd;
    uint64_t psize;
};

static int pread_full(struct reader *r, uint64_t pgno, unsigned char *buf,
    size_t len)
{
    ssize_t n = pread(r->fd, buf, len, (off_t)(pgno * r->psize));
    return n == (ssize_t)len ? 0 : -1;
}

static struct mdb_meta read_meta(struct reader *r, uint64_t psize)
{
    unsigned char p[4096];
    struct mdb_meta m0, m1;
    pread_full(r, 0, p, psize);
    memcpy(&m0, p + PAGEHDRSZ, sizeof(m0));
    pread_full(r, 1, p, psize);
    memcpy(&m1, p + PAGEHDRSZ, sizeof(m1));
    return (m0.txnid > m1.txnid) ? m0 : m1;
}

/* ------------------------------------------------------------------ */
/* output helpers                                                      */
/* ------------------------------------------------------------------ */

static void hex(const unsigned char *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void rcname(int rc)
{
    printf(" rc=%d (%s)", rc, mdb_strerror(rc));
}

/* ------------------------------------------------------------------ */
/* deterministic op helpers                                            */
/* ------------------------------------------------------------------ */

static int lst_append(const char *msg, void *ctx)
{
    struct lst_ctx { char buf[8192]; size_t len; } *c = ctx;
    size_t n = strlen(msg);
    if (c->len + n < sizeof(c->buf)) {
        memcpy(c->buf + c->len, msg, n);
        c->len += n;
    }
    return 0;
}

static void banner(const char *s)
{
    printf("== %s\n", s);
}

static void doput(MDB_txn *txn, MDB_dbi dbi, const char *ks, const char *vs,
    unsigned flags)
{
    MDB_val k, v;
    int rc;
    k.mv_size = strlen(ks);
    k.mv_data = (void *)ks;
    v.mv_size = strlen(vs);
    v.mv_data = (void *)vs;
    rc = mdb_put(txn, dbi, &k, &v, flags);
    printf("put %s", ks);
    rcname(rc);
    printf("\n");
}

static void doget(MDB_txn *txn, MDB_dbi dbi, const char *ks)
{
    MDB_val k, v;
    int rc;
    k.mv_size = strlen(ks);
    k.mv_data = (void *)ks;
    v.mv_size = 0;
    v.mv_data = NULL;
    rc = mdb_get(txn, dbi, &k, &v);
    printf("get %s", ks);
    if (rc)
        rcname(rc);
    else {
        printf(" -> ");
        hex(v.mv_data, v.mv_size);
    }
    printf("\n");
}

static void dodel(MDB_txn *txn, MDB_dbi dbi, const char *ks)
{
    MDB_val k;
    int rc;
    k.mv_size = strlen(ks);
    k.mv_data = (void *)ks;
    rc = mdb_del(txn, dbi, &k, NULL);
    printf("del %s", ks);
    rcname(rc);
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* structured page dump (direct file parse)                            */
/* ------------------------------------------------------------------ */

static void dump_pg(struct reader *r, uint64_t pgno, int depth);

static void dump_dups_region(const unsigned char *sub, size_t region)
{
    unsigned n = (rd16(sub + 12) - PAGEHDRSZ) >> 1;
    unsigned i;
    printf(" subpage nkeys=%u", n);
    if (sub[10] & P_LEAF2) {
        unsigned ksize = rd16(sub + 8);
        printf(" pad=%u", ksize);
        for (i = 0; i < n; i++) {
            printf("(");
            hex(sub + PAGEHDRSZ + i * ksize, ksize);
            printf(")");
        }
    } else {
        for (i = 0; i < n; i++) {
            uint16_t off = rd16(sub + PAGEHDRSZ + i * 2);
            const unsigned char *node = sub + off;
            uint16_t ksize = rd16(node + 6);
            printf("(");
            hex(node + 8, ksize);
            printf(")");
        }
    }
    (void)region;
    printf("\n");
}

static void dump_node(struct reader *r, const unsigned char *pg,
    unsigned i, int depth)
{
    uint16_t off = rd16(pg + PAGEHDRSZ + i * 2);
    const unsigned char *node = pg + off;
    uint16_t ksize = rd16(node + 6);
    uint16_t flags = rd16(node + 4);
    uint32_t lo = rd16(node);
    uint32_t hi = rd16(node + 2);
    size_t dsz = (size_t)lo | ((size_t)hi << 16);
    printf(" node[%u] key=", i);
    hex(node + 8, ksize);
    printf(" ksize=%u dsz=%zu flags=0x%02x", ksize, dsz, flags);
    if (pg[10] & P_BRANCH) {
        uint64_t child = (uint64_t)lo | ((uint64_t)hi << 16)
            | ((uint64_t)flags << 32);
        printf(" child=%" PRIu64, child);
    } else if (flags & F_DUPDATA) {
        const unsigned char *data = node + 8 + ksize;
        if (flags & F_SUBDATA) {
            struct mdb_db db;
            memcpy(&db, data, sizeof(db));
            printf(" subdb entries=%" PRIu64 " root=%" PRIu64 "\n",
                (uint64_t)db.entries, (uint64_t)db.root);
            if (db.root != P_INVALID) {
                printf("%*s  subdb depth=%u\n", depth * 2, "",
                    (unsigned)db.depth);
                dump_pg(r, db.root, depth + 1);
            }
            return;
        }
        dump_dups_region(data, dsz);
        return;
    }
    printf("\n");
}

static void dump_pg(struct reader *r, uint64_t pgno, int depth)
{
    unsigned char pg[65536];
    unsigned i, n;
    if (pread_full(r, pgno, pg, r->psize))
        return;
    n = (rd16(pg + 12) - PAGEHDRSZ) >> 1;
    printf("%*spage pgno=%" PRIu64 " flags=0x%02x lower=%u upper=%u nkeys=%u%s\n",
        depth * 2, "", rd64(pg), rd16(pg + 10), (unsigned)rd16(pg + 12),
        (unsigned)rd16(pg + 14), n,
        (pg[10] & P_OVERFLOW) ? " overflow" : "");
    if (pg[10] & P_OVERFLOW) {
        printf("%*s  overflow pages=%u\n", depth * 2, "",
            (unsigned)rd32(pg + 12));
        return;
    }
    if (pg[10] & P_LEAF2) {
        unsigned ksize = rd16(pg + 8);
        printf("%*s  pad=%u", depth * 2, "", ksize);
        for (i = 0; i < n; i++) {
            printf(" key[%u]=", i);
            hex(pg + PAGEHDRSZ + i * ksize, ksize);
        }
        printf("\n");
        return;
    }
    for (i = 0; i < n; i++) {
        printf("%*s", depth * 2, "");
        dump_node(r, pg, i, depth);
        if (pg[10] & P_BRANCH) {
            uint16_t off = rd16(pg + PAGEHDRSZ + i * 2);
            const unsigned char *node = pg + off;
            uint64_t child = (uint64_t)rd16(node)
                | ((uint64_t)rd16(node + 2) << 16)
                | ((uint64_t)rd16(node + 4) << 32);
            dump_pg(r, child, depth + 1);
        }
    }
}

static void dump_db(struct reader *r, const struct mdb_db *db,
    const char *label)
{
    printf("== dump %s entries=%" PRIu64 " depth=%u leaf=%" PRIu64
        " branch=%" PRIu64 " overflow=%" PRIu64 "\n", label,
        (uint64_t)db->entries, (unsigned)db->depth, (uint64_t)db->leaf_pages,
        (uint64_t)db->branch_pages, (uint64_t)db->overflow_pages);
    if (db->root != P_INVALID)
        dump_pg(r, db->root, 1);
    else
        printf("  (empty)\n");
}

static void dump_all(struct reader *r, uint64_t psize)
{
    struct mdb_meta m = read_meta(r, psize);
    printf("== meta txnid=%" PRIu64 " last_pg=%" PRIu64 " mapsize=%" PRIu64
        "\n", (uint64_t)m.txnid, (uint64_t)m.last_pg, (uint64_t)m.mapsize);
    dump_db(r, &m.dbs[1], "main");
    dump_db(r, &m.dbs[0], "free");
}

/* ------------------------------------------------------------------ */
/* phases                                                              */
/* ------------------------------------------------------------------ */

static void phase_basic(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    MDB_stat st;
    int rc;
    char path[512];
    char file[600];
    struct reader r;

    snprintf(path, sizeof(path), "%s/basic", dir);
    mkdir(path, 0777);
    banner("phase basic");
    rc = mdb_env_create(&env);
    printf("env_create"); rcname(rc); printf("\n");
    mdb_env_set_mapsize(env, 1UL << 20);
    rc = mdb_env_open(env, path, 0, 0664);
    printf("env_open"); rcname(rc); printf("\n");

    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    doput(txn, dbi, "key1", "value1", 0);
    doput(txn, dbi, "key2", "value2", 0);
    doput(txn, dbi, "key0", "value0", 0);
    doput(txn, dbi, "key1", "valueX", 0);      /* overwrite */
    doput(txn, dbi, "key1", "valueY", MDB_NOOVERWRITE); /* -> KEYEXIST */
    doget(txn, dbi, "key0");
    doget(txn, dbi, "key1");
    doget(txn, dbi, "key2");
    doget(txn, dbi, "nokey");
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u leaf=%" PRIu64 " branch=%" PRIu64
        " overflow=%" PRIu64 " psize=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth, (uint64_t)st.ms_leaf_pages,
        (uint64_t)st.ms_branch_pages, (uint64_t)st.ms_overflow_pages,
        (unsigned)st.ms_psize);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = st.ms_psize;
    dump_all(&r, st.ms_psize);
    close(r.fd);

    /* reopen and validate */
    mdb_env_close(env);
    rc = mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    doget(txn, dbi, "key1");
    dodel(txn, dbi, "key1");
    doget(txn, dbi, "key1");
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");
    mdb_env_close(env);
}

static void phase_named(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi, sub;
    MDB_stat st;
    int rc;
    char path[512];
    char file[600];
    struct reader r;

    snprintf(path, sizeof(path), "%s/named", dir);
    mkdir(path, 0777);
    banner("phase named dbs");
    mdb_env_create(&env);
    mdb_env_set_maxdbs(env, 8);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    rc = mdb_dbi_open(txn, "subdb", MDB_CREATE, &sub);
    printf("dbi_open subdb"); rcname(rc); printf(" dbi=%u\n", sub);
    doput(txn, sub, "s1", "sv1", 0);
    doput(txn, dbi, "mainkey", "mainval", 0);
    doget(txn, sub, "s1");
    mdb_stat(txn, sub, &st);
    printf("stat sub entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* reopen the named db from a fresh txn */
    mdb_txn_begin(env, NULL, 0, &txn);
    rc = mdb_dbi_open(txn, "subdb", 0, &sub);
    printf("dbi_open subdb ro"); rcname(rc); printf(" dbi=%u\n", sub);
    doget(txn, sub, "s1");
    rc = mdb_dbi_open(txn, "subdb", MDB_CREATE, &sub);
    printf("dbi_open subdb again"); rcname(rc); printf("\n");
    rc = mdb_drop(txn, sub, 1);
    printf("drop subdb"); rcname(rc); printf("\n");
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    mdb_txn_begin(env, NULL, 0, &txn);
    rc = mdb_dbi_open(txn, "subdb", 0, &sub);
    printf("dbi_open dropped"); rcname(rc); printf("\n");
    mdb_txn_abort(txn);
    mdb_env_close(env);

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = 4096;
    dump_all(&r, 4096);
    close(r.fd);
}

static void phase_overflow(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    MDB_stat st;
    int rc, i;
    char path[512];
    char file[600];
    unsigned char big[9000];
    struct reader r;

    snprintf(path, sizeof(path), "%s/overflow", dir);
    mkdir(path, 0777);
    banner("phase overflow");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);

    for (i = 0; i < 9000; i++)
        big[i] = (unsigned char)(i * 7 + 3);
    {
        MDB_val k, v;
        k.mv_size = 3;
        k.mv_data = "big";
        v.mv_size = 9000;
        v.mv_data = big;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        printf("put big 9000"); rcname(rc); printf("\n");
    }
    {
        MDB_val k, v;
        k.mv_size = 3;
        k.mv_data = "big";
        v.mv_size = 0;
        v.mv_data = NULL;
        rc = mdb_get(txn, dbi, &k, &v);
        printf("get big -> %zu bytes, first=", (size_t)v.mv_size);
        hex(v.mv_data, 16);
        printf(" last=");
        hex((unsigned char *)v.mv_data + v.mv_size - 16, 16);
        printf("\n");
    }
    for (i = 0; i < 3000; i++)
        big[i] = (unsigned char)(i * 13 + 1);
    {
        MDB_val k, v;
        k.mv_size = 4;
        k.mv_data = "med1";
        v.mv_size = 3000;
        v.mv_data = big;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        printf("put med1 3000"); rcname(rc); printf("\n");
    }
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " overflow=%" PRIu64 "\n",
        (uint64_t)st.ms_entries, (uint64_t)st.ms_overflow_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* overwrite: same size, then shrink */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 9000; i++)
        big[i] = (unsigned char)(255 - i);
    {
        MDB_val k, v;
        k.mv_size = 3;
        k.mv_data = "big";
        v.mv_size = 9000;
        v.mv_data = big;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        printf("put big same size"); rcname(rc); printf("\n");
    }
    {
        MDB_val k, v;
        k.mv_size = 3;
        k.mv_data = "big";
        v.mv_size = 1000;
        v.mv_data = big;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        printf("put big shrink 1000"); rcname(rc); printf("\n");
    }
    {
        MDB_val k, v;
        k.mv_size = 3;
        k.mv_data = "big";
        v.mv_size = 0;
        v.mv_data = NULL;
        rc = mdb_get(txn, dbi, &k, &v);
        printf("get big -> %zu bytes first=", (size_t)v.mv_size);
        hex(v.mv_data, 8);
        printf("\n");
    }
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = st.ms_psize;
    dump_all(&r, st.ms_psize);
    close(r.fd);

    /* delete the overflow keys to exercise the free list */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    dodel(txn, dbi, "big");
    dodel(txn, dbi, "med1");
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " overflow=%" PRIu64 "\n",
        (uint64_t)st.ms_entries, (uint64_t)st.ms_overflow_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");
    mdb_env_close(env);
}

static void phase_dups(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    MDB_stat st;
    int rc, i;
    char path[512];
    char file[600];
    char val[64];
    struct reader r;

    snprintf(path, sizeof(path), "%s/dups", dir);
    mkdir(path, 0777);
    banner("phase dupsort");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    rc = mdb_dbi_open(txn, NULL, MDB_DUPSORT | MDB_CREATE, &dbi);
    printf("dbi_open dupsort"); rcname(rc); printf("\n");

    doput(txn, dbi, "k", "b", 0);
    doput(txn, dbi, "k", "a", 0);
    doput(txn, dbi, "k", "c", 0);
    doput(txn, dbi, "k", "a", MDB_NODUPDATA); /* -> KEYEXIST */
    doput(txn, dbi, "j", "z", 0);
    doput(txn, dbi, "k", "a", 0); /* dup already present: no-op */
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);

    {
        MDB_cursor *mc;
        MDB_val k, v;
        size_t cnt;
        rc = mdb_cursor_open(txn, dbi, &mc);
        printf("cursor_open"); rcname(rc); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_FIRST);
        printf("first k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_NEXT);
        printf("next k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_NEXT_DUP);
        printf("next_dup k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_NEXT);
        printf("next k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_NEXT_NODUP);
        printf("next_nodup k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_PREV);
        printf("prev k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_count(mc, &cnt);
        printf("count=%zu", cnt); rcname(rc); printf("\n");
        v.mv_size = 1;
        v.mv_data = "b";
        rc = mdb_cursor_get(mc, &k, &v, MDB_GET_BOTH);
        printf("get_both b"); rcname(rc); printf(" d="); hex(v.mv_data, v.mv_size);
        printf("\n");
        v.mv_size = 1;
        v.mv_data = "z";
        rc = mdb_cursor_get(mc, &k, &v, MDB_GET_BOTH);
        printf("get_both z"); rcname(rc); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_FIRST_DUP);
        printf("first_dup d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_get(mc, &k, &v, MDB_LAST_DUP);
        printf("last_dup d="); hex(v.mv_data, v.mv_size); printf("\n");
        mdb_cursor_close(mc);
    }
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* delete dups: sub-page shrink */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    {
        MDB_val k, v;
        k.mv_size = 1;
        k.mv_data = "k";
        v.mv_size = 1;
        v.mv_data = "b";
        rc = mdb_del(txn, dbi, &k, &v);
        printf("del k/b"); rcname(rc); printf("\n");
    }
    {
        MDB_val k, v;
        k.mv_size = 1;
        k.mv_data = "k";
        v.mv_size = 1;
        v.mv_data = "c";
        rc = mdb_del(txn, dbi, &k, &v);
        printf("del k/c"); rcname(rc); printf("\n");
    }
    doget(txn, dbi, "k");
    {
        MDB_val k;
        k.mv_size = 1;
        k.mv_data = "k";
        rc = mdb_del(txn, dbi, &k, NULL);
        printf("del k all"); rcname(rc); printf("\n");
    }
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* many dups: sub-page -> sub-DB conversion */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 120; i++) {
        snprintf(val, sizeof(val), "dup%03d", i);
        doput(txn, dbi, "many", val, 0);
    }
    for (i = 0; i < 60; i++) {
        snprintf(val, sizeof(val), "dup%03d", i * 2);
        doput(txn, dbi, "even", val, 0);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    {
        MDB_val k, v;
        k.mv_size = 4;
        k.mv_data = "many";
        v.mv_size = 0;
        v.mv_data = NULL;
        rc = mdb_get(txn, dbi, &k, &v);
        printf("get many dsz=%zu\n", (size_t)v.mv_size);
        doget(txn, dbi, "even");
    }
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = st.ms_psize;
    dump_all(&r, st.ms_psize);
    close(r.fd);
    mdb_env_close(env);
}

static void phase_fixed(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    MDB_stat st;
    int rc, i;
    char path[512];
    char file[600];
    char val[64];
    struct reader r;

    snprintf(path, sizeof(path), "%s/fixed", dir);
    mkdir(path, 0777);
    banner("phase dupfixed");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    rc = mdb_dbi_open(txn, NULL, MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, &dbi);
    printf("dbi_open dupfixed"); rcname(rc); printf("\n");
    for (i = 0; i < 8; i++) {
        snprintf(val, sizeof(val), "%04d", (i * 7) % 8);
        doput(txn, dbi, "f", val, 0);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    {
        MDB_val k, v;
        size_t cnt;
        MDB_cursor *mc;
        k.mv_size = 1;
        k.mv_data = "f";
        v.mv_size = 0;
        v.mv_data = NULL;
        rc = mdb_get(txn, dbi, &k, &v);
        printf("get f dsz=%zu\n", (size_t)v.mv_size);
        mdb_cursor_open(txn, dbi, &mc);
        rc = mdb_cursor_get(mc, &k, &v, MDB_FIRST);
        printf("first d="); hex(v.mv_data, v.mv_size); printf("\n");
        rc = mdb_cursor_count(mc, &cnt);
        printf("count=%zu", cnt); rcname(rc); printf("\n");
        mdb_cursor_close(mc);
    }
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = st.ms_psize;
    dump_all(&r, st.ms_psize);
    close(r.fd);
    mdb_env_close(env);
}

static void phase_many(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    MDB_stat st;
    int rc, i;
    char path[512];
    char file[600];
    char key[64];
    char val[64];
    struct reader r;

    snprintf(path, sizeof(path), "%s/many", dir);
    mkdir(path, 0777);
    banner("phase many keys");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);

    for (i = 0; i < 400; i++) {
        snprintf(key, sizeof(key), "k%04d", i);
        snprintf(val, sizeof(val), "v%04d", i);
        doput(txn, dbi, key, val, 0);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u leaf=%" PRIu64 " branch=%" PRIu64
        "\n", (uint64_t)st.ms_entries, (unsigned)st.ms_depth,
        (uint64_t)st.ms_leaf_pages, (uint64_t)st.ms_branch_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 400; i++) {
        snprintf(key, sizeof(key), "r%04d", 399 - i);
        snprintf(val, sizeof(val), "w%04d", 399 - i);
        doput(txn, dbi, key, val, 0);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat entries=%" PRIu64 " depth=%u leaf=%" PRIu64 " branch=%" PRIu64
        "\n", (uint64_t)st.ms_entries, (unsigned)st.ms_depth,
        (uint64_t)st.ms_leaf_pages, (uint64_t)st.ms_branch_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* cursor traversal */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    {
        MDB_cursor *mc;
        MDB_val k, v;
        int n = 0;
        mdb_cursor_open(txn, dbi, &mc);
        rc = mdb_cursor_get(mc, &k, &v, MDB_FIRST);
        while (rc == 0 && n < 500) {
            n++;
            rc = mdb_cursor_get(mc, &k, &v, MDB_NEXT);
        }
        printf("cursor first->next n=%d rc=%d\n", n, rc);
        rc = mdb_cursor_get(mc, &k, &v, MDB_LAST);
        printf("last k="); hex(k.mv_data, k.mv_size);
        printf(" d="); hex(v.mv_data, v.mv_size); printf("\n");
        n = 0;
        rc = mdb_cursor_get(mc, &k, &v, MDB_PREV);
        while (rc == 0 && n < 500) {
            n++;
            rc = mdb_cursor_get(mc, &k, &v, MDB_PREV);
        }
        printf("cursor last->prev n=%d rc=%d\n", n, rc);
        k.mv_size = 5;
        k.mv_data = "k0099";
        rc = mdb_cursor_get(mc, &k, &v, MDB_SET);
        printf("set k0099"); rcname(rc); printf(" d="); hex(v.mv_data, v.mv_size);
        printf("\n");
        k.mv_size = 5;
        k.mv_data = "k0099";
        rc = mdb_cursor_get(mc, &k, &v, MDB_SET_RANGE);
        printf("set_range k0099"); rcname(rc); printf(" k=");
        hex(k.mv_data, k.mv_size); printf("\n");
        k.mv_size = 6;
        k.mv_data = "k9999";
        rc = mdb_cursor_get(mc, &k, &v, MDB_SET_RANGE);
        printf("set_range k9999"); rcname(rc); printf(" k=");
        hex(k.mv_data, k.mv_size); printf("\n");
        k.mv_size = 5;
        k.mv_data = "z9999";
        rc = mdb_cursor_get(mc, &k, &v, MDB_SET_RANGE);
        printf("set_range z9999"); rcname(rc); printf("\n");
        mdb_cursor_close(mc);
    }
    mdb_txn_abort(txn);

    /* deletes: rebalance, node move, page merge, root collapse */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 200; i++) {
        snprintf(key, sizeof(key), "k%04d", i * 2);
        dodel(txn, dbi, key);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat after del entries=%" PRIu64 " depth=%u leaf=%" PRIu64
        " branch=%" PRIu64 "\n", (uint64_t)st.ms_entries, (unsigned)st.ms_depth,
        (uint64_t)st.ms_leaf_pages, (uint64_t)st.ms_branch_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* freeDB reuse: re-insert what we deleted */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 200; i++) {
        snprintf(key, sizeof(key), "k%04d", i * 2);
        snprintf(val, sizeof(val), "nv%04d", i);
        doput(txn, dbi, key, val, 0);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat after reinsert entries=%" PRIu64 " depth=%u leaf=%" PRIu64
        " branch=%" PRIu64 "\n", (uint64_t)st.ms_entries, (unsigned)st.ms_depth,
        (uint64_t)st.ms_leaf_pages, (uint64_t)st.ms_branch_pages);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    /* drain the tree down to nothing: root collapse */
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 800; i++) {
        snprintf(key, sizeof(key), "%c%04d", (i < 400) ? 'k' : 'r', i % 400);
        dodel(txn, dbi, key);
    }
    mdb_stat(txn, dbi, &st);
    printf("stat drained entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    rc = mdb_txn_commit(txn);
    printf("commit"); rcname(rc); printf("\n");

    snprintf(file, sizeof(file), "%s/data.mdb", path);
    r.fd = open(file, O_RDONLY);
    r.psize = st.ms_psize;
    dump_all(&r, st.ms_psize);
    close(r.fd);
    mdb_env_close(env);
}

static void phase_readers(const char *dir)
{
    MDB_env *env;
    MDB_txn *r1, *r2, *w;
    MDB_dbi dbi;
    int rc, i;
    char path[512];
    char key[64];

    snprintf(path, sizeof(path), "%s/readers", dir);
    mkdir(path, 0777);
    banner("phase readers");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &w);
    mdb_dbi_open(w, NULL, 0, &dbi);
    for (i = 0; i < 4; i++) {
        snprintf(key, sizeof(key), "k%d", i);
        doput(w, dbi, key, "v", 0);
    }
    mdb_txn_commit(w);

    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &r1);
    printf("rdonly begin"); rcname(rc); printf("\n");
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &r2);
    printf("rdonly begin2"); rcname(rc); printf("\n");
    if (rc)
        r2 = NULL;   /* a failed handle must not be aborted */

    {
        MDB_val k, v;
        k.mv_size = 1;
        k.mv_data = "k0";
        v.mv_size = 1;
        v.mv_data = "x";
        rc = mdb_put(r1, dbi, &k, &v, 0);
        printf("rdonly put"); rcname(rc); printf("\n");
    }

    {
        /* 0.9.35's mdb_reader_list takes a message callback */
        struct lst_ctx { char buf[8192]; size_t len; } lc;
        lc.len = 0;
        rc = mdb_reader_list(env, lst_append, &lc);
        printf("reader_list"); rcname(rc); printf("\n");
        lc.buf[lc.len] = 0;
        {
            /* The C formats each row `%10d %x %llu` (or `-`); the pid and
             * tid differ per run so both probes replace them with fixed
             * tokens and keep the deterministic txnid column. */
            char *line = strtok(lc.buf, "\n");
            while (line) {
                if (strncmp(line + 4, "pid", 3) != 0) {
                    char *p = line;
                    char *end;
                    strtol(p, &end, 10);
                    p = end + 1;             /* skip pid */
                    strtoull(p, &end, 16);
                    p = end + 1;             /* skip tid */
                    printf("reader pid=<pid> tid=<tid> txnid=%s\n", p);
                } else {
                    printf("%s\n", line);
                }
                line = strtok(NULL, "\n");
            }
        }
    }
    rc = mdb_reader_check(env, &i);
    printf("reader_check dead=%d", i); rcname(rc); printf("\n");

    mdb_txn_abort(r1);
    /* the thread's reader slot is free again: a new read txn succeeds */
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &r2);
    printf("rdonly begin2 again"); rcname(rc); printf("\n");
    if (rc == 0) {
        doget(r2, dbi, "k1");
        mdb_txn_abort(r2);
    }
    mdb_env_close(env);
}

static void phase_copy(const char *dir)
{
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    int rc, i;
    char path[512];
    char key[64];
    char file[600];
    struct reader r;
    MDB_stat st;

    snprintf(path, sizeof(path), "%s/copy", dir);
    mkdir(path, 0777);
    banner("phase copy");
    mdb_env_create(&env);
    mdb_env_open(env, path, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    for (i = 0; i < 100; i++) {
        snprintf(key, sizeof(key), "ck%03d", i);
        doput(txn, dbi, key, "cv", 0);
    }
    mdb_txn_commit(txn);

    /* the copy target is a directory (the env is a subdir env): the file
     * written is <target>/data.mdb */
    snprintf(key, sizeof(key), "%s/copy/cout", dir);
    mkdir(key, 0777);
    rc = mdb_env_copy2(env, key, MDB_CP_COMPACT);
    printf("copy compact"); rcname(rc); printf("\n");
    snprintf(file, sizeof(file), "%s/data.mdb", key);
    {
        struct stat sb;
        stat(file, &sb);
        printf("copy size=%lld\n", (long long)sb.st_size);
    }
    {
        int fd = open(file, O_RDONLY);
        unsigned char hdr[4096];
        pread(fd, hdr, sizeof(hdr), 0);
        r.fd = fd;
        r.psize = rd32(hdr + 16 + 24); /* meta0 mm_dbs[0].md_pad */
        dump_all(&r, r.psize);
        close(fd);
    }
    snprintf(key, sizeof(key), "%s/copy/cout2", dir);
    mkdir(key, 0777);
    rc = mdb_env_copy(env, key);
    printf("copy plain"); rcname(rc); printf("\n");
    snprintf(file, sizeof(file), "%s/data.mdb", key);
    {
        struct stat sb;
        stat(file, &sb);
        printf("copy2 size=%lld\n", (long long)sb.st_size);
    }
    mdb_env_close(env);

    /* reopen the compact copy and validate */
    rc = mdb_env_create(&env);
    mdb_env_open(env, key, 0, 0664);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    mdb_stat(txn, dbi, &st);
    printf("compact stat entries=%" PRIu64 " depth=%u\n", (uint64_t)st.ms_entries,
        (unsigned)st.ms_depth);
    {
        MDB_val k, v;
        k.mv_size = 4;
        k.mv_data = "ck050";
        v.mv_size = 0;
        v.mv_data = NULL;
        rc = mdb_get(txn, dbi, &k, &v);
        printf("compact get ck050"); rcname(rc); printf(" d=");
        hex(v.mv_data, v.mv_size); printf("\n");
    }
    mdb_txn_abort(txn);
    mdb_env_close(env);
}

int main(void)
{
    const char *dir = "/tmp/lmdb_work";

    setbuf(stdout, NULL);
    mkdir(dir, 0777);
    phase_basic(dir);
    phase_named(dir);
    phase_overflow(dir);
    phase_dups(dir);
    phase_fixed(dir);
    phase_many(dir);
    phase_readers(dir);
    phase_copy(dir);
    return 0;
}
