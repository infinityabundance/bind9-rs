# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## LMDB-LORE-0001 — `MDB_node` is a 4×u16 header, and node sizes are EVEN

The on-disk `MDB_node` header is `mn_lo`/`mn_hi`/`mn_flags`/`mn_ksize`, four
`unsigned short`s (8 bytes) — not 12 — so `NODESIZE` is 8 and a leaf node
for a 4-byte key + 6-byte value occupies `EVEN(8+4+6) = 18` bytes
(`mdb_node_add` applies `EVEN` *without* the 2-byte pointer slot; the room
check subtracts the slot separately).  `mdb_leaf_size`/`mdb_branch_size`
*do* fold the pointer slot into `EVEN(sz + 2)` for split sizing.  Getting
this wrong shifts every page's `mp_upper` and cascades into split points,
so the whole tree layout diverges.  Court: LMDB-0001.

## LMDB-LORE-0002 — the freeDB is lazy: `me_pghead` per txn, records loaded on demand

`env->me_pghead` is per-transaction state: NULL at txn begin, allocated by
the first freeDB-record load (`mdb_page_alloc`'s fetch loop) or dirty
overflow-page release, reset at txn end (`mdb_txn_end`).  `mdb_page_alloc`
fetches freeDB records one at a time — from `me_pglast+1` onward, stopping
at the first record whose txnid is >= the oldest reader's txnid ("too
recent" — its pages may still be visible to a reader).  The freed-pgno
IDLs therefore become reusable only in the *next* txn that allocates, and a
record is deleted from the freeDB only once its pages are in `me_pghead`.
The txn's own frees (`mt_free_pgs`) are written as the txnid-keyed freeDB
record at commit — before any of them can be reused.  Court: LMDB-0001.

## LMDB-LORE-0003 — the freelist_save reserve/fill-in writes me_pghead back into the freeDB

At commit, `freelist_save` first deletes the freeDB records whose pages are
already loaded in `me_pghead`, writes the txn's own frees as a new
txnid-keyed record, then *reserves* records for the remaining `me_pghead`
content (keys `head_id`, decrementing) and fills them in with `MDB_CURRENT`
writes.  The reserved record sizes (`(head_room+1)*8`) determine the
fill-in's capacity.  The net effect is that pages freed several txns ago
stay recorded in the freeDB (visible to `mdb_env_copy`) until they are
actually reused.  Court: LMDB-0001.

## LMDB-LORE-0004 — the freeDB IDLs are stored descending; me_pghead pops the smallest first

`mdb_midl_sort` sorts descending, so every freeDB record's data is
`[count, pgs...]` with the page numbers descending.  `mdb_midl_xmerge`
merges a descending IDL into the descending `me_pghead`; `mdb_page_alloc`
searches from the tail, so the *smallest* free pages are reused first
(matching the C exactly — the opposite would renumber every reuse).  The
record's `[count]` word must not be mistaken for a page number when
loading it back.  Court: LMDB-0001.

## LMDB-LORE-0005 — reader slots are thread-bound (TLS): a second read txn in the thread is BAD_RSLOT

`mdb_txn_begin(MDB_RDONLY)` claims one reader slot per thread via
`pthread_getspecific`; while a read txn is active, `mr_txnid != -1`, so a
second `mdb_txn_begin(MDB_RDONLY)` in the same thread returns
`MDB_BAD_RSLOT`.  Only after the txn ends (`mr_txnid = -1`) can the slot be
reused.  The Rust mirrors this with `EnvCore.reader_slot`; the probe's
second read-only begin fails with `-30783` and the reader list shows one
row.  Court: LMDB-0001.

## LMDB-LORE-0006 — overflow-page overwrites: clean blocks are freed and re-added, dirty ones written in place

`mdb_cursor_put` on an existing `F_BIGDATA` node only overwrites the
overflow block in place when the block is already `P_DIRTY` in the current
txn (allocated by an earlier put) *and* large enough; a clean block — even
for a same-size overwrite — is freed (`mdb_ovpage_free` → `mt_free_pgs`)
and the node is deleted and re-added, COW-ing the block through
`page_alloc`.  The C also never shrinks an in-place overwritten block.  A
dirty block that is freed (too small) is removed from the dirty list and
released to `me_pghead`.  Court: LMDB-0001.

## LMDB-LORE-0007 — `mdb_env_copy2(MDB_CP_COMPACT)` renumbers pages; the fresh copy carries txnid 0/1

The compacting copy walks the reachable tree and writes the pages in
breadth-first order, renumbering them contiguously (leaves before branches,
overflow blocks after their node), then writes a fresh meta0 (empty, txnid
0) and meta1 (txnid 1) so the copy opens as a brand-new database.  The
plain `mdb_env_copy` copies the file verbatim.  Court: LMDB-0001.
