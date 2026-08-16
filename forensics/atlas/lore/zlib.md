# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## ZLIB-LORE-0001 — `opt_len`/`static_len` accumulate with unsigned wraparound

`trees.c build_tree` guarantees "at least two codes of non zero frequency" by
inventing fake leaf nodes and doing `s->opt_len--` / `s->static_len -= len`
on a field that is still 0.  In the C these are unsigned long fields, so the
decrements wrap to near ULONG_MAX and `gen_bitlen`'s subsequent additions
wrap back to the true block cost.  The Rust mirrors the C's `ulg` fields with
`u64` and must use `wrapping_add`/`wrapping_sub` in the same places;
`debug` builds panic on the first tiny input otherwise.  The empty-block cost
(`opt_len == 1`) is only correct because of this wrap.  Court: ZLIB-0001.

## ZLIB-LORE-0002 — the "inconsistent bit counts" Assert is compiled out

`gen_codes` ends with `Assert(code + bl_count[MAX_BITS] - 1 == (1 << MAX_BITS)
- 1, "inconsistent bit counts")`.  For streams with fewer than three symbols
the forced-two-codes hack makes the length distribution violate Kraft
equality, so the assert would fire on every tiny input.  The default build
compiles with no `DEBUG`, so `Assert` is empty and the check never runs; the
C still emits a valid stream because the code is sent (dynamic blocks) or the
standard table is used (fixed blocks).  The Rust has no runtime check.

## ZLIB-LORE-0003 — `deflate`'s status persists across calls

The C's `s->status` moves INIT_STATE → BUSY_STATE → FINISH_STATE and persists
between `deflate` calls; the gzip header is written exactly once.  The Rust
must therefore not overwrite the pulled-out state's status with the entry
snapshot on return (an early transcription bug re-emitted the gzip header and
trailer on every Z_FINISH call, producing an infinite `gz_comp` loop).

## ZLIB-LORE-0004 — the gz layer models the C's next_in/next_out pointers

`gzlib.c`/`gzread.c`/`gzwrite.c` track the consumed/produced positions through
`strm->next_in`/`strm->next_out` advancing inside `inflate`/`deflate`.  The
Rust mirrors those pointers with `ZStream.next_in_pos`/`next_out_pos`, which
`inflate_call_internal`/`deflate_call_internal` must advance by the per-call
consumed/produced counts (`io.in_pos`/`io.out_pos`).  A missing advance made
the gz read and write paths resend/redecode the same input forever or drop
all output.  Note the inflate CHECK state resets its produced tracker
(`out = left`), so the output cursor must advance by the full `put`, not by
the post-check `produced`.

## ZLIB-LORE-0005 — zero-length stored blocks are sync markers, not dead ends

`deflate` emits an empty stored block (`LEN=0`, `NLEN=0xffff`) on
Z_SYNC_FLUSH/Z_FULL_FLUSH.  `inflate`'s COPY state must treat a stored block
whose length is already zero as "stored end" and move to TYPE (the C's
`if (copy) { ... } else { state->mode = TYPE; }`); treating it as
"no progress" (`goto inf_leave`) stalls the decoder on every synced stream.
`inflateSync` relies on these markers.

## ZLIB-LORE-0006 — overlapping matches need sequential byte copies

The fast match copy reads three bytes per iteration.  For distances smaller
than the copy width the source overlaps the destination, so the reads must be
interleaved with the writes (`*put++ = *from++` in the C); reading the three
bytes up front reproduces stale data and corrupts long runs (e.g. a `dist=1`
space run decodes as NULs).  The Rust copies byte-by-byte for output-sourced
matches.

## ZLIB-LORE-0007 — gz_look checks the input cursor, not the buffer start

`gz_look` detects the gzip magic by reading `strm->next_in[0..1]` — the
unconsumed cursor, not `state->in[0]`.  After a member ends with leftover
input (gzip streams leave the ISIZE unread when `FLG == 0`), checking the
buffer start re-detects the stale magic and re-decodes the stream; checking
the cursor sees the leftover bytes as trailing garbage and finishes.

## ZLIB-LORE-0008 — `deflateParams` flushes into the caller's buffer

`deflateParams` calls `deflate(strm, Z_BLOCK)` internally and the flushed
block lands at the caller's `next_out`, advancing `total_out`.  The Rust API
passes buffers per call and has no caller buffer during the params call, so
the flushed bytes are stashed in `DeflateState.params_flush` and emitted at
the start of the next `deflate` call; `total_out` is restored so the caller
slices that call at the pre-flush position and the stream stays contiguous.

## ZLIB-LORE-0009 — the gzip FLG field is the high byte of the 16-bit flags

`inflate`'s FLAGS state reads 16 bits: `flags = CM | (FLG << 8)`.  `flags != 0`
is therefore true for every gzip stream (CM == 8), which selects the raw
(little-endian) CRC comparison in CHECK and enables the LENGTH (ISIZE)
comparison — and leaves the 4 ISIZE bytes unconsumed when FLG == 0, which is
what makes ZLIB-LORE-0007's cursor handling necessary.

## ZLIB-LORE-0010 — `inflateCopy` carries the active code tables

The C's `lencode`/`distcode` are pointers *into* the `codes` workspace.  The
Rust stores them as separate slices; a copy that rebuilds them from the whole
`codes` Vec produces garbage tables and mid-stream copies decode corrupt
data.  The copy must carry the source's active `lencode`/`distcode` slices.

## ZLIB-LORE-0011 — inflate tolerates `avail_out == 0` calls

`uncompress2` with a destination too small drives `inflate` with a zero-length
output window and relies on it returning Z_BUF_ERROR only when *no progress*
was made (the `(in == 0 && out == 0) || flush == Z_FINISH` check in
`inf_leave`).  Rejecting empty output slices up front turns the documented
Z_BUF_ERROR ("not enough room in the output buffer") into Z_STREAM_ERROR.

## ZLIB-LORE-0012 — `gzprintf` delegates to vsnprintf

`gzvprintf` formats with the platform's `vsnprintf` and feeds the bytes into
the gzip stream.  The Rust implements a glibc-compatible printf subset
(d/i/u/o/x/X with flags/width/precision and hh/h/l/ll/z/t lengths, s, c, p,
%, f/e/g with glibc rounding and the `#`/`0` interactions, `*` width and
precision).  The ZLIB-0001 gzprintf battery pins the formats BIND-adjacent
code actually uses; unknown conversions pass through literally like glibc.

## ZLIB-LORE-0013 — the gzip trailer is read byte-aligned after BYTEBITS

The final block's EOB is aligned to a byte boundary (`BYTEBITS`) before the
CRC/ISIZE are read, so the stored CRC compares against `hold` in
little-endian order (no ZSWAP32 for gzip).  The ISIZE check runs only when
`flags != 0` — which, per ZLIB-LORE-0009, is always true for gzip — and
compares against `state->total` (the output count since the header).

## ZLIB-LORE-0014 — gz buffers: read path uses `want << 1` output, double-size input

`gz_look` allocates `in` of `want` bytes and `out` of `want << 1`; the input
buffer is double-sized (2x `want`) only on the *write* side (allocated by
`gz_init`, "double size for gzprintf").  `gzbuffer` may only be called before
the first read (or write), so a fresh `gzopen` + `gzbuffer` resizes `want`
before any I/O.
