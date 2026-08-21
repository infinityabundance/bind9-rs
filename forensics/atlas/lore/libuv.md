# Lore Archive — libuv 1.52.1 (addendum §30)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.  Court:
LIBUV-0001 (18 phases, byte-exact in the oracle-libuv-1.52.1 container)
unless noted.

## LIBUV-LORE-0001 — the timer heap orders by (timeout, start_id), and the probe fires same-timeout timers in start order

`timer.c timer_less_than` compares `timeout` first, then `start_id`
(the per-loop `timer_counter`).  Two timers started with the same timeout
in the same iteration fire in start order; `uv__run_timers` pops *all*
due timers into a ready queue in heap order before firing any of them.
The Rust mirrors the heap with a `BinaryHeap` (a max-heap) over the
reversed comparison.

## LIBUV-LORE-0002 — `uv_timer_again` re-arms repeat timers BEFORE the callback

`uv__run_timers` calls `uv_timer_again(handle)` then `handle->timer_cb`.
For a repeat timer the re-arm computes `timeout = loop->time + repeat`
from the *current* loop time, so the repeat fires at
T+10/T+20/T+30/T+40 with a 10 ms repeat, not T+10/T+20/T+40/T+80
(no doubling).  The callback also stays set after firing: `uv_timer_again`
on a one-shot with `repeat == 0` is a no-op that leaves `timer_cb`
installed (the mirror must restore the callback after firing it).

## LIBUV-LORE-0003 — idle runs BEFORE prepare in 1.52.1 (and always before check)

`uv_run`'s iteration is pending → idle → prepare → poll → pending(≤8) →
check → closing → timers.  The probe courts the exact print order
`idle`, `prepare`, `check` in one iteration, with the check callback
stopping all three so a run cannot spin on the zero poll timeout that
active idle handles force.  One idle callback fires per NOWAIT
iteration because the watcher is re-inserted at the tail of its list
before its callback runs.

## LIBUV-LORE-0004 — the send-before-receive round boundary is a poll() snapshot artifact

libuv's linux backend uses edge-triggered epoll; datagrams written during
a round are only *seen* by the receiving socket in a later round.  The
mirror uses `poll`, which computes readiness once per round and dispatches
only that snapshot — data written during the dispatch loop cannot mark a
receiver ready in the same round.  The probe relies on this: the UDP
`send_cb`s fire in the pending pass of the round that writes them
(`queue=600` then `queue=0`), the `recv_cb`s in later rounds, in
datagram order (`ping`, `abcd`, 600 x's, `pong`).

The mirror dispatches the round in a single pass over the pollfd array in
array order, each fd's full event set in libuv's per-watcher order
(uv__udp_io/uv__stream_io: read first, then write; a pending connect
consumes the round) — see NETMGR-LORE-0002 for why the old
"writables-then-readables" two-pass dispatch reversed the kernel's ready
order and broke the netmgr court's connect/accept pair.

## LIBUV-LORE-0005 — the EAGAIN drain marker is recv_cb(0, NULL)

`uv__udp_recvmsg` allocates a buffer, `recvmsg`s, and on
EAGAIN/EWOULDBLOCK fires `recv_cb(handle, 0, &buf, NULL, 0)` — nread 0
with a NULL peer address means "the socket buffer is exhausted", not "a
zero-length datagram".  The only recv callback that ever sees
`addr == NULL` is this drain marker.  The alloc suggestion is the fixed
`UV__UDP_DGRAM_MAXSIZE = 64 * 1024`.

## LIBUV-LORE-0006 — the loop-init allocator counts: one calloc + one realloc, and two frees at close

With `uv_replace_allocator` customs installed, `uv_loop_init` calls
`calloc(1, sizeof(*lfields))` (the loop internal fields, loop.c) and one
`realloc(NULL, n)` — the watchers-array growth from registering the
internal `wq_async` watcher (core.c `maybe_resize`).  The io_uring
control block is *mmap*'d (`uv__iou_init`, linux.c), never malloc'd.
`uv_loop_close` frees the watchers array then the internal fields —
exactly two frees.  The probe asserts calloc=1 realloc=1 free=0 after
init and free=2 after close.

## LIBUV-LORE-0007 — `uv_dlerror` is the captured glibc message, or the literal "no error"

`uv__dlerror` reads glibc's `dlerror()` exactly once, strdups it into
`lib->errmsg`, and returns -1; `uv_dlopen`/`uv_dlsym` fail with -1 and
the message lives in the lib.  A successful call clears errmsg, so
`uv_dlerror` then returns the literal `"no error"` (not "unknown error").
The exact glibc texts (`/lib/.../libc.so.6: undefined symbol: getpid_bogus`,
`/nonexistent/lib.so: cannot open shared object file: No such file or
directory`) are container-pinned: the court runs both probes in the same
oracle image, where the paths exist.

## LIBUV-LORE-0008 — `uv_version` is `(major<<16)|(minor<<8)|patch`, not a 24-bit major

`version.h UV_VERSION_HEX` packs `1.52.1` as `0x00013401 = 78849`
(`(1<<16)|(52<<8)|1`).  A `(major<<24)|(minor<<16)|(patch<<8)` reading of
the header prints 20185344 and fails the byte-exact version check.

## LIBUV-LORE-0009 — `uv_loop_close` is EBUSY for every never-closed handle, active or not

The 1.52.1 check iterates the *handle queue* and rejects any non-internal
handle that was ever initialized and not closed — even long-fired,
inactive timers.  The probe's final `uv_loop_close(loop2)` is therefore
EBUSY (-16) even though nothing is active; a loop whose handles were all
closed closes clean.  `uv__finish_close` also clears the CLOSING flag
before the close_cb fires and drops the handle from the queue (uv_walk
stops seeing it).

## LIBUV-LORE-0010 — refused connects arrive as a delayed error through the pending pass

On Linux `uv__tcp_connect` maps an immediate ECONNREFUSED to
`delayed_error` and `uv__io_feed`s the stream; the connect_cb fires from
the next pending pass with the error.  EINPROGRESS completes via
POLLOUT + `getsockopt(SO_ERROR)`, and a still-EINPROGRESS SO_ERROR keeps
the request pending.  The probe's port-1 connect prints
`cli2 connect_cb status=ECONNREFUSED` either way.

## LIBUV-LORE-0011 — `uv_random` goes through the threadpool even for tiny buffers

`uv_random` with a non-NULL callback always `uv__work_submit`s
(UV__WORK_CPU), so the completion fires during a later `uv_run` — never
synchronously — even for a 16-byte buffer.  The mirror's helper thread
fills via `getrandom`, hands back `(len, status)`, and wakes the loop
through the eventfd; the completion callback itself stays on the loop
side (the callback type is not `Send`).

## LIBUV-LORE-0012 — `uv_write`'s immediate path completes via the pending pass, queue stays 0

On a fresh loopback connection a small `uv_write` succeeds immediately;
the request is *still* completed through the pending queue
(`uv__write_req_finish` + `uv__io_feed`), so the write_cb fires in the
next run's first pending pass while `uv_stream_get_write_queue_size`
stays 0.  `uv_try_write` on the same socket then writes synchronously
and returns the byte count; both paths courted by the probe's
`ping`/`pingping` sequence.

## LIBUV-LORE-0013 — the barrier's serial-thread return is 1 for the last releaser

glibc's `pthread_barrier_wait` returns `PTHREAD_BARRIER_SERIAL_THREAD`
(1) for exactly the thread that releases the last waiter, 0 for the
others.  `uv_barrier_wait` forwards that.  `uv_barrier_init` with count 0
is EINVAL; the glibc path has no NULL guard, so the NULL case is not
portable and is not courted.
