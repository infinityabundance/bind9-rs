# Lore Archive — the BIND 9.20.26 netmgr (`lib/isc/netmgr`, addendum §30)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.  Court:
NETMGR-0001 (13 phases, byte-exact in the oracle-bind-9.20.26 container)
unless noted.

## NETMGR-LORE-0001 — the accept_cb runs BEFORE the connect_cb, and the probe's pair-print chain depends on it

On loopback the listener's accept-ready (POLLIN) precedes the client's
connect-complete (POLLOUT) in the kernel's ready list: the SYN arrives at
the server before the SYN-ACK returns to the client.  libuv's
`uv__io_poll` iterates the epoll events in that ready order, so the
accept callback fires before the connect callback.  The probe records
both and prints them from a chained loop-0 job in a fixed documented
order (connect first, then accept) — and the pair-print chain is driven
ONLY from the connect cb (`if (rec_conn_ready && rec_acc_ready)`), so a
connect-before-accept dispatch deadlocks the phase silently: the connect
cb sees `acc=false`, nobody chains the pair, and the server read timer
fires.  The mirror's poll() cannot see the kernel order, but the pollfd
array is built in handle-registration order and the listener always
precedes its clients, so a single dispatch pass in array order
reproduces the kernel order deterministically.

## NETMGR-LORE-0002 — the poll round dispatches per-fd in array order, read before write

Real `uv__io_poll` calls `uv__io_cb` per event immediately; each
watcher's callback then handles its full event set in a fixed order:
`uv__udp_io` does POLLIN (recv) then POLLOUT (send); `uv__stream_io`
runs a pending connect first (`uv__stream_connect` returns immediately),
then reads, then writes.  The mirror's original two-pass dispatch (all
POLLOUT, then all POLLIN) processed the connect completion before the
accept on the same round — the reverse of the kernel — which stalled the
netmgr court at phase 8 (see NETMGR-LORE-0001).  The fix is a single
pass over the pollfd array in order, each fd's events dispatched in
libuv's per-watcher order.  poll(2) reports revents in array order, so
the only order poll() can preserve is registration order — which is the
order the court's deterministic transcript depends on.

## NETMGR-LORE-0003 — the write-timeout timer holds a handle ref released only at its uv_close

`tcp_send_direct` (tcp.c) creates a per-write timeout timer with
`isc_nm_timer_create(req->handle, ...)`, which does
`isc_nmhandle_attach(handle, &timer->handle)` — an extra handle ref.
`tcp_send_cb` calls `isc_nm_timer_detach(&uvreq->timer)`, but the
decrement is on the *timer's* refcount; the handle detach happens in the
`timer_destroy` uv_close callback, on a later loop iteration.  So the
user send cb observes `handle refs=4` (statichandle-keep + probe send
handle + send req + timer) for the 131072-byte echo, vs 3 for the small
sends.  The mirror reproduces the ref with a per-pending-uv_write count
(`pending_write_timers`) released after the send cb, and on close for
any write the close cancelled.

## NETMGR-LORE-0004 — `statichandle` is ASSIGNED, not attached

`isc___nmhandle_get` (netmgr.c) sets `sock->statichandle = handle`
directly, with the comment "statichandle must be assigned, not attached;
otherwise, if a handle was detached elsewhere it could never reach 0
references, and the handle and socket would never be freed."  The
connect cb's `handle refs=1 (entry)` is therefore the connect req's own
ref only; the probe's attach then takes it to 2.  The mirror assigns the
field the same way (no ref).

## NETMGR-LORE-0005 — the accept callback is a pointer copy, shared by every child, never consumed

`start_tcp_child` copies the parent listener's accept_cb to each child
(`csock->accept_cb = sock->accept_cb`), and `isc__nm_acceptcb` reads it
from the accepted socket's server chain.  The callback is never
consumed by an accept — the mirror's original take-from-the-listener
design fired it once and left every later accept callbackless (the
phase-8b stall).  A `Box<dyn FnMut>` cannot be copied, so the mirror
shares the listener's cb as `Arc<Mutex<AcceptCb>>`: each child job holds
a clone of the same Arc, and `accept_connection` locks, calls, unlocks.
The same sharing applies to the UDP `recv_cb` (the server's recv_cb is
permanent — `udp_recv_event` restores it after every datagram).

## NETMGR-LORE-0006 — children count refs against the parent through a shared atomic

The rsock rule (`isc___nmsocket_attach`): every attach of a child socket
or its handles increments the PARENT's refcount, and the parent's
refcount reaching zero drives `nmsocket_prep_destroy` — but the parent
object is shared heap memory in the C (the child's `sock->parent` is a
pointer into loop 0's tree), while the mirror keeps per-loop `Vec`s of
sockets.  A child running on loop 1 cannot index loop 0's Vec.  The
mirror therefore gives the listener tree a shared refcount cell
(`shared_refs: Arc<AtomicU32>`), created at listen, copied into every
child job, and used by `rsock_attach`/`rsock_detach`/`rsock_refs`.
When the last ref drops on a child loop, the parent's destroy is
dispatched to loop 0 (the listeners assert `isc_tid() == 0`, so the
parent always lives there).  The probe's `sock refs` prints read the
socket's OWN field (a listener child's stays 1 — its attaches all go to
the parent).

## NETMGR-LORE-0007 — `SO_REUSEADDR` unconditionally, `SO_REUSEPORT` for load-balance listeners

`uv__tcp_bind` (libuv tcp.c) sets `SO_REUSEADDR` unconditionally before
`bind`; without it a listener restart after a TIME_WAIT close races
EADDRINUSE (the intermittent `listentcp -> unset` flake).  BIND's own
socket setup (`isc__nm_tcp_lb_socket`/`isc__nm_udp_lb_socket`) sets
SO_REUSEADDR on the raw fd and adds SO_REUSEPORT when
`load_balance_sockets` is on (Linux's `isc__nm_socket_reuse_lb`) so the
nloops children can bind the same address.  The mirror applies both at
the same places: `uv_tcp_bind` for every TCP bind, and the sockopts on
the child fds in `tcp_child_open`/`udp_child_open` when
`nm.load_balance` (the probe prints `getloadbalancesockets=true`).

## NETMGR-LORE-0008 — `isc_refcount_decrement` returns the PRE-decrement value

The C's `isc_refcount_decrement(&refs) == 1` fires the destruction path
only when the count was 1 (1→0), not at 2→1.  A mirror that fires at
`refs == 1` *after* decrementing detaches one reference early — the
socket and handle die under a live callback.  This was root-caused with
a patched oracle probe printing the raw counter at every decrement.

## NETMGR-LORE-0009 — the configured socket buffers force the big writes through uv_write

`setnetbuffers(1024,2048,4096,8192)` stores per-type SO_RCVBUF/SO_SNDBUF;
`isc__nm_set_network_buffers` applies them to every client/listener
socket (NOT to accepted sockets).  The 131072-byte court sends therefore
partial on `uv_try_write` — the client's SO_SNDBUF is 2048, and the
server's echo throttles on the client's tiny receive window — so both
sends take the `uv_write` path and the probe observes the write-timer
handle ref (NETMGR-LORE-0003).  The mirror applied the buffers at the
same four open sites; without them the whole 131072 fits the default
212992-byte loopback buffer and the write completes immediately
(`refs=3`, transcript mismatch).

## NETMGR-LORE-0010 — `uv_write` queues only the remainder; the drain advances a write index

libuv's `uv__write` tracks progress (`req->write_index`); a partial
write advances the index and the remainder goes out on the next POLLOUT.
The mirror's original drain requeued the WHOLE request on a partial
write, so with the 2048-byte SO_SNDBUF the client resent its first 2048
bytes forever — the server's accumulated byte counter crossed 131072
again and again ("received full message" ×96, then a hang).  `uv_write`
now writes the head immediately (preserving LIBUV-0001's
"queue size after uv_write=0 (immediate write path)") and queues only
the unwritten remainder; the drain rebuilds the remainder after each
partial write and `write_queue_size` tracks the remaining bytes.  The
netmgr's `tcp_send_direct` additionally passes only the post-`uv_try_write`
remainder to `uv_write`, so no byte is ever written twice.

## NETMGR-LORE-0011 — the UDP connect req owns the handle from `isc__nmhandle_get` (no attach)

`isc_nm_udpconnect` does `req->handle = isc__nmhandle_get(sock, &peer,
&iface)` — the handle's initial refs=1 IS the connect req's ref; there is
no separate attach (the mirror's original double-count printed refs=2
at the connect cb entry).  The read req (`isc__nm_get_read_req`) is the
opposite: `isc_nmhandle_attach(statichandle, &req->handle)`, and the
attached ref is released by `isc__nm_uvreq_put` after the recv cb — so
a UDP client's read req is refcount-neutral across reads and must not
be made observable (the mirror keeps reads refcount-neutral; the server
side's datagram handle is fresh per event).

## NETMGR-LORE-0012 — the connect-completion status is the kernel's SO_ERROR

`uv__stream_connect` reads `getsockopt(SO_ERROR)`; EINPROGRESS keeps the
request pending, anything else (ECONNREFUSED on a closed loopback port)
becomes the connect_cb status.  The mirror's `tcp_poll_out` does the
same and feeds the status through the pending pass (`tcp_run_completed`).
The result code must map the real Linux errno (ECONNREFUSED = 111), not a
hard-coded -12: the mirror's original `-12 => ConnRefused` mapping made
phase 10 print `unset`.
