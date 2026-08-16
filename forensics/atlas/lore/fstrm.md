# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## FSTRM-LORE-0001 — the reader's max-frame-size failure reports success

`reader.c fstrm__reader_next_data` checks `len > r->max_frame_size` with
`goto fail`, but `res` at that point still holds the `fstrm_res_success`
returned by the length read (`fstrm__reader_read_be32`).  The `fail` label
returns `res`, so `fstrm_reader_read` reports *success* with unspecified
`data`/`len_data` while the reader state becomes `failed` — the next
`fstrm_reader_close` fails.  The Rust mirrors this: the frame-size violation
returns an empty slice (unspecified output) with the state set to `Failed`.
Court: FSTRM-0001.

## FSTRM-LORE-0002 — reads in the closing state fail, not stop

After `fstrm__reader_next_data` returns `fstrm_res_stop` the reader state is
`closing`, not `closed`.  `fstrm_reader_read` only returns `fstrm_res_stop`
for the `closed` state, so a second read after STOP returns `failure` (the
probe prints the closing-state read as failure).  The reader must be closed
explicitly.  Court: FSTRM-0001.

## FSTRM-LORE-0003 — reader and writer double-open asymmetry

`fstrm_writer_open` treats a second open as a success
(`if (state == opened) return success`), while `fstrm_reader_open` treats a
second open as a failure.  The asymmetry is deliberate in the C and is
preserved.  Court: FSTRM-0001.

## FSTRM-LORE-0004 — the iothr_init fail path segfaults in 0.6.1

`fstrm_iothr_init`'s `goto fail` → `fstrm_iothr_destroy` joins the
`pthread_t` and signals/destroys the condvar *before they are initialized*
(the queue-allocation failure happens earlier).  A non-power-of-2
`input_queue_size` therefore segfaults the C library instead of returning
NULL.  The FSTRM-0001 corpus excludes that input; the Rust conserves the
documented contract (NULL return, captive writer destroyed) — the crash is
not reproducible output.  Court: FSTRM-0001.

## FSTRM-LORE-0005 — strtoul base-0 port parsing quirks

`tcp_writer.c fstrm__tcp_writer_fill_socket_port` uses
`strtoul(port, &endptr, 0)` and accepts the value iff `*endptr == '\0'` and
`port <= UINT16_MAX`.  Consequences the court pins: the empty string is a
valid port 0 (no digits consumed, endptr at the terminating NUL); `"-1"`
wraps to ULONG_MAX and fails the `> 65535` check; `"0x1F90"` is hex 8080;
`"010"` is octal 8; `" 8080"` skips leading whitespace; `"8080junk"` has
trailing garbage and fails; a `"0x"` prefix with no following hex digit
consumes only the `0` (octal), leaving the `x` as trailing garbage.  The
Rust `strtoul_base0` transcribes these (glibc saturates to ULONG_MAX on
overflow and keeps consuming digits).  Court: FSTRM-0001.

## FSTRM-LORE-0006 — inet_pton strictness in the tcp writer address

`fstrm__tcp_writer_fill_socket_address` tries `inet_pton(AF_INET)` first,
then `AF_INET6`.  glibc `inet_pton` rejects leading-zero octets
(`"010.0.0.1"`), non-decimal octets, octets above 255, hostnames, and
port-suffixed forms; the IPv6 form allows one `::` compression and an
embedded IPv4 tail but no zone ids.  The Rust mirrors this exactly, since
the init success/failure surface is observable.  Court: FSTRM-0001.

## FSTRM-LORE-0007 — iothr input queue handles are one-shot

`fstrm_iothr_get_input_queue` returns a *unique* queue per call (round-robin
index guarded by a mutex) up to `num_input_queues`, then NULL.  Callers must
hold the handle; re-fetching after exhaustion yields NULL.  The court pins
the exhaustion and the `get_input_queue_idx` bounds.  Court: FSTRM-0001.

## FSTRM-LORE-0008 — content types are length-based, not string-based

`fstrm_writer_options_add_content_type`/`fstrm_control_add_field_content_type`
copy `len` bytes; embedded NULs are legal (the upstream test corpus uses
`"wharr\x00garbl"`).  The control codec's match rule is byte-exact length +
memcmp over the *clamped* field count — a frame with no content-type fields
matches any requested type (this is what lets a reader with no configured
types accept anything, and what makes the empty ACCEPT reply complete the
bidirectional handshake), while STOP/FINISH never match.  Court: FSTRM-0001.

## FSTRM-LORE-0009 — the writer's Failed state is never assigned

The C `fstrm_writer_state` enum includes `failed` (writer.c:33) but no
writer path assigns it (only the reader fails).  The Rust keeps the variant
for structural fidelity with an `allow(dead_code)`.  Court: FSTRM-0001.

## FSTRM-LORE-0010 — SIGPIPE handling is intentionally not transcribed

The C I/O thread blocks SIGPIPE for its lifetime
(`fstrm__iothr_thr_setup`) so a write to a peer-closed socket fails instead
of killing the process; Rust cannot set a per-thread signal mask without
`unsafe`, which the tools crate forbids.  The FSTRM-0001 corpus never writes
to a peer-closed socket (the handshake completes before either side closes),
so the divergence is unobservable in the conservation surface.
