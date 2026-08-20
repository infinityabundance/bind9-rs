# Lore Archive — liburcu 0.15.6 (addendum §30)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.  Court:
LIBURCU-0001 (7 phases, byte-exact in the oracle-liburcu-0.15.6 container)
unless noted.

## LIBURCU-LORE-0001 — BIND's default flavor is membarrier, and its read locks are real nesting counters

`configure.ac --with-liburcu` defaults to `membarrier` (`<urcu.h>` →
`urcu-memb.h`, `-lurcu`).  In that flavor `rcu_read_lock` increments a
per-thread counter (`urcu_reader.ctr`), so `rcu_read_ongoing()` returns
the exact nesting depth (1, 2, 1, 0 in the probe) — it is not an
online/offline flag.  The `isc_qsbr_*` auto-online wrappers in
`isc/urcu.h` compile only under `RCU_QSBR` (the developer-only `qsbr`
flavor, where read locks ARE no-ops and "reading" means online-but-not-
quiesced).

## LIBURCU-LORE-0002 — quiescent_state/thread_online/thread_offline are no-ops in the membarrier flavor

`urcu-memb.h` defines `urcu_memb_quiescent_state`, `urcu_memb_thread_
offline` and `urcu_memb_thread_online` as empty inlines "for API
compatibility" — the QSBR-style quiescent-state reporting does not exist
in the membarrier design.  BIND's `loop.c`/`work.c` calls to
`rcu_thread_offline()`/`rcu_thread_online()` around blocking operations
are therefore no-ops in the default build (they matter only under
`--with-liburcu=qsbr`).  The court asserts the state is untouched.

## LIBURCU-LORE-0003 — a membarrier grace period waits for the *snapshot* readers, and the two passes exist for a reason

`synchronize_rcu` runs `wait_for_readers` twice around the phase toggle
(`urcu.c`): pass 1 moves nested-current readers into `cur_snap_readers`
(and quiescent readers out), then the phase bit flips, then pass 2 waits
only for the snapshot.  A reader that starts *after* the toggle carries
the new phase and does not extend the grace period; a reader that was
quiescent during pass 1 but nests before the toggle is protected by the
release/acquire ordering, not by being waited on.  The mirror's pass 1 is
conservative (it waits until *no* registered thread is nested before
snapshotting) — always safe, and indistinguishable from the C's scan on
the courted sequences.

## LIBURCU-LORE-0004 — the writer goes through the same registry as the readers; an unregistered nested thread still blocks an in-flight grace period

The membarrier `synchronize_rcu` does NOT take the calling thread offline
(that is QSBR-only): it waits for every registered thread, including
itself, so the caller must not be nested.  `rcu_unregister_thread` removes
the thread from the registry but leaves its counter untouched — a writer
that already snapshotted the thread still waits for it to quiesce, while
a *later* grace period never sees it (the probe's phase 4 courts both).

## LIBURCU-LORE-0005 — call_rcu callbacks run FIFO after one grace period per batch

`call_rcu_thread` (urcu-call-rcu-impl.h) splices the whole default queue,
runs one `synchronize_rcu`, then executes the batch in FIFO order.  So
three callbacks queued in a row run 1, 2, 3 in order, each batch exactly
one grace period later.  `rcu_barrier` queues a completion marker behind
everything already submitted and waits for it — which is why the empty
queue still costs one grace period, and why a barrier with no call_rcu
thread ever created (an empty `call_rcu_data_list`) returns immediately.

## LIBURCU-LORE-0006 — register asserts nesting == 0 with an always-on assert

`rcu_register_thread` uses `urcu_posix_assert` (active in the default
build; `urcu_assert_debug` is the compiled-out one) for the
not-registered and not-nested checks.  A thread that unregisters while
nested cannot re-register without tripping the assert in the C — the
mirror uses the same always-on `assert!`.
