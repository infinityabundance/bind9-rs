/*
 * probe-liburcu.c — the liburcu 0.15.6 oracle probe (court LIBURCU-0001).
 *
 * A deterministic op sequence over the userspace-RCU surface BIND 9.20's
 * netmgr/isc depends on (the membarrier flavor, `-lurcu`, `<urcu.h>` —
 * BIND's default `--with-liburcu=membarrier` build).
 *
 * Transcript determinism contract (the Rust mirror must reproduce the
 * stdout byte-for-byte in the SAME oracle-liburcu-0.15.6 container):
 *  - only logical events and read-side nesting counts are printed; never
 *    wall-clock values, addresses, pointers, pids or thread ids;
 *  - the read-side state machine is single-threaded and prints the exact
 *    rcu_read_ongoing() nesting values (1, 2, 1, 0 — the membarrier
 *    counter, not a QSBR online/offline flag);
 *  - the grace-period phases are structured so the print ORDER is
 *    guaranteed: the writer thread's synchronize_rcu() cannot complete
 *    while the snapshot reader is nested (the two-pass membarrier grace
 *    period waits for it), so "sync blocked (reader nested)" always
 *    precedes "sync completed after reader unlock";
 *  - helper threads print nothing; the main thread joins them and prints
 *    the recorded results, so the transcript order is fixed;
 *  - call_rcu callbacks fire FIFO on the call_rcu thread after a grace
 *    period, and rcu_barrier() returns only after every previously queued
 *    callback ran — both sides print the same interleaving;
 *  - rcu_quiescent_state/rcu_thread_online/rcu_thread_offline are no-ops
 *    in the membarrier flavor and are courted as such.
 */

#include <urcu.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* phase 3/4: the reader helper + the sync writer                      */
/* ------------------------------------------------------------------ */

struct sync_ctx {
	volatile int *reader_active;   /* helper took its read lock       */
	volatile int *release_reader;  /* main tells the helper to unlock  */
	volatile int *sync_done;       /* the writer finished the GP       */
};

static void *reader_helper(void *arg) {
	struct sync_ctx *c = (struct sync_ctx *) arg;

	rcu_register_thread();
	rcu_read_lock();
	*c->reader_active = 1;
	while (!*c->release_reader) {
		/* spin: hold the read lock until released */
	}
	rcu_read_unlock();
	rcu_unregister_thread();
	return NULL;
}

static void *sync_writer(void *arg) {
	struct sync_ctx *c = (struct sync_ctx *) arg;

	rcu_register_thread();
	synchronize_rcu();
	*c->sync_done = 1;
	rcu_unregister_thread();
	return NULL;
}

/* ------------------------------------------------------------------ */
/* phase 4: unregister-while-nested helper                             */
/* ------------------------------------------------------------------ */

struct unreg_ctx {
	volatile int *reader_active;
	volatile int *release_reader;
	volatile int *sync_done;
	volatile int *unreg_done;   /* helper finished unlock+unregister */
};

static void *unreg_helper(void *arg) {
	struct unreg_ctx *c = (struct unreg_ctx *) arg;

	rcu_register_thread();
	rcu_read_lock();
	*c->reader_active = 1;
	while (!*c->release_reader) {
		/* spin */
	}
	rcu_read_unlock();
	rcu_unregister_thread();
	*c->unreg_done = 1;
	return NULL;
}

/* ------------------------------------------------------------------ */
/* phase 5: call_rcu                                                   */
/* ------------------------------------------------------------------ */

struct cb_item {
	struct rcu_head head;
	int id;
};

static void cb_run(struct rcu_head *h) {
	struct cb_item *it = caa_container_of(h, struct cb_item, head);
	printf("    call_rcu cb %d\n", it->id);
}

static struct cb_item c1, c2, c3, c4;

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
	volatile int reader_active = 0;
	volatile int release_reader = 0;
	volatile int sync_done = 0;
	struct sync_ctx sc;
	pthread_t helper, writer;
	int *val;
	static int target = 42;
	int *pub = NULL;

	printf("=== PHASE 0: thread registration ===\n");
	printf("  rcu_read_ongoing before register=%d\n", rcu_read_ongoing());
	rcu_register_thread();
	printf("  rcu_register_thread -> ok\n");
	printf("  rcu_read_ongoing after register=%d\n", rcu_read_ongoing());

	printf("=== PHASE 1: read-side nesting ===\n");
	rcu_read_lock();
	printf("  rcu_read_lock -> ongoing=%d\n", rcu_read_ongoing());
	rcu_read_lock();
	printf("  rcu_read_lock -> ongoing=%d\n", rcu_read_ongoing());
	rcu_read_unlock();
	printf("  rcu_read_unlock -> ongoing=%d\n", rcu_read_ongoing());
	rcu_read_unlock();
	printf("  rcu_read_unlock -> ongoing=%d\n", rcu_read_ongoing());
	rcu_quiescent_state();
	printf("  rcu_quiescent_state (membar no-op) -> ongoing=%d\n",
	       rcu_read_ongoing());
	rcu_thread_offline();
	printf("  rcu_thread_offline (membar no-op) -> ongoing=%d\n",
	       rcu_read_ongoing());
	rcu_thread_online();
	printf("  rcu_thread_online (membar no-op) -> ongoing=%d\n",
	       rcu_read_ongoing());

	printf("=== PHASE 2: grace period with no readers ===\n");
	synchronize_rcu();
	printf("  synchronize_rcu returned\n");

	printf("=== PHASE 3: nested reader blocks the writer ===\n");
	sc.reader_active = &reader_active;
	sc.release_reader = &release_reader;
	sc.sync_done = &sync_done;
	if (pthread_create(&helper, NULL, reader_helper, &sc) != 0) {
		printf("  pthread_create failed\n");
		return 2;
	}
	while (!reader_active) {
		/* wait for the helper to take its read lock */
	}
	if (pthread_create(&writer, NULL, sync_writer, &sc) != 0) {
		printf("  pthread_create failed\n");
		return 2;
	}
	usleep(50000);
	/* structurally guaranteed: the writer cannot finish while the
	 * helper is nested, so the order of these prints is fixed */
	printf("  sync blocked (reader nested)\n");
	release_reader = 1;
	pthread_join(helper, NULL);
	pthread_join(writer, NULL);
	printf("  sync completed after reader unlock\n");

	printf("=== PHASE 4: unregister removes the thread from the registry ===\n");
	{
		volatile int ua = 0, ur = 0, sd = 0, ud = 0;
		struct unreg_ctx uc;
		pthread_t uhelper, uwriter;

		uc.reader_active = &ua;
		uc.release_reader = &ur;
		uc.sync_done = &sd;
		uc.unreg_done = &ud;
		if (pthread_create(&uhelper, NULL, unreg_helper, &uc) != 0) {
			printf("  pthread_create failed\n");
			return 2;
		}
		while (!ua) {
			/* wait */
		}
		if (pthread_create(&uwriter, NULL, sync_writer, &uc) != 0) {
			printf("  pthread_create failed\n");
			return 2;
		}
		usleep(50000);
		printf("  sync blocked (reader nested)\n");
		ur = 1;
		pthread_join(uhelper, NULL);
		pthread_join(uwriter, NULL);
		printf("  sync completed after reader unregistered\n");
		synchronize_rcu();
		printf("  synchronize_rcu (unregistered thread) returned\n");
	}

	printf("=== PHASE 5: call_rcu ordering + rcu_barrier ===\n");
	c1.id = 1;
	c2.id = 2;
	c3.id = 3;
	call_rcu(&c1.head, cb_run);
	call_rcu(&c2.head, cb_run);
	call_rcu(&c3.head, cb_run);
	printf("  queued 3 callbacks\n");
	rcu_barrier();
	printf("  rcu_barrier returned\n");
	rcu_barrier();
	printf("  rcu_barrier (empty) returned\n");
	c4.id = 4;
	call_rcu(&c4.head, cb_run);
	printf("  queued 1 callback after the barrier\n");
	rcu_barrier();
	printf("  rcu_barrier returned (cb4 ran before it)\n");

	printf("=== PHASE 6: rcu_dereference / rcu_assign_pointer ===\n");
	rcu_assign_pointer(pub, &target);
	val = rcu_dereference(pub);
	printf("  assign+deref round trip (plain) %s\n",
	       val == &target ? "ok" : "MISMATCH");
	rcu_read_lock();
	val = rcu_dereference(pub);
	printf("  assign+deref round trip (inside read lock) %s\n",
	       val == &target ? "ok" : "MISMATCH");
	rcu_read_unlock();

	rcu_unregister_thread();
	printf("  rcu_unregister_thread -> ok\n");
	return 0;
}
