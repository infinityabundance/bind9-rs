//! liburcu 0.15.6 — native Rust conservation of the userspace-RCU surface
//! BIND 9.20.26's netmgr/isc depends on (§30, §38, court LIBURCU-0001).
//!
//! Archaeology (pinned source `liburcu-0.15.6.tar.gz`, sha256
//! 15c341ce8b93d3b70bec120c1df90b2b02a219d65593cddeb4b52521a950e45e):
//! BIND's default build is the **membarrier flavor** (`--with-liburcu=
//! membarrier` → `<urcu.h>` → `urcu-memb.h`, linked as `-lurcu`); the
//! `isc_qsbr_*` auto-online wrappers in `isc/urcu.h` are the QSBR
//! developer option only.  The conserved surface is what BIND calls
//! (`lib/isc/thread.c`, `loop.c`, `work.c`, `lib.c` + the dns/* callers):
//! `rcu_register_thread`/`rcu_unregister_thread`,
//! `rcu_read_lock`/`rcu_read_unlock` (real per-thread nesting counters in
//! the membarrier flavor), `rcu_read_ongoing`, `rcu_quiescent_state` /
//! `rcu_thread_online` / `rcu_thread_offline` (compile-time **no-ops** in
//! this flavor, urcu-memb.h — they exist for QSBR compatibility),
//! `synchronize_rcu`, `call_rcu` + `rcu_barrier`, and
//! `rcu_dereference`/`rcu_assign_pointer`.
//!
//! Model notes:
//! - Each registered thread owns a `ThreadState` whose `ctr` packs the
//!   grace-period phase (bit 32) and the nesting count (low 32 bits),
//!   exactly like the C's `urcu_reader.ctr` (`URCU_GP_CTR_NEST_MASK`,
//!   `URCU_GP_CTR_PHASE`); `synchronize_rcu` toggles the phase and waits
//!   for the snapshot readers (urcu.c `wait_for_readers`, two passes).
//!   The mirror's first pass is conservative — it waits until *no*
//!   registered thread is nested, then snapshots; the courted sequences
//!   (readers established before the writer starts) cannot distinguish
//!   this from the C's scan, and waiting for more readers is always safe.
//! - `call_rcu` queues onto a single default queue (the C's default
//!   `call_rcu_data`); the call_rcu thread registers itself, drains a
//!   batch, runs one grace period, then runs the callbacks FIFO
//!   (urcu-call-rcu-impl.h `call_rcu_thread`).  `rcu_barrier` queues a
//!   completion marker behind everything queued so far and waits for it —
//!   the C's `_rcu_barrier_complete` mechanism; with no call_rcu thread
//!   ever created it returns immediately (an empty `call_rcu_data_list`).
//! - Every synchronization primitive is std::sync; no libc, no unsafe.
//!
//! Status: LIBURCU-0001 court green at 0 residuals.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};

/// `URCU_GP_CTR_NEST_MASK` (static/urcu-common.h): the low 32 bits of the
/// per-thread counter are the nesting depth.
const NEST_MASK: u64 = 0xFFFF_FFFF;
/// `URCU_GP_CTR_PHASE`: the phase bit toggled by each grace period.
const PHASE: u64 = 1 << 32;
/// `URCU_GP_COUNT`: the initial grace-period counter value.
const GP_INIT: u64 = 1;

/// The per-thread read-side state, shared with the writers (`urcu_reader`).
struct ThreadState {
    /// phase bits | nesting depth (0 = never read / fully unlocked).
    ctr: AtomicU64,
}

/// The registry of registered reader threads (urcu.c `registry`); also the
/// condvar mutex so a quiescing thread can wake a waiting writer without a
/// lost-wakeup race.
static REGISTRY: Mutex<Vec<Arc<ThreadState>>> = Mutex::new(Vec::new());
static GP_MON: Condvar = Condvar::new();
/// The grace-period counter (`rcu_gp.ctr`): `GP_INIT` phase 0, toggling
/// `PHASE` on every `synchronize_rcu`.
static GP_CTR: AtomicU64 = AtomicU64::new(GP_INIT);

thread_local! {
    static MY_STATE: std::cell::RefCell<Option<Arc<ThreadState>>> =
        const { std::cell::RefCell::new(None) };
    static MY_REGISTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ---------------------------------------------------------------------------
// thread registration
// ---------------------------------------------------------------------------

/// `rcu_register_thread` (urcu.c): asserts the thread is not already
/// registered and not nested, then adds it to the registry.  A registered
/// thread starts quiescent (ctr 0).
pub fn rcu_register_thread() {
    assert!(
        !MY_REGISTERED.with(|r| r.get()),
        "rcu_register_thread: thread already registered"
    );
    MY_STATE.with(|m| {
        if let Some(s) = m.borrow().as_ref() {
            assert_eq!(
                s.ctr.load(Ordering::Relaxed) & NEST_MASK,
                0,
                "rcu_register_thread: thread nested"
            );
        }
    });
    let s = Arc::new(ThreadState {
        ctr: AtomicU64::new(0),
    });
    MY_REGISTERED.with(|r| r.set(true));
    MY_STATE.with(|m| *m.borrow_mut() = Some(s.clone()));
    let mut reg = REGISTRY.lock().unwrap();
    reg.push(s);
    GP_MON.notify_all();
}

/// `rcu_unregister_thread` (urcu.c): removes the thread from the registry.
/// The counter is intentionally left untouched (an in-flight writer that
/// already snapshotted this thread still waits for it to quiesce).
pub fn rcu_unregister_thread() {
    let mine = MY_STATE.with(|m| m.borrow_mut().take());
    assert!(
        MY_REGISTERED.with(|r| r.replace(false)),
        "rcu_unregister_thread: thread not registered"
    );
    if let Some(mine) = mine {
        let mut reg = REGISTRY.lock().unwrap();
        reg.retain(|s| !Arc::ptr_eq(s, &mine));
        GP_MON.notify_all();
    }
}

// ---------------------------------------------------------------------------
// read-side critical sections
// ---------------------------------------------------------------------------

/// `rcu_read_lock` (urcu.c `_urcu_memb_read_lock`): increment the nesting
/// counter; on 0→1 record the current grace-period phase.
pub fn rcu_read_lock() {
    let s = MY_STATE
        .with(|m| m.borrow().clone())
        .expect("rcu_read_lock: thread not registered");
    let old = s.ctr.load(Ordering::Relaxed);
    let new = if old & NEST_MASK == 0 {
        let g = GP_CTR.load(Ordering::Acquire);
        g
    } else {
        old + 1
    };
    s.ctr.store(new, Ordering::Relaxed);
}

/// `rcu_read_unlock` (urcu.c `_urcu_memb_read_unlock`): decrement the
/// nesting counter; waking the waiting writers when it reaches 0.
pub fn rcu_read_unlock() {
    let s = MY_STATE
        .with(|m| m.borrow().clone())
        .expect("rcu_read_unlock: thread not registered");
    let old = s.ctr.load(Ordering::Relaxed);
    debug_assert_ne!(old & NEST_MASK, 0, "rcu_read_unlock: not nested");
    let new = old - 1;
    s.ctr.store(new, Ordering::Relaxed);
    if new & NEST_MASK == 0 {
        let _reg = REGISTRY.lock().unwrap();
        GP_MON.notify_all();
    }
}

/// `rcu_read_ongoing` (urcu.c): the current thread's nesting depth.
pub fn rcu_read_ongoing() -> u32 {
    MY_STATE.with(|m| match m.borrow().as_ref() {
        Some(s) => (s.ctr.load(Ordering::Relaxed) & NEST_MASK) as u32,
        None => 0,
    })
}

/// No-op in the membarrier flavor (urcu-memb.h).  QSBR's quiescent-state
/// reporting does not exist here: a membarrier reader is simply "nested"
/// until `rcu_read_unlock`.
pub fn rcu_quiescent_state() {}

/// No-op in the membarrier flavor (urcu-memb.h).
pub fn rcu_thread_offline() {}

/// No-op in the membarrier flavor (urcu-memb.h).
pub fn rcu_thread_online() {}

// ---------------------------------------------------------------------------
// grace periods
// ---------------------------------------------------------------------------

/// `synchronize_rcu` (urcu.c): the two-pass membarrier grace period —
/// snapshot the nested readers, toggle the phase, wait for the snapshot
/// readers to finish.  The calling thread must not be nested.
pub fn synchronize_rcu() {
    // Pass 1: wait until no registered thread is nested, collecting the
    // snapshot of the threads that were (urcu.c `wait_for_readers` moving
    // ACTIVE_CURRENT readers into cur_snap_readers).
    let mut snapshot: Vec<Arc<ThreadState>> = Vec::new();
    {
        let mut reg = REGISTRY.lock().unwrap();
        loop {
            let mut any_nested = false;
            for s in reg.iter() {
                if s.ctr.load(Ordering::Acquire) & NEST_MASK != 0 {
                    any_nested = true;
                    if !snapshot.iter().any(|x| Arc::ptr_eq(x, s)) {
                        snapshot.push(s.clone());
                    }
                }
            }
            if !any_nested {
                break;
            }
            reg = GP_MON.wait(reg).unwrap();
        }
    }
    // Switch parity (urcu.c: `rcu_gp.ctr ^ URCU_GP_CTR_PHASE`).
    GP_CTR.fetch_xor(PHASE, Ordering::SeqCst);
    // Pass 2: wait for the snapshot readers to finish.
    if !snapshot.is_empty() {
        let mut reg = REGISTRY.lock().unwrap();
        loop {
            let all_done = snapshot
                .iter()
                .all(|s| s.ctr.load(Ordering::Acquire) & NEST_MASK == 0);
            if all_done {
                break;
            }
            reg = GP_MON.wait(reg).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// pointer publication
// ---------------------------------------------------------------------------

/// `rcu_dereference` (urcu/pointer.h): the acquire-load side of the
/// publication pair.
pub fn rcu_dereference<T>(p: &AtomicPtr<T>) -> *mut T {
    p.load(Ordering::Acquire)
}

/// `rcu_assign_pointer` (urcu/pointer.h `rcu_set_pointer`): the
/// release-store publication side.
pub fn rcu_assign_pointer<T>(p: &AtomicPtr<T>, v: *mut T) {
    p.store(v, Ordering::Release);
}

// ---------------------------------------------------------------------------
// deferred reclamation: call_rcu + rcu_barrier
// ---------------------------------------------------------------------------

/// `struct rcu_head` (call-rcu.h): the per-callback identity token.  The
/// mirror's queue owns the callback; the head is what the caller passes.
pub struct RcuHead;

/// The deferred callback (`void (*func)(struct rcu_head *)`).
pub type CallRcuCb = Box<dyn FnMut() + Send + 'static>;

/// The default call_rcu queue entry: a callback, or a barrier completion
/// marker queued behind everything already submitted (the C's
/// `_rcu_barrier_complete`).
enum CallRcuEntry {
    Callback { cb: CallRcuCb },
    Barrier { done: Arc<(Mutex<bool>, Condvar)> },
}

static CALL_QUEUE: Mutex<VecDeque<CallRcuEntry>> = Mutex::new(VecDeque::new());
static CALL_CV: Condvar = Condvar::new();
static CALL_THREAD_ONCE: Once = Once::new();
/// Whether the call_rcu thread exists (the C's non-empty call_rcu_data_list).
static CALL_THREAD_ALIVE: AtomicBool = AtomicBool::new(false);

/// `call_rcu` (urcu-call-rcu-impl.h): schedule `cb` to run after a
/// following grace period, on the call_rcu thread.  The first invocation
/// creates the call_rcu thread (the default call_rcu_data).
pub fn call_rcu(_head: &mut RcuHead, cb: CallRcuCb) {
    CALL_THREAD_ONCE.call_once(|| {
        CALL_THREAD_ALIVE.store(true, Ordering::SeqCst);
        std::thread::spawn(call_rcu_thread_main);
    });
    let mut q = CALL_QUEUE.lock().unwrap();
    q.push_back(CallRcuEntry::Callback { cb });
    CALL_CV.notify_all();
}

/// `rcu_barrier` (urcu-call-rcu-impl.h): returns only after every
/// previously queued call_rcu callback has run.  With no call_rcu thread
/// ever created (an empty call_rcu_data_list) it returns immediately.
pub fn rcu_barrier() {
    if !CALL_THREAD_ALIVE.load(Ordering::SeqCst) {
        return;
    }
    let done = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let mut q = CALL_QUEUE.lock().unwrap();
        q.push_back(CallRcuEntry::Barrier { done: done.clone() });
    }
    CALL_CV.notify_all();
    let (lock, cv) = &*done;
    let mut d = lock.lock().unwrap();
    while !*d {
        d = cv.wait(d).unwrap();
    }
}

/// The call_rcu thread (urcu-call-rcu-impl.h `call_rcu_thread`): registered
/// like the C's, drains a whole batch, runs one grace period, then runs the
/// callbacks FIFO.
fn call_rcu_thread_main() {
    rcu_register_thread();
    loop {
        let batch: Vec<CallRcuEntry> = {
            let mut q = CALL_QUEUE.lock().unwrap();
            while q.is_empty() {
                q = CALL_CV.wait(q).unwrap();
            }
            q.drain(..).collect()
        };
        synchronize_rcu();
        for e in batch {
            match e {
                CallRcuEntry::Callback { mut cb } => cb(),
                CallRcuEntry::Barrier { done } => {
                    let (lock, cv) = &*done;
                    *lock.lock().unwrap() = true;
                    cv.notify_all();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// unit tests (oracle vectors from probe-liburcu.c and the pinned source)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_side_nesting_matches_the_oracle() {
        // probe-liburcu.c PHASE 0/1 values.
        assert_eq!(rcu_read_ongoing(), 0); // before register
        rcu_register_thread();
        assert_eq!(rcu_read_ongoing(), 0); // after register
        rcu_read_lock();
        assert_eq!(rcu_read_ongoing(), 1);
        rcu_read_lock();
        assert_eq!(rcu_read_ongoing(), 2);
        rcu_read_unlock();
        assert_eq!(rcu_read_ongoing(), 1);
        rcu_read_unlock();
        assert_eq!(rcu_read_ongoing(), 0);
        // the membarrier no-ops leave the state untouched
        rcu_quiescent_state();
        rcu_thread_offline();
        rcu_thread_online();
        assert_eq!(rcu_read_ongoing(), 0);
        rcu_unregister_thread();
        assert_eq!(rcu_read_ongoing(), 0);
    }

    #[test]
    fn grace_period_without_readers_returns() {
        rcu_register_thread();
        synchronize_rcu();
        rcu_unregister_thread();
    }

    #[test]
    fn nested_reader_blocks_the_writer() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        rcu_register_thread();
        let reading = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let r1 = reading.clone();
        let r2 = release.clone();
        let helper = std::thread::spawn(move || {
            rcu_register_thread();
            rcu_read_lock();
            r1.store(true, Ordering::SeqCst);
            while !r2.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            rcu_read_unlock();
            rcu_unregister_thread();
        });
        while !reading.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let writer = std::thread::spawn(move || {
            rcu_register_thread();
            synchronize_rcu();
            d.store(true, Ordering::SeqCst);
            rcu_unregister_thread();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Structural: the writer cannot finish while the helper is nested.
        assert!(!done.load(Ordering::SeqCst), "writer finished early");
        release.store(true, Ordering::SeqCst);
        helper.join().unwrap();
        writer.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
        rcu_unregister_thread();
    }

    #[test]
    fn offline_and_quiescent_state_are_noops() {
        rcu_register_thread();
        rcu_read_lock();
        rcu_quiescent_state();
        rcu_thread_offline();
        rcu_thread_online();
        assert_eq!(rcu_read_ongoing(), 1); // still nested
        rcu_read_unlock();
        rcu_unregister_thread();
    }

    #[test]
    fn call_rcu_order_and_barrier() {
        use std::sync::atomic::{AtomicI32, Ordering};
        use std::sync::Arc;

        rcu_register_thread();
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        for id in 1..=3 {
            let o = order.clone();
            let mut head = RcuHead;
            call_rcu(&mut head, Box::new(move || o.lock().unwrap().push(id)));
        }
        rcu_barrier();
        assert_eq!(*order.lock().unwrap(), vec![1, 2, 3]);
        rcu_barrier(); // empty: still returns
                       // a callback queued after a barrier runs before the next barrier
        let fired = Arc::new(AtomicI32::new(0));
        let f = fired.clone();
        let mut head = RcuHead;
        call_rcu(
            &mut head,
            Box::new(move || {
                f.store(1, Ordering::SeqCst);
            }),
        );
        rcu_barrier();
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        rcu_unregister_thread();
    }

    #[test]
    fn barrier_without_call_rcu_thread_returns_immediately() {
        // No call_rcu ever invoked: the (empty) call_rcu_data_list path.
        rcu_barrier();
    }

    #[test]
    fn pointer_round_trip() {
        let mut target: i32 = 42;
        let p = AtomicPtr::new(std::ptr::null_mut());
        let tp = &target as *const i32 as *mut i32;
        rcu_assign_pointer(&p, tp);
        assert_eq!(rcu_dereference(&p), tp);
    }

    #[test]
    fn unregister_removes_the_thread_from_the_registry() {
        rcu_register_thread();
        let reading = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let r1 = reading.clone();
        let r2 = release.clone();
        let helper = std::thread::spawn(move || {
            rcu_register_thread();
            rcu_read_lock();
            r1.store(true, Ordering::SeqCst);
            while !r2.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            rcu_read_unlock();
            rcu_unregister_thread();
        });
        while !reading.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let writer = std::thread::spawn(move || {
            rcu_register_thread();
            synchronize_rcu();
            d.store(true, Ordering::SeqCst);
            rcu_unregister_thread();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!done.load(Ordering::SeqCst));
        release.store(true, Ordering::SeqCst);
        helper.join().unwrap();
        writer.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
        // The unregistered thread is gone: a fresh grace period is instant.
        synchronize_rcu();
        rcu_unregister_thread();
    }

    #[test]
    #[should_panic]
    fn read_lock_without_registration_panics() {
        rcu_read_lock();
    }
}
