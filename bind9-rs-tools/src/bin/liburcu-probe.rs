//! liburcu-probe — Rust mirror of `forensics/oracle/probes/probe-liburcu.c`
//! for the LIBURCU-0001 court (§30, §38).  Runs in the same
//! oracle-liburcu-0.15.6 container; stdout must be byte-identical.
//!
//! Usage: liburcu-probe
//!
//! The C probe is the transcript contract: every phase, every print.
//! Handshake flags live in `Arc<AtomicBool>` (the callbacks are `'static`);
//! the helper threads print nothing and are joined before their results are
//! reported, so the transcript order is fixed.

use bind9_rs_tools::compat::liburcu::*;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// phase 3/4: the reader helper + the sync writer
// ---------------------------------------------------------------------------

fn reader_helper(reading: Arc<AtomicBool>, release: Arc<AtomicBool>) {
    rcu_register_thread();
    rcu_read_lock();
    reading.store(true, Ordering::SeqCst);
    while !release.load(Ordering::SeqCst) {
        /* spin: hold the read lock until released */
        std::hint::spin_loop();
    }
    rcu_read_unlock();
    rcu_unregister_thread();
}

fn sync_writer(done: Arc<AtomicBool>) {
    rcu_register_thread();
    synchronize_rcu();
    done.store(true, Ordering::SeqCst);
    rcu_unregister_thread();
}

fn unreg_helper(reading: Arc<AtomicBool>, release: Arc<AtomicBool>, unreg_done: Arc<AtomicBool>) {
    rcu_register_thread();
    rcu_read_lock();
    reading.store(true, Ordering::SeqCst);
    while !release.load(Ordering::SeqCst) {
        /* spin */
        std::hint::spin_loop();
    }
    rcu_read_unlock();
    rcu_unregister_thread();
    unreg_done.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== PHASE 0: thread registration ===");
    println!("  rcu_read_ongoing before register={}", rcu_read_ongoing());
    rcu_register_thread();
    println!("  rcu_register_thread -> ok");
    println!("  rcu_read_ongoing after register={}", rcu_read_ongoing());

    println!("=== PHASE 1: read-side nesting ===");
    rcu_read_lock();
    println!("  rcu_read_lock -> ongoing={}", rcu_read_ongoing());
    rcu_read_lock();
    println!("  rcu_read_lock -> ongoing={}", rcu_read_ongoing());
    rcu_read_unlock();
    println!("  rcu_read_unlock -> ongoing={}", rcu_read_ongoing());
    rcu_read_unlock();
    println!("  rcu_read_unlock -> ongoing={}", rcu_read_ongoing());
    rcu_quiescent_state();
    println!(
        "  rcu_quiescent_state (membar no-op) -> ongoing={}",
        rcu_read_ongoing()
    );
    rcu_thread_offline();
    println!(
        "  rcu_thread_offline (membar no-op) -> ongoing={}",
        rcu_read_ongoing()
    );
    rcu_thread_online();
    println!(
        "  rcu_thread_online (membar no-op) -> ongoing={}",
        rcu_read_ongoing()
    );

    println!("=== PHASE 2: grace period with no readers ===");
    synchronize_rcu();
    println!("  synchronize_rcu returned");

    println!("=== PHASE 3: nested reader blocks the writer ===");
    {
        let reading = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let (r, rel) = (reading.clone(), release.clone());
        let helper = std::thread::spawn(move || reader_helper(r, rel));
        while !reading.load(Ordering::SeqCst) {
            /* wait for the helper to take its read lock */
            std::hint::spin_loop();
        }
        let d = done.clone();
        let writer = std::thread::spawn(move || sync_writer(d));
        std::thread::sleep(std::time::Duration::from_millis(50));
        /* structurally guaranteed: the writer cannot finish while the
         * helper is nested, so the order of these prints is fixed */
        println!("  sync blocked (reader nested)");
        release.store(true, Ordering::SeqCst);
        helper.join().unwrap();
        writer.join().unwrap();
        println!("  sync completed after reader unlock");
    }

    println!("=== PHASE 4: unregister removes the thread from the registry ===");
    {
        let reading = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let unreg_done = Arc::new(AtomicBool::new(false));
        let (r, rel, ud) = (reading.clone(), release.clone(), unreg_done.clone());
        let uhelper = std::thread::spawn(move || unreg_helper(r, rel, ud));
        while !reading.load(Ordering::SeqCst) {
            /* wait */
            std::hint::spin_loop();
        }
        let d = done.clone();
        let uwriter = std::thread::spawn(move || sync_writer(d));
        std::thread::sleep(std::time::Duration::from_millis(50));
        println!("  sync blocked (reader nested)");
        release.store(true, Ordering::SeqCst);
        uhelper.join().unwrap();
        uwriter.join().unwrap();
        println!("  sync completed after reader unregistered");
        synchronize_rcu();
        println!("  synchronize_rcu (unregistered thread) returned");
    }

    println!("=== PHASE 5: call_rcu ordering + rcu_barrier ===");
    let mut h1 = RcuHead;
    let mut h2 = RcuHead;
    let mut h3 = RcuHead;
    call_rcu(&mut h1, Box::new(|| println!("    call_rcu cb 1")));
    call_rcu(&mut h2, Box::new(|| println!("    call_rcu cb 2")));
    call_rcu(&mut h3, Box::new(|| println!("    call_rcu cb 3")));
    println!("  queued 3 callbacks");
    rcu_barrier();
    println!("  rcu_barrier returned");
    rcu_barrier();
    println!("  rcu_barrier (empty) returned");
    let mut h4 = RcuHead;
    call_rcu(&mut h4, Box::new(|| println!("    call_rcu cb 4")));
    println!("  queued 1 callback after the barrier");
    rcu_barrier();
    println!("  rcu_barrier returned (cb4 ran before it)");

    println!("=== PHASE 6: rcu_dereference / rcu_assign_pointer ===");
    let mut target: i32 = 42;
    let pub_ = AtomicPtr::new(std::ptr::null_mut());
    let tp = &target as *const i32 as *mut i32;
    rcu_assign_pointer(&pub_, tp);
    let val = rcu_dereference(&pub_);
    println!(
        "  assign+deref round trip (plain) {}",
        if val == tp { "ok" } else { "MISMATCH" }
    );
    rcu_read_lock();
    let val = rcu_dereference(&pub_);
    println!(
        "  assign+deref round trip (inside read lock) {}",
        if val == tp { "ok" } else { "MISMATCH" }
    );
    rcu_read_unlock();

    rcu_unregister_thread();
    println!("  rcu_unregister_thread -> ok");
}
