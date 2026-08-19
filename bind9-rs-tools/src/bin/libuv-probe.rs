//! libuv-probe — Rust mirror of `forensics/oracle/probes/probe-libuv.c`
//! for the LIBUV-0001 court (§30, §38).  Runs in the same
//! oracle-libuv-1.52.1 container; stdout must be byte-identical.
//!
//! Usage: libuv-probe
//!
//! The C probe is the transcript contract: every phase, every print, every
//! return value.  State shared between the loop's callbacks and the helper
//! threads lives in statics (the closures are `'static`); the custom
//! allocator functions mirror the C's counters exactly — the mirror's loop
//! never dereferences the opaque allocations (its real state is in the Rust
//! struct), so the customs only count.

use bind9_rs_tools::compat::libuv::*;
use bind9_rs_tools::platform::linux as lx;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// transcript helpers
// ---------------------------------------------------------------------------

/// The C probe's `SNAME`: a 0 status is success, not a libuv error name.
fn sname(st: i32) -> String {
    if st == 0 {
        "0".to_string()
    } else {
        uv_err_name(st)
    }
}

/// The C probe's `PERR`.
fn perr(tag: &str, rc: i32) {
    println!("{tag} rc={} ({})", uv_err_name(rc), uv_strerror(rc));
}

/// Look the error code up by table name (the probe's `ERR` battery).
fn code_of(name: &str) -> i32 {
    TABLE
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.value)
        .unwrap()
}

// ---------------------------------------------------------------------------
// shared: the silent stop timer
// ---------------------------------------------------------------------------

fn arm_stop(l: &mut UvLoop, stop_t: &mut Timer) {
    l.uv_timer_init(stop_t);
    let _ = l.uv_timer_start(*stop_t, Some(Box::new(|l: &mut UvLoop| l.uv_stop())), 30, 0);
}

// ---------------------------------------------------------------------------
// phase 2: timers
// ---------------------------------------------------------------------------

static REP_COUNT: AtomicI32 = AtomicI32::new(0);
static T8_COUNT: AtomicI32 = AtomicI32::new(0);

fn phase2_timers(l: &mut UvLoop) {
    println!("=== PHASE 2: timers ===");
    let mut t1 = Handle(0);
    let mut t2 = Handle(0);
    let mut t3 = Handle(0);
    l.uv_timer_init(&mut t1);
    l.uv_timer_init(&mut t2);
    l.uv_timer_init(&mut t3);
    let _ = l.uv_timer_start(
        t1,
        Some(Box::new(|_| println!("    t1 fired (due 50)"))),
        50,
        0,
    );
    let _ = l.uv_timer_start(
        t2,
        Some(Box::new(|_| println!("    t2 fired (due 10)"))),
        10,
        0,
    );
    let _ = l.uv_timer_start(
        t3,
        Some(Box::new(|_| println!("    t3 fired (due 10)"))),
        10,
        0,
    );
    /* NULL callback -> UV_EINVAL (the check runs before uv_timer_stop) */
    perr(
        "  uv_timer_start(NULL cb)",
        l.uv_timer_start(t1, None, 10, 0),
    );
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* repeat timer with a stopper; repeat re-arms BEFORE the callback */
    let mut rep = Handle(0);
    let mut stopper = Handle(0);
    l.uv_timer_init(&mut rep);
    l.uv_timer_init(&mut stopper);
    REP_COUNT.store(0, Ordering::SeqCst);
    let rep_h = rep;
    let _ = l.uv_timer_start(
        rep,
        Some(Box::new(move |_l: &mut UvLoop| {
            let n = REP_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
            println!("    repeat fired ({n})");
        })),
        10,
        10,
    );
    let _ = l.uv_timer_start(
        stopper,
        Some(Box::new(move |l: &mut UvLoop| {
            println!("    stopper fired; stopping repeat");
            l.uv_timer_stop(rep_h);
        })),
        45,
        0,
    );
    println!("  uv_timer_get_repeat(rep)={}", l.uv_timer_get_repeat(rep));
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* restart a timer from another timer's callback */
    let mut ta = Handle(0);
    let mut tb = Handle(0);
    l.uv_timer_init(&mut ta);
    l.uv_timer_init(&mut tb);
    let tb_h = tb;
    let _ = l.uv_timer_start(
        ta,
        Some(Box::new(move |l: &mut UvLoop| {
            println!("    a fired (starting b with 5ms)");
            let _ = l.uv_timer_start(
                tb_h,
                Some(Box::new(|_| println!("    b fired (5ms after a)"))),
                5,
                0,
            );
        })),
        30,
        0,
    );
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* uv_timer_again on a one-shot: no repeat -> fires once */
    let mut t8 = Handle(0);
    l.uv_timer_init(&mut t8);
    T8_COUNT.store(0, Ordering::SeqCst);
    let t8_h = t8;
    let _ = l.uv_timer_start(
        t8,
        Some(Box::new(move |l: &mut UvLoop| {
            let n = T8_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
            println!("    t8 fired ({n}); uv_timer_again -> no repeat, no re-arm");
            l.uv_timer_again(t8_h);
        })),
        10,
        0,
    );
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* stop an inactive timer -> 0; a started-then-stopped timer and a
     * closed timer never fire */
    println!("  uv_timer_stop(inactive)={}", l.uv_timer_stop(t8));
    let mut t10 = Handle(0);
    let mut t11 = Handle(0);
    l.uv_timer_init(&mut t10);
    let _ = l.uv_timer_start(
        t10,
        Some(Box::new(|_| println!("    UNEXPECTED timer fire"))),
        10,
        0,
    );
    l.uv_timer_stop(t10);
    l.uv_timer_init(&mut t11);
    let _ = l.uv_timer_start(
        t11,
        Some(Box::new(|_| println!("    UNEXPECTED timer fire"))),
        10,
        0,
    );
    l.uv_close(t11, None);
    println!(
        "  uv_run(DEFAULT) returned {} (stopped/closed timers never fired)",
        l.uv_run(RunMode::Default)
    );
}

// ---------------------------------------------------------------------------
// phase 3: idle/prepare/check ordering
// ---------------------------------------------------------------------------

fn phase3_watchers(l: &mut UvLoop) {
    println!("=== PHASE 3: idle/prepare/check ===");
    let mut id1 = Handle(0);
    let mut pr1 = Handle(0);
    let mut ch1 = Handle(0);
    l.uv_idle_init(&mut id1);
    l.uv_prepare_init(&mut pr1);
    l.uv_check_init(&mut ch1);
    let (id1_h, pr1_h, ch1_h) = (id1, pr1, ch1);
    let _ = l.uv_idle_start(id1, Box::new(|_| println!("    idle")));
    let _ = l.uv_prepare_start(pr1, Box::new(|_| println!("    prepare")));
    let _ = l.uv_check_start(
        ch1,
        Box::new(move |l: &mut UvLoop| {
            println!("    check; stopping idle/prepare/check");
            l.uv_idle_stop(id1_h);
            l.uv_prepare_stop(pr1_h);
            l.uv_check_stop(ch1_h);
        }),
    );
    /* the check handle stops everything inside the FIRST iteration, so
     * the loop cannot spin (idle handles force a zero poll timeout) */
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    /* starting an already-active watcher is a no-op */
    println!(
        "  uv_idle_start(active)={}",
        l.uv_idle_start(id1, Box::new(|_| println!("    idle")))
    );
    l.uv_idle_stop(id1);

    /* one callback per iteration (UV_RUN_NOWAIT) */
    let mut id2 = Handle(0);
    l.uv_idle_init(&mut id2);
    let _ = l.uv_idle_start(id2, Box::new(|_| println!("    idle2")));
    println!("  run1(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
    println!("  run2(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
    l.uv_idle_stop(id2);
    println!("  run3(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
}

// ---------------------------------------------------------------------------
// phase 4: async
// ---------------------------------------------------------------------------

fn phase4_async(l: &mut UvLoop) {
    println!("=== PHASE 4: async ===");
    let mut a1 = Handle(0);
    let mut a2 = Handle(0);
    l.uv_async_init(
        &mut a1,
        Box::new(|_| println!("    a1 fired (3 sends coalesced into one callback)")),
    );
    l.uv_async_init(
        &mut a2,
        Box::new(|_| println!("    a2 fired (cross-thread send)")),
    );
    /* three sends before the run -> one callback (coalescing) */
    let _ = l.uv_async_send(a1);
    let _ = l.uv_async_send(a1);
    let _ = l.uv_async_send(a1);
    println!("  uv_run(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
    l.uv_close(a1, None);
    println!(
        "  uv_run(NOWAIT) returned {} (a2 still active)",
        l.uv_run(RunMode::Nowait)
    );

    /* cross-thread send: a timer releases the helper, which sends a2 once */
    let mut sig_timer = Handle(0);
    let mut stop4 = Handle(0);
    l.uv_timer_init(&mut sig_timer);
    l.uv_timer_init(&mut stop4);
    let released = Arc::new(AtomicBool::new(false));
    let helper_flag = released.clone();
    let cb_flag = helper_flag.clone();
    let wake_token = l.async_wake(a2);
    let _ = l.uv_timer_start(
        sig_timer,
        Some(Box::new(move |_l: &mut UvLoop| {
            println!("    timer fired; releasing helper thread");
            cb_flag.store(true, Ordering::Release); /* the helper spins on this flag */
        })),
        20,
        0,
    );
    let _ = l.uv_timer_start(stop4, Some(Box::new(|l: &mut UvLoop| l.uv_stop())), 100, 0);
    let helper = std::thread::spawn(move || {
        while !helper_flag.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        wake_token.send();
    });
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    helper.join().unwrap();
    println!("  helper thread joined");
    l.uv_close(a2, None);
    println!(
        "  uv_run(NOWAIT) returned {} (a2 closed)",
        l.uv_run(RunMode::Nowait)
    );
}

// ---------------------------------------------------------------------------
// phase 5: signal
// ---------------------------------------------------------------------------

static SIG_COUNT: AtomicI32 = AtomicI32::new(0);

fn phase5_signal(l: &mut UvLoop) {
    println!("=== PHASE 5: signal ===");
    let mut sig1 = Handle(0);
    l.uv_signal_init(&mut sig1);
    SIG_COUNT.store(0, Ordering::SeqCst);
    let mk_sig_cb = || -> Cb {
        Box::new(|_l: &mut UvLoop| {
            let n = SIG_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
            println!("    signal {} caught ({n})", libc::SIGUSR1);
        })
    };
    perr(
        "  uv_signal_start(signum=0)",
        l.uv_signal_start(sig1, mk_sig_cb(), 0),
    );
    println!(
        "  uv_signal_start(SIGUSR1)={}",
        l.uv_signal_start(sig1, mk_sig_cb(), libc::SIGUSR1)
    );
    let _ = lx::raise(libc::SIGUSR1);
    let _ = lx::raise(libc::SIGUSR1);
    arm_stop(l, &mut Handle(0));
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    println!("  uv_signal_stop={}", l.uv_signal_stop(sig1));
    /* same-signum restart only replaces the callback */
    println!(
        "  uv_signal_start(same signum)={}",
        l.uv_signal_start(sig1, mk_sig_cb(), libc::SIGUSR1)
    );
    l.uv_signal_stop(sig1);
    l.uv_close(sig1, None);
    println!("  uv_run(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
}

// ---------------------------------------------------------------------------
// phase 6: UDP
// ---------------------------------------------------------------------------

static UB_SEND_CBS: AtomicI32 = AtomicI32::new(0);

fn alloc_cb(_l: &mut UvLoop, suggested: usize, buf: &mut Buf) {
    println!("    alloc suggested={suggested}");
    buf.data = vec![0u8; suggested];
}

fn ua_recv_cb(_l: &mut UvLoop, nread: i64, buf: &mut Buf, addr: Option<&Addr>, _flags: u32) {
    if nread < 0 {
        println!("    ua recv nread={}", uv_err_name(nread as i32));
        return;
    }
    match addr {
        Some(_) => {
            let content = String::from_utf8_lossy(&buf.data[..nread as usize]);
            println!("    ua recv nread={nread} content={content} addr=127.0.0.1");
        }
        None => {
            /* nread == 0 with addr == NULL is the EAGAIN drain marker libuv
             * emits when the socket buffer is exhausted */
            println!("    ua recv nread={nread} addr=null(eagain-drain)");
        }
    }
}

fn mk_ub_send_cb(ub_h: Udp) -> UdpSendCb {
    Box::new(move |l: &mut UvLoop, status: i32| {
        let n = UB_SEND_CBS.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "    send_cb ({n}) status={} queue={}",
            sname(status),
            l.uv_udp_get_send_queue_size(ub_h)
        );
    })
}

fn phase6_udp(l: &mut UvLoop) {
    println!("=== PHASE 6: UDP ===");

    let mut uc = Handle(0);
    perr(
        "  uv_udp_init_ex(bad domain)",
        l.uv_udp_init_ex(&mut uc, 999),
    );
    perr(
        "  uv_udp_init_ex(bad extra flags)",
        l.uv_udp_init_ex(&mut uc, (libc::AF_INET as u32) | 0x200),
    );
    l.uv_udp_init(&mut uc);
    l.uv_close(uc, None);
    println!("  uv_run(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));

    let mut ua = Handle(0);
    let mut ub = Handle(0);
    l.uv_udp_init(&mut ua);
    l.uv_udp_init(&mut ub);
    println!(
        "  uv_udp_bind(ua)={}",
        l.uv_udp_bind(ua, &Addr::v4_loopback(0))
    );
    let mut ua_port = 0;
    println!(
        "  uv_udp_getsockname(ua)={}",
        l.uv_udp_getsockname(ua, &mut ua_port)
    );
    let a_addr = Addr::v4_loopback(ua_port);

    /* try_send without an address on an unconnected socket -> EDESTADDRREQ */
    let p1 = b"ping";
    perr(
        "  ub try_send(no addr, unconnected)",
        l.uv_udp_try_send(ub, p1, None),
    );

    /* try_send to ua's address: synchronous byte count */
    let n = l.uv_udp_try_send(ub, p1, Some(&a_addr));
    println!("  ub try_send(to ua) sent={n}");

    /* connect ub to ua; send with an address -> EISCONN; queue stays 0 */
    println!(
        "  uv_udp_connect(ub)={}",
        l.uv_udp_connect(ub, Some(&a_addr))
    );
    perr(
        "  ub send(addr, connected)",
        l.uv_udp_send(ub, &[p1.to_vec()], Some(&a_addr), mk_ub_send_cb(ub)),
    );
    perr(
        "  ub try_send(addr, connected)",
        l.uv_udp_try_send(ub, p1, Some(&a_addr)),
    );

    /* run 1: ua recv_start; the earlier try_send'd "ping" is already in
     * the socket buffer and is the only event in this run */
    l.uv_udp_recv_start(ua, Box::new(alloc_cb), Box::new(ua_recv_cb));
    arm_stop(l, &mut Handle(0));
    println!("  uv_run1(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* queue a scatter send (two buffers -> one datagram) and a 600-byte
     * send; the send_cbs fire in the pending pass of the round that
     * writes them, the recv_cbs in later iterations, in datagram order */
    let bufs2 = vec![b"ab".to_vec(), b"cd".to_vec()];
    let _ = l.uv_udp_send(ub, &bufs2, None, mk_ub_send_cb(ub));
    println!(
        "  queue size after 2 bufs={}",
        l.uv_udp_get_send_queue_size(ub)
    );
    let big = vec![b'x'; 600];
    let _ = l.uv_udp_send(ub, &[big.clone()], None, mk_ub_send_cb(ub));
    println!(
        "  queue size after 600b={}",
        l.uv_udp_get_send_queue_size(ub)
    );
    arm_stop(l, &mut Handle(0));
    println!("  uv_run2(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    /* disconnect semantics (no sends pending) */
    println!("  uv_udp_connect(ub, NULL)={}", l.uv_udp_connect(ub, None));
    perr(
        "  uv_udp_connect(ub, NULL) again",
        l.uv_udp_connect(ub, None),
    );
    perr(
        "  ub send(NULL addr, unconnected)",
        l.uv_udp_send(ub, &[big.clone()], None, mk_ub_send_cb(ub)),
    );
    println!("  uv_udp_recv_stop(ua)={}", l.uv_udp_recv_stop(ua));
    println!("  uv_udp_recv_stop again={}", l.uv_udp_recv_stop(ua));

    /* connected recv: ua connects to its own address; ub connects to ua
     * and sends without an address; ua's recv_cb still gets the peer
     * address (only the EAGAIN drain marker has addr == NULL) */
    println!(
        "  uv_udp_connect(ua)={}",
        l.uv_udp_connect(ua, Some(&a_addr))
    );
    l.uv_udp_recv_start(ua, Box::new(alloc_cb), Box::new(ua_recv_cb));
    println!(
        "  uv_udp_connect(ub)={}",
        l.uv_udp_connect(ub, Some(&a_addr))
    );
    let p2 = b"pong";
    let _ = l.uv_udp_send(ub, &[p2.to_vec()], None, mk_ub_send_cb(ub));
    arm_stop(l, &mut Handle(0));
    println!("  uv_run3(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    l.uv_close(ua, None);
    l.uv_close(ub, None);
    println!("  uv_run(NOWAIT) returned {}", l.uv_run(RunMode::Nowait));
}

// ---------------------------------------------------------------------------
// phase 7: TCP
// ---------------------------------------------------------------------------

static CONNECT_STATUS: AtomicI32 = AtomicI32::new(-999);
static ACCEPT_STATUS: AtomicI32 = AtomicI32::new(-999);
static ACCEPT_RC: AtomicI32 = AtomicI32::new(-999);
static SHUTDOWN_STATUS: AtomicI32 = AtomicI32::new(-999);
/// The accepted client handle (uv_accept reuses the pre-created slot, so the
/// handle value is stable; the Cell-role is played by this static).
static CONN_CELL: std::sync::Mutex<Tcp> = std::sync::Mutex::new(Handle(0));
/// The listening server handle, captured for the accept callback.
static SRV_H: std::sync::Mutex<Tcp> = std::sync::Mutex::new(Handle(0));
static CONN_TOTAL: AtomicI64 = AtomicI64::new(0);
static CLI_TOTAL: AtomicI64 = AtomicI64::new(0);
static CLI_EOF: AtomicBool = AtomicBool::new(false);
static CONN_BUF: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
static CLI_BUF: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

fn conn_alloc(_l: &mut UvLoop, suggested: usize, buf: &mut Buf) {
    buf.data = vec![0u8; suggested];
}

fn conn_read(_l: &mut UvLoop, nread: i64, buf: &mut Buf) {
    if nread < 0 {
        return;
    }
    let n = nread as usize;
    let mut cb = CONN_BUF.lock().unwrap();
    let take = n.min(64 - 1 - cb.len());
    cb.extend_from_slice(&buf.data[..take]);
    CONN_TOTAL.fetch_add(n as i64, Ordering::SeqCst);
}

fn cli_alloc(_l: &mut UvLoop, suggested: usize, buf: &mut Buf) {
    buf.data = vec![0u8; suggested];
}

fn cli_read(_l: &mut UvLoop, nread: i64, buf: &mut Buf) {
    if nread < 0 {
        if nread == UV_EOF as i64 {
            CLI_EOF.store(true, Ordering::SeqCst);
        }
        return;
    }
    let n = nread as usize;
    let mut cb = CLI_BUF.lock().unwrap();
    let take = n.min(64 - 1 - cb.len());
    cb.extend_from_slice(&buf.data[..take]);
    CLI_TOTAL.fetch_add(n as i64, Ordering::SeqCst);
}

fn conn_content() -> String {
    String::from_utf8_lossy(&CONN_BUF.lock().unwrap()).into_owned()
}

fn cli_content() -> String {
    String::from_utf8_lossy(&CLI_BUF.lock().unwrap()).into_owned()
}

fn phase7_tcp(l: &mut UvLoop) -> Tcp {
    println!("=== PHASE 7: TCP ===");
    let mut srv = Handle(0);
    let mut cli = Handle(0);
    let mut conn = Handle(0);
    l.uv_tcp_init(&mut srv);
    l.uv_tcp_init(&mut cli);
    l.uv_tcp_init(&mut conn);
    println!(
        "  uv_tcp_bind(srv)={}",
        l.uv_tcp_bind(srv, &Addr::v4_loopback(0))
    );
    let mut port = 0;
    println!(
        "  uv_tcp_getsockname(srv)={}",
        l.uv_tcp_getsockname(srv, &mut port)
    );
    let a_addr = Addr::v4_loopback(port);
    *CONN_CELL.lock().unwrap() = conn;
    *SRV_H.lock().unwrap() = srv;
    let mk_srv_cb = || -> Cb {
        Box::new(move |l: &mut UvLoop| {
            ACCEPT_STATUS.store(0, Ordering::SeqCst);
            let srv_h = *SRV_H.lock().unwrap();
            let mut c = *CONN_CELL.lock().unwrap();
            let rc = l.uv_accept(srv_h, &mut c);
            ACCEPT_RC.store(rc, Ordering::SeqCst);
            *CONN_CELL.lock().unwrap() = c;
            let _ = l.uv_read_start(c, Box::new(conn_alloc), Box::new(conn_read));
        })
    };
    println!("  uv_listen(srv)={}", l.uv_listen(srv, 8, mk_srv_cb()));
    println!(
        "  uv_listen(srv) again={}",
        l.uv_listen(srv, 8, mk_srv_cb())
    );
    perr("  uv_accept(no pending)", l.uv_accept(srv, &mut conn));

    /* socket buffer size get/set/get roundtrip (srv is alive) */
    let mut bufsize = 0;
    let rc = l.uv_recv_buffer_size(srv, &mut bufsize);
    println!("  uv_recv_buffer_size(get)={rc} value={bufsize}");
    bufsize = 65536;
    let rc = l.uv_recv_buffer_size(srv, &mut bufsize);
    println!("  uv_recv_buffer_size(set 65536)={rc}");
    bufsize = 0;
    let rc = l.uv_recv_buffer_size(srv, &mut bufsize);
    println!("  uv_recv_buffer_size(get after set)={rc} value={bufsize}");
    bufsize = 0;
    let rc = l.uv_send_buffer_size(srv, &mut bufsize);
    println!("  uv_send_buffer_size(get)={rc} value={bufsize}");

    /* run 1: connect + accept (two fds, one poll round; the intra-round
     * order is unspecified, so the observations are printed in the fixed
     * order documented in the manifest) */
    let cb_cli_connect = Box::new(|_l: &mut UvLoop, status: i32| {
        CONNECT_STATUS.store(status, Ordering::SeqCst);
    }) as ConnectCb;
    let _ = l.uv_tcp_connect(cli, &a_addr, cb_cli_connect);
    arm_stop(l, &mut Handle(0));
    println!("  uv_run1(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    println!(
        "  [run1 fixed order] cli connect_cb status={}",
        sname(CONNECT_STATUS.load(Ordering::SeqCst))
    );
    println!(
        "  [run1 fixed order] srv accept_cb status={}; uv_accept rc={}",
        sname(ACCEPT_STATUS.load(Ordering::SeqCst)),
        sname(ACCEPT_RC.load(Ordering::SeqCst))
    );
    println!(
        "  [run1] conn read total={} content={} (nothing yet)",
        CONN_TOTAL.load(Ordering::SeqCst),
        conn_content()
    );

    /* write "ping" from the client; on a fresh loopback connection the
     * write completes immediately (the fast path) without entering the
     * write queue; the write_cb still fires via the pending pass */
    let b = b"ping".to_vec();
    let cli_h = cli;
    println!(
        "  queue size before uv_write={}",
        l.uv_stream_get_write_queue_size(cli)
    );
    let cb_cli_write = Box::new(move |l: &mut UvLoop, status: i32| {
        println!(
            "    cli write_cb status={} queue={}",
            sname(status),
            l.uv_stream_get_write_queue_size(cli_h)
        );
    }) as WriteCb;
    let _ = l.uv_write(cli, &[b.clone()], cb_cli_write);
    println!(
        "  queue size after uv_write={} (immediate write path)",
        l.uv_stream_get_write_queue_size(cli)
    );
    let n = l.uv_try_write(cli, &b);
    println!("  cli try_write returned {n} (second ping)");
    arm_stop(l, &mut Handle(0));
    println!("  uv_run2(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    println!(
        "  [run2] conn read total={} content={}",
        CONN_TOTAL.load(Ordering::SeqCst),
        conn_content()
    );

    /* server try_write -> synchronous byte count */
    let b2 = b"pong".to_vec();
    let n = l.uv_try_write(conn, &b2);
    println!("  conn try_write returned {n}");

    /* client reads the pong (already in the buffer), then the shutdown
     * writes the FIN -> the client reads EOF; the shutdown_cb is an
     * immediate callback */
    let _ = l.uv_read_start(cli, Box::new(cli_alloc), Box::new(cli_read));
    let cb_conn_shutdown = Box::new(|_l: &mut UvLoop, status: i32| {
        SHUTDOWN_STATUS.store(status, Ordering::SeqCst);
    }) as ShutdownCb;
    println!(
        "  uv_shutdown(conn)={}",
        l.uv_shutdown(conn, cb_conn_shutdown)
    );
    arm_stop(l, &mut Handle(0));
    println!("  uv_run3(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    println!(
        "  [run3] conn shutdown_cb status={}",
        sname(SHUTDOWN_STATUS.load(Ordering::SeqCst))
    );
    println!(
        "  [run3] cli read total={} content={}",
        CLI_TOTAL.load(Ordering::SeqCst),
        cli_content()
    );
    println!(
        "  [run3] cli read nread={} (EOF)",
        if CLI_EOF.load(Ordering::SeqCst) {
            "UV_EOF"
        } else {
            "MISSING"
        }
    );

    /* connect to a closed port -> ECONNREFUSED in the connect_cb */
    let mut cli2 = Handle(0);
    l.uv_tcp_init(&mut cli2);
    let cli2_h = cli2;
    let cb_cli2_connect = Box::new(move |l: &mut UvLoop, status: i32| {
        println!("    cli2 connect_cb status={}", sname(status));
        l.uv_close(
            cli2_h,
            Some(Box::new(|_l: &mut UvLoop| println!("    cli2 close_cb"))),
        );
    }) as ConnectCb;
    let _ = l.uv_tcp_connect(cli2, &Addr::v4_loopback(1), cb_cli2_connect);
    arm_stop(l, &mut Handle(0));
    println!("  uv_run4(DEFAULT) returned {}", l.uv_run(RunMode::Default));

    let cb_conn_close = Box::new(|_l: &mut UvLoop| println!("    conn close_cb"));
    let cb_cli_close = Box::new(|_l: &mut UvLoop| println!("    cli close_cb"));
    let cb_srv_close = Box::new(|_l: &mut UvLoop| println!("    srv close_cb"));
    let _ = l.uv_tcp_close_reset(conn, cb_conn_close);
    l.uv_close(cli, Some(cb_cli_close));
    l.uv_close(srv, Some(cb_srv_close));
    arm_stop(l, &mut Handle(0));
    println!("  uv_run5(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    srv
}

// ---------------------------------------------------------------------------
// phase 8: handle utilities (fresh loop)
// ---------------------------------------------------------------------------

static WALK_COUNT: AtomicI32 = AtomicI32::new(0);

fn walk_cb(l: &UvLoop, h: Handle, ty: HandleType) {
    WALK_COUNT.fetch_add(1, Ordering::SeqCst);
    println!(
        "    walk: {} active={} closing={}",
        ty.name(),
        l.uv_is_active(h),
        l.uv_is_closing(h)
    );
}

fn phase8_handles(l2: &mut UvLoop, srv: Tcp) {
    println!("=== PHASE 8: handle utilities ===");
    let mut loop8 = UvLoop::default();
    loop8.uv_loop_init();
    let mut w_t = Handle(0);
    let mut w_p = Handle(0);
    let mut w_a = Handle(0);
    loop8.uv_timer_init(&mut w_t);
    loop8.uv_prepare_init(&mut w_p);
    loop8.uv_async_init(&mut w_a, Box::new(|_| {}));
    let _ = loop8.uv_timer_start(w_t, Some(Box::new(|_| {})), 1000, 0);
    let _ = loop8.uv_prepare_start(w_p, Box::new(|_| {}));
    WALK_COUNT.store(0, Ordering::SeqCst);
    loop8.uv_walk(walk_cb);
    println!("  walked {} handles", WALK_COUNT.load(Ordering::SeqCst));

    loop8.uv_timer_stop(w_t);
    loop8.uv_prepare_stop(w_p);
    loop8.uv_close(w_t, None);
    loop8.uv_close(w_p, None);
    loop8.uv_close(w_a, None);
    println!("  is_closing before run={}", loop8.uv_is_closing(w_t));
    println!(
        "  uv_run(NOWAIT) returned {}",
        loop8.uv_run(RunMode::Nowait)
    );

    /* close_cb LIFO order: c1,c2,c3 closed -> c3,c2,c1 (same print) */
    let mut c1 = Handle(0);
    let mut c2 = Handle(0);
    let mut c3 = Handle(0);
    loop8.uv_timer_init(&mut c1);
    loop8.uv_timer_init(&mut c2);
    loop8.uv_timer_init(&mut c3);
    let _ = loop8.uv_timer_start(c1, Some(Box::new(|_| {})), 1000, 0);
    let _ = loop8.uv_timer_start(c2, Some(Box::new(|_| {})), 1000, 0);
    let _ = loop8.uv_timer_start(c3, Some(Box::new(|_| {})), 1000, 0);
    loop8.uv_close(
        c1,
        Some(Box::new(|_l: &mut UvLoop| println!("    close_cb: timer"))),
    );
    loop8.uv_close(
        c2,
        Some(Box::new(|_l: &mut UvLoop| println!("    close_cb: timer"))),
    );
    loop8.uv_close(
        c3,
        Some(Box::new(|_l: &mut UvLoop| println!("    close_cb: timer"))),
    );
    println!(
        "  uv_run(NOWAIT) returned {}",
        loop8.uv_run(RunMode::Nowait)
    );

    /* fileno: timer -> EINVAL; closed tcp (srv, phase 7, owned by loop2)
     * -> EBADF */
    let rc = match loop8.uv_fileno(c1) {
        Ok(_) => 0,
        Err(e) => e,
    };
    perr("  uv_fileno(timer)", rc);
    let rc = match l2.uv_fileno(srv) {
        Ok(_) => 0,
        Err(e) => e,
    };
    println!("  uv_fileno(closed tcp)={rc}");
    let mut bs = 0;
    let rc = l2.uv_recv_buffer_size(srv, &mut bs);
    println!("  uv_recv_buffer_size(closed) rc={}", uv_err_name(rc));
    println!("  uv_loop_close(walk loop)={}", loop8.uv_loop_close());
}

// ---------------------------------------------------------------------------
// phase 9: dlopen
// ---------------------------------------------------------------------------

fn phase9_dl() {
    println!("=== PHASE 9: dl ===");
    let mut lib = match uv_dlopen("/lib/x86_64-linux-gnu/libc.so.6") {
        Ok(l) => {
            println!("  uv_dlopen(libc)=0");
            l
        }
        Err(l) => {
            println!("  uv_dlopen(libc)=-1");
            l
        }
    };
    println!(
        "  uv_dlsym(getpid)={}",
        match uv_dlsym(&mut lib, "getpid") {
            Ok(()) => 0,
            Err(c) => c,
        }
    );
    println!(
        "  uv_dlsym(bogus symbol)={}",
        match uv_dlsym(&mut lib, "getpid_bogus") {
            Ok(()) => 0,
            Err(c) => c,
        }
    );
    println!("  uv_dlerror: {}", uv_dlerror(&lib));
    uv_dlclose(&mut lib);
    println!("  dlclose ok");
    let mut lib2 = match uv_dlopen("/nonexistent/lib.so") {
        Ok(l) => {
            println!("  uv_dlopen(nonexistent)=0");
            l
        }
        Err(l) => {
            println!("  uv_dlopen(nonexistent)=-1");
            l
        }
    };
    println!("  uv_dlerror: {}", uv_dlerror(&lib2));
    uv_dlclose(&mut lib2);
    println!("  dlclose ok");
}

// ---------------------------------------------------------------------------
// phase 10: random + sleep
// ---------------------------------------------------------------------------

fn phase10_random(l: &mut UvLoop) {
    println!("=== PHASE 10: random + sleep ===");
    let r = uv_random(
        l,
        16,
        Box::new(|_l: &mut UvLoop, status: i32, len: usize| {
            println!("    random cb status={} len={len}", sname(status));
        }),
    );
    println!("  uv_random={r}");
    arm_stop(l, &mut Handle(0));
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    uv_sleep(30);
    println!("  slept 30ms");
}

// ---------------------------------------------------------------------------
// phase 12: barrier
// ---------------------------------------------------------------------------

static HELPER_RC: AtomicI32 = AtomicI32::new(-1);

fn phase12_barrier() {
    println!("=== PHASE 12: barrier ===");
    /* NOTE: on glibc uv_barrier_init is a bare pthread_barrier_init (no
     * NULL guard), so only the count==0 EINVAL is portable */
    let mut bar = Barrier::default();
    perr("  uv_barrier_init(&b, 0)", uv_barrier_init(&mut bar, 0));
    println!("  uv_barrier_init(&b, 2)={}", uv_barrier_init(&mut bar, 2));
    let mut bar = Arc::new(bar);
    let bar_h = bar.clone();
    let helper = std::thread::spawn(move || {
        let rc = uv_barrier_wait(&bar_h);
        HELPER_RC.store(rc, Ordering::SeqCst);
    });
    uv_sleep(20); /* the helper is blocked on the barrier by now */
    println!("  main uv_barrier_wait={}", uv_barrier_wait(&bar));
    helper.join().unwrap();
    println!(
        "  helper uv_barrier_wait={} (serial=1 on the last releaser)",
        HELPER_RC.load(Ordering::SeqCst)
    );
    let bar_mut = Arc::get_mut(&mut bar).unwrap();
    uv_barrier_destroy(bar_mut);
    println!("  barrier destroyed");
}

// ---------------------------------------------------------------------------
// phase 13: allocator
// ---------------------------------------------------------------------------

static M_ALLOC: AtomicI32 = AtomicI32::new(0);
static M_REALLOC: AtomicI32 = AtomicI32::new(0);
static M_CALLOC: AtomicI32 = AtomicI32::new(0);
static M_FREE: AtomicI32 = AtomicI32::new(0);

fn my_malloc(_size: usize) -> *mut c_void {
    M_ALLOC.fetch_add(1, Ordering::SeqCst);
    std::ptr::null_mut()
}
fn my_realloc(_ptr: *mut c_void, _size: usize) -> *mut c_void {
    M_REALLOC.fetch_add(1, Ordering::SeqCst);
    std::ptr::null_mut()
}
fn my_calloc(_n: usize, _size: usize) -> *mut c_void {
    M_CALLOC.fetch_add(1, Ordering::SeqCst);
    std::ptr::null_mut()
}
fn my_free(_ptr: *mut c_void) {
    M_FREE.fetch_add(1, Ordering::SeqCst);
}

fn phase13_allocator() {
    println!("=== PHASE 13: allocator ===");
    M_ALLOC.store(0, Ordering::SeqCst);
    M_REALLOC.store(0, Ordering::SeqCst);
    M_CALLOC.store(0, Ordering::SeqCst);
    M_FREE.store(0, Ordering::SeqCst);
    perr(
        "  uv_replace_allocator(NULLs)",
        uv_replace_allocator(None, None, None, None),
    );
    println!(
        "  uv_replace_allocator(custom)={}",
        uv_replace_allocator(
            Some(my_malloc),
            Some(my_realloc),
            Some(my_calloc),
            Some(my_free)
        )
    );
    /* every libuv allocation now goes through the customs: uv_loop_init
     * callocs the internal fields exactly once and reallocs the watchers
     * array once; uv_loop_close frees both */
    let mut aloop = UvLoop::default();
    println!("  uv_loop_init after replace={}", aloop.uv_loop_init());
    println!(
        "  counts after loop_init malloc={} realloc={} calloc={} free={}",
        M_ALLOC.load(Ordering::SeqCst),
        M_REALLOC.load(Ordering::SeqCst),
        M_CALLOC.load(Ordering::SeqCst),
        M_FREE.load(Ordering::SeqCst)
    );
    println!("  uv_loop_close after replace={}", aloop.uv_loop_close());
    println!(
        "  counts after loop_close malloc={} realloc={} calloc={} free={}",
        M_ALLOC.load(Ordering::SeqCst),
        M_REALLOC.load(Ordering::SeqCst),
        M_CALLOC.load(Ordering::SeqCst),
        M_FREE.load(Ordering::SeqCst)
    );
}

// ---------------------------------------------------------------------------
// phase 15: uv_stop + run-return semantics
// ---------------------------------------------------------------------------

static ST1_FIRED: AtomicI32 = AtomicI32::new(0);

fn phase15_stop(l: &mut UvLoop) {
    println!("=== PHASE 15: uv_stop ===");
    let mut st1 = Handle(0);
    let mut st2 = Handle(0);
    l.uv_timer_init(&mut st1);
    l.uv_timer_init(&mut st2);
    let _ = l.uv_timer_start(
        st1,
        Some(Box::new(move |l: &mut UvLoop| {
            ST1_FIRED.fetch_add(1, Ordering::SeqCst);
            println!("    st1 fired; calling uv_stop");
            l.uv_stop();
        })),
        10,
        0,
    );
    let _ = l.uv_timer_start(st2, Some(Box::new(|_| println!("    st2 fired"))), 20, 0);
    println!(
        "  uv_run(DEFAULT) returned {} (alive: st2 still pending)",
        l.uv_run(RunMode::Default)
    );
    println!("  uv_run(DEFAULT) returned {}", l.uv_run(RunMode::Default));
    println!("  st1 fired {} time(s)", ST1_FIRED.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------
// phase 16: cancel
// ---------------------------------------------------------------------------

fn phase16_cancel() {
    println!("=== PHASE 16: uv_cancel ===");
    /* non-work request types are UV_EINVAL in 1.52.1 (threadpool.c) */
    perr("  uv_cancel(completed WRITE req)", uv_cancel_write_req());
    /* a completed RANDOM work req is no longer cancellable -> UV_EBUSY */
    perr(
        "  uv_cancel(completed RANDOM req)",
        uv_cancel_random_completed(),
    );
}

// ---------------------------------------------------------------------------
// phase 17: error battery
// ---------------------------------------------------------------------------

macro_rules! err {
    ($name:ident) => {{
        let n = stringify!($name);
        let e = code_of(n);
        println!(
            "  UV_{:<14} {:<6} {} | {}",
            n,
            e,
            uv_err_name(e),
            uv_strerror(e)
        );
    }};
}

fn phase17_errors() {
    println!("=== PHASE 17: error battery ===");
    err!(E2BIG);
    err!(EACCES);
    err!(EADDRINUSE);
    err!(EADDRNOTAVAIL);
    err!(EAFNOSUPPORT);
    err!(EAGAIN);
    err!(EAI_ADDRFAMILY);
    err!(EAI_AGAIN);
    err!(EAI_BADFLAGS);
    err!(EAI_BADHINTS);
    err!(EAI_CANCELED);
    err!(EAI_FAIL);
    err!(EAI_FAMILY);
    err!(EAI_MEMORY);
    err!(EAI_NODATA);
    err!(EAI_NONAME);
    err!(EAI_OVERFLOW);
    err!(EAI_PROTOCOL);
    err!(EAI_SERVICE);
    err!(EAI_SOCKTYPE);
    err!(EALREADY);
    err!(EBADF);
    err!(EBUSY);
    err!(ECANCELED);
    err!(ECHARSET);
    err!(ECONNABORTED);
    err!(ECONNREFUSED);
    err!(ECONNRESET);
    err!(EDESTADDRREQ);
    err!(EEXIST);
    err!(EFAULT);
    err!(EFBIG);
    err!(EHOSTUNREACH);
    err!(EINTR);
    err!(EINVAL);
    err!(EIO);
    err!(EISCONN);
    err!(EISDIR);
    err!(ELOOP);
    err!(EMFILE);
    err!(EMSGSIZE);
    err!(ENAMETOOLONG);
    err!(ENETDOWN);
    err!(ENETUNREACH);
    err!(ENFILE);
    err!(ENOBUFS);
    err!(ENODEV);
    err!(ENOENT);
    err!(ENOMEM);
    err!(ENONET);
    err!(ENOPROTOOPT);
    err!(ENOSPC);
    err!(ENOSYS);
    err!(ENOTCONN);
    err!(ENOTDIR);
    err!(ENOTEMPTY);
    err!(ENOTSOCK);
    err!(ENOTSUP);
    err!(EOVERFLOW);
    err!(EPERM);
    err!(EPIPE);
    err!(EPROTO);
    err!(EPROTONOSUPPORT);
    err!(EPROTOTYPE);
    err!(ERANGE);
    err!(EROFS);
    err!(ESHUTDOWN);
    err!(ESPIPE);
    err!(ESRCH);
    err!(ETIMEDOUT);
    err!(ETXTBSY);
    err!(EXDEV);
    err!(UNKNOWN);
    err!(EOF);
    err!(ENXIO);
    err!(EMLINK);
    err!(EHOSTDOWN);
    err!(EREMOTEIO);
    err!(ENOTTY);
    err!(EFTYPE);
    err!(EILSEQ);
    err!(ESOCKTNOSUPPORT);
    err!(ENODATA);
    err!(EUNATCH);
    err!(ENOEXEC);
    {
        let e = -12345;
        println!(
            "  UV_UNKNOWN-12345   {:<6} {} | {}",
            e,
            uv_err_name(e),
            uv_strerror(e)
        );
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== PHASE 0: version ===");
    println!("  uv_version={}", uv_version());
    println!("  uv_version_string={}", uv_version_string());

    println!("=== PHASE 1: loop basics ===");
    let mut loop1 = UvLoop::default();
    println!("  uv_loop_init={}", loop1.uv_loop_init());
    println!("  uv_run(NOWAIT, empty)={}", loop1.uv_run(RunMode::Nowait));
    println!("  uv_loop_alive={}", loop1.uv_loop_alive());
    println!("  uv_loop_close={}", loop1.uv_loop_close());

    let mut loop2 = UvLoop::default();
    loop2.uv_loop_init();
    phase2_timers(&mut loop2);
    phase3_watchers(&mut loop2);
    phase4_async(&mut loop2);
    phase5_signal(&mut loop2);
    phase6_udp(&mut loop2);
    let srv = phase7_tcp(&mut loop2);
    phase8_handles(&mut loop2, srv);
    phase9_dl();
    phase10_random(&mut loop2);
    phase12_barrier();
    phase15_stop(&mut loop2);
    phase16_cancel();
    /* the leftover handles (never closed) make this UV_EBUSY */
    println!(
        "  uv_loop_close(loop2 with leftover handles)={} (EBUSY)",
        loop2.uv_loop_close()
    );
    phase17_errors();
    phase13_allocator();
    uv_library_shutdown();
    println!("  uv_library_shutdown called");
}
