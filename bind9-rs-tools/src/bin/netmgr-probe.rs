//! netmgr-probe — the netmgr court probe (court NETMGR-0001).
//!
//! A deterministic op sequence over the public `isc_nm_*` surface BIND 9.20's
//! query pipeline depends on, plus internal-state observations through
//! netmgr-int.h.  Both the C probe (`forensics/oracle/probes/probe-netmgr.c`)
//! and this Rust mirror run in the SAME `oracle-bind-9.20.26` container;
//! stdout must be byte-identical.
//!
//! Transcript determinism contract (mirrored from the C probe):
//!  - only logical events, byte contents, sizes, results and internal state
//!    values are printed; never wall-clock values, kernel-assigned ports,
//!    fds, pointers, pids or thread ids (the loop tids 0/1/2 are fixed by
//!    construction);
//!  - every address is the loopback literal 127.0.0.1 with a fixed port;
//!    client source ports are fixed so the server sees deterministic peer
//!    addresses;
//!  - the loop manager runs 3 loops; loops 1 and 2 are idle except for the
//!    load-balance phase, whose callbacks never print (only aggregate
//!    counters are printed, from the loop-0 client side);
//!  - the one genuinely unspecified intra-round order — the client's TCP
//!    connect_cb vs the server's accept_cb, two events of the same epoll
//!    round on the same loop — is recorded by each callback and printed by
//!    a chained job in a fixed documented order (connect first, then
//!    accept);
//!  - TCP stream reads are accumulated to a known message length before
//!    printing (the kernel may deliver a stream in arbitrary chunks);
//!  - every internal-state print happens on the socket's owning thread at
//!    a quiescent point (callback entry or a chained loop-0 job);
//!  - I/O is loopback and completes in microseconds; the idle loops 1/2
//!    print nothing, so the transcript order is fixed.

use bind9_rs_tools::compat::libuv::UvLoop;
use bind9_rs_tools::compat::netmgr::*;
use bind9_rs_tools::platform::linux as lx;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The loopmgr, parked for the phase-13 shutdown call (`isc_loopmgr_shutdown`).
static LOOPMGR: OnceLock<Loopmgr> = OnceLock::new();

// ---------------------------------------------------------------------------
// transcript helpers (the C probe's SNAME/PADDR/STYPE/next_job)
// ---------------------------------------------------------------------------

fn sname(r: Res) -> &'static str {
    r.name()
}

fn paddr(tag: &str, sa: SockAddr) -> String {
    format!("{}={}", tag, sa.fmt())
}

fn stype(t: SockKind) -> &'static str {
    t.name()
}

/// `isc_async_run(mainloop, cb, arg)`: chain the next phase driver on loop 0.
fn next_job(inner: &mut LoopInner, job: Job) {
    inner.async_dispatch(job);
}

// ---------------------------------------------------------------------------
// probe state (the C's file-scope statics)
// ---------------------------------------------------------------------------

struct ProbeState {
    udp_listen_sock: Option<SocketId>,
    udp_keep: Option<HandleId>,
    udp_client_send: Option<HandleId>,
    udp_server_send: Option<HandleId>,
    udp_round: i32,
    udp_no_reply: bool,
    udp_blocked_send_calls: i32,

    tcp_listen_sock: Option<SocketId>,
    tcp_keep: Option<HandleId>,
    tcp_client_send: Option<HandleId>,
    tcp_server_send: Option<HandleId>,
    tcp_server_readhandle: Option<HandleId>,
    tcp_conn: i32,
    rec_conn_peer: SockAddr,
    rec_conn_local: SockAddr,
    rec_acc_peer: SockAddr,
    rec_acc_local: SockAddr,
    rec_conn_refs: i32,
    rec_conn_sock_refs: i32,
    rec_conn_ready: bool,
    rec_acc_ready: bool,
    rec_conn_ah: u32,
    rec_acc_ah: u32,
    rec_conn_connected: bool,
    rec_acc_client: bool,
    tcp_big_server_got: usize,
    tcp_big_client_got: usize,
    tcp_conn3_recv_calls: i32,

    lb_udp_sock: Option<SocketId>,
    lb_tcp_sock: Option<SocketId>,
    lb_keep: Option<HandleId>,
    lb_send: Option<HandleId>,
    lb_udp_round: i32,
    lb_tcp_round: i32,
    lb_send_data: Vec<u8>,
}

static ST: Mutex<ProbeState> = Mutex::new(ProbeState {
    udp_listen_sock: None,
    udp_keep: None,
    udp_client_send: None,
    udp_server_send: None,
    udp_round: 0,
    udp_no_reply: false,
    udp_blocked_send_calls: 0,

    tcp_listen_sock: None,
    tcp_keep: None,
    tcp_client_send: None,
    tcp_server_send: None,
    tcp_server_readhandle: None,
    tcp_conn: 0,
    rec_conn_peer: SockAddr::loopback(0),
    rec_conn_local: SockAddr::loopback(0),
    rec_acc_peer: SockAddr::loopback(0),
    rec_acc_local: SockAddr::loopback(0),
    rec_conn_refs: 0,
    rec_conn_sock_refs: 0,
    rec_conn_ready: false,
    rec_acc_ready: false,
    rec_conn_ah: 0,
    rec_acc_ah: 0,
    rec_conn_connected: false,
    rec_acc_client: false,
    tcp_big_server_got: 0,
    tcp_big_client_got: 0,
    tcp_conn3_recv_calls: 0,

    lb_udp_sock: None,
    lb_tcp_sock: None,
    lb_keep: None,
    lb_send: None,
    lb_udp_round: 0,
    lb_tcp_round: 0,
    lb_send_data: Vec::new(),
});

/// `atomic_int_fast64_t lb_tcp_accepts` — bumped on any worker loop.
static LB_TCP_ACCEPTS: AtomicI64 = AtomicI64::new(0);

// ---------------------------------------------------------------------------
// phase 1: netmgr lifecycle
// ---------------------------------------------------------------------------

fn phase1_setup(inner: &mut LoopInner, _l: &mut UvLoop) {
    println!("tid={}", inner.tid());
    println!("nloops={}", inner.nm.nloops);

    let (init, idle, keepalive, advertised) = inner.nm.gettimeouts();
    println!(
        "default timeouts: init={init} idle={idle} keepalive={keepalive} advertised={advertised}"
    );
    println!(
        "getloadbalancesockets={}",
        if inner.nm.load_balance {
            "true"
        } else {
            "false"
        }
    );

    inner.nm.settimeouts(700, 800, 900, 1000);
    let (init, idle, keepalive, advertised) = inner.nm.gettimeouts();
    println!(
        "settimeouts(700,800,900,1000); gettimeouts: init={init} idle={idle} \
         keepalive={keepalive} advertised={advertised}"
    );

    inner.nm.setnetbuffers(1024, 2048, 4096, 8192);
    println!("setnetbuffers(1024,2048,4096,8192) ok");

    inner.nm.maxudp(0);
    println!("maxudp=0");

    println!("netmgr refs={}", inner.nm.refs());
    inner.nm.attach();
    println!("netmgr refs after attach={}", inner.nm.refs());
    inner.nm.detach();
    println!("netmgr refs after detach={}", inner.nm.refs());

    next_job(inner, Box::new(phase2_checkaddr));
}

// ---------------------------------------------------------------------------
// phase 2: isc_nm_checkaddr
// ---------------------------------------------------------------------------

fn phase2_checkaddr(inner: &mut LoopInner, _l: &mut UvLoop) {
    println!("=== PHASE 2: isc_nm_checkaddr ===");

    let addr = SockAddr::loopback(19153);

    let r = NetmgrShared::checkaddr(addr, SockType::Tcp);
    println!("checkaddr(127.0.0.1#19153, tcp) -> {}", sname(r));

    let fd = lx::socket(libc::AF_INET, libc::SOCK_STREAM, 0).expect("socket");
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 19153u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be(0x7f00_0001),
        },
        sin_zero: [0; 8],
    };
    lx::bind(fd, &sin).expect("bind");
    println!("bound a plain tcp socket to 19153");

    let r = NetmgrShared::checkaddr(addr, SockType::Tcp);
    println!("checkaddr(127.0.0.1#19153, tcp) -> {}", sname(r));

    lx::close(fd);
    println!("closed the plain socket");

    let r = NetmgrShared::checkaddr(addr, SockType::Tcp);
    println!("checkaddr(127.0.0.1#19153, tcp) -> {}", sname(r));

    let r = NetmgrShared::checkaddr(addr, SockType::Raw);
    println!("checkaddr(127.0.0.1#19153, raw) -> {}", sname(r));

    next_job(inner, Box::new(phase3_udp));
}

// ---------------------------------------------------------------------------
// phase 3: UDP echo (LISTEN_ONE)
// ---------------------------------------------------------------------------

fn udp_client_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!(
        "  client send cb: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().udp_client_send);
    println!(
        "  client send cb: after detach refs={}",
        inner.handle_refs(handle)
    );
}

fn udp_server_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, _eresult: i32) {
    println!(
        "  server send cb: handle refs={}",
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().udp_server_send);
}

fn udp_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    peer: Option<SockAddr>,
) {
    if eresult != 0 {
        return;
    }
    let mut echo = data.clone();
    if ST.lock().unwrap().udp_no_reply {
        println!(
            "  server recv: data=\"{}\" (no reply)",
            String::from_utf8_lossy(&data)
        );
        return;
    }

    print!(
        "  server recv: data=\"{}\" ",
        String::from_utf8_lossy(&data)
    );
    print!("{}", paddr("peer", peer.unwrap()));
    let sock = inner.handle_sock(handle);
    println!(
        " handle refs={} sock refs={} active_handles={}",
        inner.handle_refs(handle),
        inner.sock_refs(sock),
        inner.sock_active_handles(sock)
    );

    /* echo back (upper-cased first byte) */
    if !echo.is_empty() {
        echo[0] ^= 0x20;
    }
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().udp_server_send = Some(send_h);
    inner.send(l, send_h, &echo, Box::new(udp_server_send_cb));
}

fn udp_client_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} data=\"{}\" handle refs={}",
        sname(code_to_res(eresult)),
        String::from_utf8_lossy(&data),
        inner.handle_refs(handle)
    );

    if eresult != 0 {
        return;
    }

    /* a UDP client gets exactly one datagram per isc_nm_read; re-arm */
    inner.read(l, handle, Box::new(udp_client_recv_cb));

    let mut st = ST.lock().unwrap();
    st.udp_round += 1;
    if st.udp_round < 3 {
        let msg = format!("ping-{}", st.udp_round + 1);
        let send_h = inner.handle_attach(handle);
        st.udp_client_send = Some(send_h);
        inner.send(l, send_h, msg.as_bytes(), Box::new(udp_client_send_cb));
        println!("  client sent \"{}\"", msg);
    } else {
        let sock = inner.handle_sock(handle);
        println!(
            "  client state: handle refs={} sock refs={} statichandle={} active_handles={}",
            inner.handle_refs(handle),
            inner.sock_refs(sock),
            if inner.sock_statichandle(sock) {
                "true"
            } else {
                "false"
            },
            inner.sock_active_handles(sock)
        );
        drop(st);
        next_job(inner, Box::new(phase4_maxudp));
    }
}

fn udp_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
    if eresult != 0 {
        return;
    }
    let sock = inner.handle_sock(handle);

    println!(
        "    {} {} is_stream={} netmgr_match={}",
        paddr("handle peer", inner.handle_peer(handle)),
        paddr("local", inner.handle_local(handle)),
        if inner.handle_is_stream(handle) {
            "true"
        } else {
            "false"
        },
        if inner.handle_netmgr_match(handle) {
            "true"
        } else {
            "false"
        }
    );
    println!("    handle refs={} (entry)", inner.handle_refs(handle));
    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().udp_keep = Some(keep);
    println!("    handle refs after attach={}", inner.handle_refs(handle));
    println!(
        "    client sock: refs={} active={} connected={} connecting={} reading={} \
         statichandle={} active_handles={}",
        inner.sock_refs(sock),
        if inner.sock_active(sock) {
            "true"
        } else {
            "false"
        },
        if inner.sock_connected(sock) {
            "true"
        } else {
            "false"
        },
        if inner.sock_connecting(sock) {
            "true"
        } else {
            "false"
        },
        if inner.sock_reading(sock) {
            "true"
        } else {
            "false"
        },
        if inner.sock_statichandle(sock) {
            "true"
        } else {
            "false"
        },
        inner.sock_active_handles(sock)
    );

    inner.read(l, handle, Box::new(udp_client_recv_cb));
    println!(
        "    read started; timer_running={}",
        if inner.socket_timer_running(sock) {
            "true"
        } else {
            "false"
        }
    );

    let msg = b"ping-1";
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().udp_client_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(udp_client_send_cb));
    println!("  client sent \"ping-1\"");
}

fn phase3_udp(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 3: UDP echo (LISTEN_ONE) ===");

    let iface = SockAddr::loopback(19153);

    match inner.listenudp(l, 1, iface, Box::new(udp_server_recv_cb)) {
        Ok(sid) => {
            ST.lock().unwrap().udp_listen_sock = Some(sid);
            println!("listenudp(workers=1, 127.0.0.1#19153) -> success");
            println!(
                "  server type={} active={} closing={} closed={} nchildren={}",
                stype(inner.sock_kind(sid)),
                if inner.sock_active(sid) {
                    "true"
                } else {
                    "false"
                },
                if inner.sock_closing(sid) {
                    "true"
                } else {
                    "false"
                },
                if inner.sock_closed(sid) {
                    "true"
                } else {
                    "false"
                },
                inner.sock_nchildren(sid)
            );
            for i in 0..inner.sock_nchildren(sid) {
                println!(
                    "  child[{}]: tid={} result={}",
                    i,
                    inner.sock_child_tid(sid, i as usize),
                    sname(inner.sock_child_result(sid, i as usize))
                );
            }
        }
        Err(e) => {
            println!("listenudp(workers=1, 127.0.0.1#19153) -> {}", sname(e));
            return;
        }
    }

    let local = SockAddr::loopback(19155);
    println!("udpconnect(local=127.0.0.1#19155 -> 127.0.0.1#19153, timeout=5000)");
    inner.udpconnect(l, local, iface, Box::new(udp_connect_cb), 5000);
}

// ---------------------------------------------------------------------------
// phase 4: UDP maxudp firewall simulation
// ---------------------------------------------------------------------------

fn udp_blocked_send_cb(_inner: &mut LoopInner, _l: &mut UvLoop, _handle: HandleId, _eresult: i32) {
    ST.lock().unwrap().udp_blocked_send_calls += 1;
}

fn udp_ok_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    _handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} data=\"{}\"",
        sname(code_to_res(eresult)),
        String::from_utf8_lossy(&data)
    );
    if eresult == 0 && data.len() == 2 && &data[..] == b"Ok" {
        /* close the phase-3/4 client before the next connection */
        inner.handle_detach(l, &mut ST.lock().unwrap().udp_keep);
        next_job(inner, Box::new(phase5_timeout));
    }
}

fn phase4_maxudp(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 4: UDP maxudp firewall ===");

    inner.nm.maxudp(4);
    println!("maxudp=4");

    let big = b"1234567890";
    let handle = ST.lock().unwrap().udp_keep.unwrap();
    ST.lock().unwrap().udp_blocked_send_calls = 0;
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().udp_client_send = Some(send_h);
    inner.send(l, send_h, &big[..10], Box::new(udp_blocked_send_cb));
    /* the blocked send consumed our ref (isc__nm_udp_send detached the
     * handle internally); the send cb never fires, so drop the pointer */
    ST.lock().unwrap().udp_client_send = None;
    println!(
        "  send 10 bytes while maxudp=4: blocked, send cb calls={}",
        ST.lock().unwrap().udp_blocked_send_calls
    );

    inner.nm.maxudp(0);
    println!("maxudp=0");

    inner.read(l, handle, Box::new(udp_ok_recv_cb));
    let ok = b"ok";
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().udp_client_send = Some(send_h);
    inner.send(l, send_h, ok, Box::new(udp_client_send_cb));
    println!("  client sent \"ok\"");
}

// ---------------------------------------------------------------------------
// phase 5: UDP read timeout
// ---------------------------------------------------------------------------

fn udp_timeout_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    _data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    if eresult == -1 {
        /* ISC_R_TIMEDOUT */
        inner.handle_detach(l, &mut ST.lock().unwrap().udp_keep);
        next_job(inner, Box::new(phase6_cancelread));
    }
}

fn udp_timeout_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
    if eresult != 0 {
        return;
    }
    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().udp_keep = Some(keep);
    inner.read(l, handle, Box::new(udp_timeout_recv_cb));
    let msg = b"no-reply";
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().udp_client_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(udp_client_send_cb));
    println!("  client sent \"no-reply\" (read timeout=50ms)");
}

fn phase5_timeout(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 5: UDP read timeout ===");
    {
        let mut st = ST.lock().unwrap();
        st.udp_round = 0;
        st.udp_no_reply = true;
    }

    let local = SockAddr::loopback(19156);
    let peer = SockAddr::loopback(19153);
    inner.udpconnect(l, local, peer, Box::new(udp_timeout_connect_cb), 50);
}

// ---------------------------------------------------------------------------
// phase 6: UDP cancelread
// ---------------------------------------------------------------------------

fn udp_cancel_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    _data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    if eresult == -2 {
        /* ISC_R_CANCELED */
        inner.handle_detach(l, &mut ST.lock().unwrap().udp_keep);
        next_job(inner, Box::new(phase7_udp_stop));
    }
}

fn udp_cancel_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
    if eresult != 0 {
        return;
    }
    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().udp_keep = Some(keep);
    inner.read(l, handle, Box::new(udp_cancel_recv_cb));
    println!("  read started; calling isc_nm_cancelread");
    inner.cancelread(l, handle);
}

fn phase6_cancelread(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 6: UDP cancelread ===");

    let local = SockAddr::loopback(19157);
    let peer = SockAddr::loopback(19153);
    inner.udpconnect(l, local, peer, Box::new(udp_cancel_connect_cb), 5000);
}

// ---------------------------------------------------------------------------
// phase 7: UDP stoplistening
// ---------------------------------------------------------------------------

fn phase7_udp_stop(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 7: UDP stoplistening ===");

    let sid = ST.lock().unwrap().udp_listen_sock.unwrap();
    inner.stoplistening(l, sid);
    println!(
        "  stoplistening: parent active={} closing={} closed={}",
        if inner.sock_active(sid) {
            "true"
        } else {
            "false"
        },
        if inner.sock_closing(sid) {
            "true"
        } else {
            "false"
        },
        if inner.sock_closed(sid) {
            "true"
        } else {
            "false"
        }
    );
    if inner.sock_nchildren(sid) > 0 {
        let (a, c, cl) = inner.sock_child_lifecycle(sid, 0);
        println!(
            "  child[0]: active={} closing={} closed={}",
            if a { "true" } else { "false" },
            if c { "true" } else { "false" },
            if cl { "true" } else { "false" }
        );
    }

    inner.nmsocket_close(l, &mut ST.lock().unwrap().udp_listen_sock);
    println!("  nmsocket_close ok");

    next_job(inner, Box::new(phase8_tcp));
}

// ---------------------------------------------------------------------------
// phase 8: TCP echo (LISTEN_ONE)
// ---------------------------------------------------------------------------

fn tcp_client_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!(
        "  client send cb: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().tcp_client_send);
}

/* print the recorded connect/accept pair in the fixed documented order */
fn tcp_print_pair(_inner: &mut LoopInner, _l: &mut UvLoop) {
    let st = ST.lock().unwrap();
    println!(
        "  connect cb: eresult=success {} {} is_stream=true handle refs={} \
         sock refs={} connected={} active_handles={}",
        paddr("peer", st.rec_conn_peer),
        paddr("local", st.rec_conn_local),
        st.rec_conn_refs,
        st.rec_conn_sock_refs,
        if st.rec_conn_connected {
            "true"
        } else {
            "false"
        },
        st.rec_conn_ah
    );
    println!(
        "  accept cb: eresult=success {} {} is_stream=true client={} active_handles={}",
        paddr("peer", st.rec_acc_peer),
        paddr("local", st.rec_acc_local),
        if st.rec_acc_client { "true" } else { "false" },
        st.rec_acc_ah
    );
}

fn tcp_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult == 0 {
        println!(
            "  server recv: data=\"{}\" handle refs={}",
            String::from_utf8_lossy(&data),
            inner.handle_refs(handle)
        );
        let mut echo = data.clone();
        if !echo.is_empty() {
            echo[0] ^= 0x20;
        }
        let send_h = inner.handle_attach(handle);
        ST.lock().unwrap().tcp_server_send = Some(send_h);
        inner.send(l, send_h, &echo, Box::new(tcp_server_send_cb));
    } else {
        println!("  server recv: eresult={}", sname(code_to_res(eresult)));
        inner.handle_detach(l, &mut Some(handle));
        next_job(inner, Box::new(phase8_conn2));
    }
}

fn tcp_server_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!(
        "  server send cb: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().tcp_server_send);
}

/* --- connection 1: small echo + timeout/keepalive observations --- */

fn tcp_conn1_client_done(inner: &mut LoopInner, l: &mut UvLoop) {
    let keep = ST.lock().unwrap().tcp_keep.unwrap();
    let sock = inner.handle_sock(keep);

    println!(
        "  client handle: timer_running={} read_timeout={}",
        if inner.handle_timer_running(keep) {
            "true"
        } else {
            "false"
        },
        inner.sock_read_timeout(sock)
    );
    inner.handle_cleartimeout(l, keep);
    println!(
        "  cleartimeout: timer_running={} read_timeout={}",
        if inner.handle_timer_running(keep) {
            "true"
        } else {
            "false"
        },
        inner.sock_read_timeout(sock)
    );
    inner.handle_settimeout(l, keep, 500);
    println!(
        "  settimeout(500): timer_running={} read_timeout={}",
        if inner.handle_timer_running(keep) {
            "true"
        } else {
            "false"
        },
        inner.sock_read_timeout(sock)
    );
    inner.handle_keepalive(keep, true);
    println!(
        "  keepalive(true): read_timeout={}",
        inner.sock_read_timeout(sock)
    );
    inner.handle_keepalive(keep, false);
    println!(
        "  keepalive(false): read_timeout={}",
        inner.sock_read_timeout(sock)
    );
    inner.handle_cleartimeout(l, keep);

    inner.handle_close(l, keep);
    inner.handle_detach(l, &mut ST.lock().unwrap().tcp_keep);
    println!("  client handle closed");
}

fn tcp_conn1_go(inner: &mut LoopInner, l: &mut UvLoop) {
    let keep = ST.lock().unwrap().tcp_keep.unwrap();
    let msg = b"tcp-1";
    let send_h = inner.handle_attach(keep);
    ST.lock().unwrap().tcp_client_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(tcp_client_send_cb));
    println!("  client sent \"tcp-1\"");
}

fn tcp_client_recv_cb(
    inner: &mut LoopInner,
    _l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} data=\"{}\" handle refs={}",
        sname(code_to_res(eresult)),
        String::from_utf8_lossy(&data),
        inner.handle_refs(handle)
    );

    if eresult != 0 {
        return;
    }
    if ST.lock().unwrap().tcp_conn == 1 {
        next_job(inner, Box::new(tcp_conn1_client_done));
    }
}

/* --- connection 2: large echo (uv_write path) --- */

fn tcp_big_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        println!("  server recv: eresult={}", sname(code_to_res(eresult)));
        inner.handle_detach(l, &mut Some(handle));
        next_job(inner, Box::new(phase8_conn3));
        return;
    }

    let mut st = ST.lock().unwrap();
    st.tcp_big_server_got += data.len();
    if st.tcp_big_server_got >= 131072 {
        println!("  server: received full message (131072 bytes)");
        let big = vec![b'E'; 131072];
        let send_h = inner.handle_attach(handle);
        st.tcp_server_send = Some(send_h);
        inner.send(l, send_h, &big, Box::new(tcp_server_send_cb));
    }
}

fn tcp_big_client_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    _handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        return;
    }
    let mut st = ST.lock().unwrap();
    st.tcp_big_client_got += data.len();
    if st.tcp_big_client_got >= 131072 {
        println!("  client: received full echo (131072 bytes)");
        let keep = st.tcp_keep.unwrap();
        inner.handle_close(l, keep);
        inner.handle_detach(l, &mut st.tcp_keep);
        println!("  client handle closed");
    }
}

fn tcp_conn2_go(inner: &mut LoopInner, l: &mut UvLoop) {
    let keep = ST.lock().unwrap().tcp_keep.unwrap();
    let big = vec![b'L'; 131072];
    let send_h = inner.handle_attach(keep);
    ST.lock().unwrap().tcp_client_send = Some(send_h);
    inner.send(l, send_h, &big, Box::new(tcp_client_send_cb));
    println!("  client sent 131072 bytes");
}

fn tcp_conn2_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    if eresult != 0 {
        println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
        return;
    }
    let sock = inner.handle_sock(handle);

    {
        let mut st = ST.lock().unwrap();
        st.rec_conn_peer = inner.handle_peer(handle);
        st.rec_conn_local = inner.handle_local(handle);
        st.rec_conn_refs = inner.handle_refs(handle) as i32;
        st.rec_conn_sock_refs = inner.sock_refs(sock) as i32;
        st.rec_conn_connected = inner.sock_connected(sock);
        st.rec_conn_ah = inner.sock_active_handles(sock);
        st.rec_conn_ready = true;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_keep = Some(keep);
    inner.read(l, handle, Box::new(tcp_big_client_recv_cb));

    let mut st = ST.lock().unwrap();
    if st.rec_conn_ready && st.rec_acc_ready {
        st.rec_conn_ready = false;
        st.rec_acc_ready = false;
        drop(st);
        next_job(inner, Box::new(tcp_print_pair));
        next_job(inner, Box::new(tcp_conn2_go));
    }
}

fn phase8_conn2(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 8b: TCP large echo (uv_write path) ===");
    {
        let mut st = ST.lock().unwrap();
        st.tcp_conn = 2;
        st.tcp_big_server_got = 0;
        st.tcp_big_client_got = 0;
    }

    let local = SockAddr::loopback(19161);
    let peer = SockAddr::loopback(19154);
    inner.tcpconnect(l, local, peer, Box::new(tcp_conn2_connect_cb), 5000);
}

/* --- connection 3: read_stop --- */

fn tcp_conn3_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        println!("  server recv: eresult={}", sname(code_to_res(eresult)));
        inner.handle_detach(l, &mut Some(handle));
        next_job(inner, Box::new(phase9_tcp_timeout));
        return;
    }

    println!(
        "  server recv: data=\"{}\" (holding handle)",
        String::from_utf8_lossy(&data)
    );
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_server_send = Some(send_h);
}

fn tcp_conn3_server_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!(
        "  server send cb: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().tcp_server_send);
    next_job(inner, Box::new(tcp_conn3_recheck));
}

fn tcp_conn3_server_send(inner: &mut LoopInner, l: &mut UvLoop) {
    let send_h = ST.lock().unwrap().tcp_server_send.unwrap();
    let stop1 = b"STOP1";
    inner.send(l, send_h, stop1, Box::new(tcp_conn3_server_send_cb));
    println!("  server sent \"STOP1\"");
}

fn tcp_conn3_stop_read(inner: &mut LoopInner, l: &mut UvLoop) {
    let keep = ST.lock().unwrap().tcp_keep.unwrap();
    inner.read_stop(l, keep);
    println!("  client read_stop ok");

    next_job(inner, Box::new(tcp_conn3_server_send));
}

fn tcp_conn3_client_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!(
        "  client send cb: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    inner.handle_detach(l, &mut ST.lock().unwrap().tcp_client_send);
    next_job(inner, Box::new(tcp_conn3_stop_read));
}

fn tcp_conn3_client_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    _handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    let mut st = ST.lock().unwrap();
    st.tcp_conn3_recv_calls += 1;
    println!(
        "  client recv: eresult={} data=\"{}\" calls={}",
        sname(code_to_res(eresult)),
        String::from_utf8_lossy(&data),
        st.tcp_conn3_recv_calls
    );
    if eresult == 0 && data.len() == 5 && &data[..] == b"STOP1" {
        let keep = st.tcp_keep.unwrap();
        inner.handle_close(l, keep);
        inner.handle_detach(l, &mut st.tcp_keep);
        println!("  client handle closed");
    }
}

fn tcp_conn3_recheck(inner: &mut LoopInner, l: &mut UvLoop) {
    let st = ST.lock().unwrap();
    println!(
        "  state: client recv calls={} (read stopped)",
        st.tcp_conn3_recv_calls
    );
    let keep = st.tcp_keep.unwrap();
    drop(st);
    inner.read(l, keep, Box::new(tcp_conn3_client_recv_cb));
    println!("  client re-read: data arrives");
}

fn tcp_conn3_go(inner: &mut LoopInner, l: &mut UvLoop) {
    let keep = ST.lock().unwrap().tcp_keep.unwrap();
    let msg = b"stop-test";
    let send_h = inner.handle_attach(keep);
    ST.lock().unwrap().tcp_client_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(tcp_conn3_client_send_cb));
    println!("  client sent \"stop-test\"");
}

fn tcp_conn3_client_connect_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
) {
    if eresult != 0 {
        println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
        return;
    }
    let sock = inner.handle_sock(handle);

    {
        let mut st = ST.lock().unwrap();
        st.rec_conn_peer = inner.handle_peer(handle);
        st.rec_conn_local = inner.handle_local(handle);
        st.rec_conn_refs = inner.handle_refs(handle) as i32;
        st.rec_conn_sock_refs = inner.sock_refs(sock) as i32;
        st.rec_conn_connected = inner.sock_connected(sock);
        st.rec_conn_ah = inner.sock_active_handles(sock);
        st.rec_conn_ready = true;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_keep = Some(keep);
    inner.read(l, handle, Box::new(tcp_conn3_client_recv_cb));

    let mut st = ST.lock().unwrap();
    if st.rec_conn_ready && st.rec_acc_ready {
        st.rec_conn_ready = false;
        st.rec_acc_ready = false;
        drop(st);
        next_job(inner, Box::new(tcp_print_pair));
        next_job(inner, Box::new(tcp_conn3_go));
    }
}

fn phase8_conn3(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 8c: TCP read_stop ===");
    {
        let mut st = ST.lock().unwrap();
        st.tcp_conn = 3;
        st.tcp_conn3_recv_calls = 0;
    }

    let local = SockAddr::loopback(19162);
    let peer = SockAddr::loopback(19154);
    inner.tcpconnect(l, local, peer, Box::new(tcp_conn3_client_connect_cb), 5000);
}

/* --- connection 1: connect + accept callbacks (used by phase 8) --- */

fn tcp_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    if eresult != 0 {
        println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
        return;
    }
    let sock = inner.handle_sock(handle);

    {
        let mut st = ST.lock().unwrap();
        st.rec_conn_peer = inner.handle_peer(handle);
        st.rec_conn_local = inner.handle_local(handle);
        st.rec_conn_refs = inner.handle_refs(handle) as i32;
        st.rec_conn_sock_refs = inner.sock_refs(sock) as i32;
        st.rec_conn_connected = inner.sock_connected(sock);
        st.rec_conn_ah = inner.sock_active_handles(sock);
        st.rec_conn_ready = true;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_keep = Some(keep);
    inner.read(l, handle, Box::new(tcp_client_recv_cb));

    let mut st = ST.lock().unwrap();
    if st.rec_conn_ready && st.rec_acc_ready {
        st.rec_conn_ready = false;
        st.rec_acc_ready = false;
        drop(st);
        next_job(inner, Box::new(tcp_print_pair));
        next_job(inner, Box::new(tcp_conn1_go));
    }
}

fn tcp_accept_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) -> i32 {
    if eresult != 0 {
        return eresult;
    }
    let sock = inner.handle_sock(handle);

    {
        let mut st = ST.lock().unwrap();
        st.rec_acc_peer = inner.handle_peer(handle);
        st.rec_acc_local = inner.handle_local(handle);
        st.rec_acc_ah = inner.sock_active_handles(sock);
        st.rec_acc_client = inner.sock_client(sock);
        st.rec_acc_ready = true;
    }

    /* the C's readhandle: a probe-held ref that keeps the connection's
     * handle alive across reads (passed as the cbarg) */
    let readhandle = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_server_readhandle = Some(readhandle);
    match ST.lock().unwrap().tcp_conn {
        1 => inner.read(l, handle, Box::new(tcp_server_recv_cb)),
        2 => inner.read(l, handle, Box::new(tcp_big_server_recv_cb)),
        3 => inner.read(l, handle, Box::new(tcp_conn3_server_recv_cb)),
        4 => inner.read(l, handle, Box::new(tcp_timeout_server_recv_cb)),
        _ => {}
    }

    0
}

fn phase8_tcp(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 8: TCP echo (LISTEN_ONE) ===");

    let iface = SockAddr::loopback(19154);

    match inner.listentcp(l, 1, iface, Box::new(tcp_accept_cb), 10) {
        Ok(sid) => {
            ST.lock().unwrap().tcp_listen_sock = Some(sid);
            println!("listentcp(workers=1, 127.0.0.1#19154, backlog=10) -> success");
            println!(
                "  server type={} active={} closing={} closed={} nchildren={}",
                stype(inner.sock_kind(sid)),
                if inner.sock_active(sid) {
                    "true"
                } else {
                    "false"
                },
                if inner.sock_closing(sid) {
                    "true"
                } else {
                    "false"
                },
                if inner.sock_closed(sid) {
                    "true"
                } else {
                    "false"
                },
                inner.sock_nchildren(sid)
            );
            for i in 0..inner.sock_nchildren(sid) {
                println!(
                    "  child[{}]: tid={} result={}",
                    i,
                    inner.sock_child_tid(sid, i as usize),
                    sname(inner.sock_child_result(sid, i as usize))
                );
            }
        }
        Err(e) => {
            println!(
                "listentcp(workers=1, 127.0.0.1#19154, backlog=10) -> {}",
                sname(e)
            );
            return;
        }
    }

    ST.lock().unwrap().tcp_conn = 1;
    let local = SockAddr::loopback(19160);
    let peer = SockAddr::loopback(19154);
    inner.tcpconnect(l, local, peer, Box::new(tcp_connect_cb), 5000);
}

// ---------------------------------------------------------------------------
// phase 9: TCP read timeout
// ---------------------------------------------------------------------------

fn tcp_timeout_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        println!("  server recv: eresult={}", sname(code_to_res(eresult)));
        inner.handle_detach(l, &mut Some(handle));
        return;
    }
    println!(
        "  server recv: data=\"{}\" (no reply)",
        String::from_utf8_lossy(&data)
    );
}

fn tcp_timeout_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    _data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    println!(
        "  client recv: eresult={} handle refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    if eresult == -1 {
        /* ISC_R_TIMEDOUT */
        inner.handle_detach(l, &mut ST.lock().unwrap().tcp_keep);
        next_job(inner, Box::new(phase10_refused));
    }
}

fn tcp_timeout_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    if eresult != 0 {
        println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
        return;
    }
    let sock = inner.handle_sock(handle);

    {
        let mut st = ST.lock().unwrap();
        st.rec_conn_peer = inner.handle_peer(handle);
        st.rec_conn_local = inner.handle_local(handle);
        st.rec_conn_refs = inner.handle_refs(handle) as i32;
        st.rec_conn_sock_refs = inner.sock_refs(sock) as i32;
        st.rec_conn_connected = inner.sock_connected(sock);
        st.rec_conn_ah = inner.sock_active_handles(sock);
        st.rec_conn_ready = true;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_keep = Some(keep);
    inner.handle_settimeout(l, handle, 50);
    inner.read(l, handle, Box::new(tcp_timeout_recv_cb));
    let msg = b"slow";
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().tcp_client_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(tcp_client_send_cb));
    println!("  client sent \"slow\" (read timeout=50ms)");

    let mut st = ST.lock().unwrap();
    if st.rec_conn_ready && st.rec_acc_ready {
        st.rec_conn_ready = false;
        st.rec_acc_ready = false;
        drop(st);
        next_job(inner, Box::new(tcp_print_pair));
    }
}

fn phase9_tcp_timeout(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 9: TCP read timeout ===");
    ST.lock().unwrap().tcp_conn = 4;

    let local = SockAddr::loopback(19163);
    let peer = SockAddr::loopback(19154);
    inner.tcpconnect(l, local, peer, Box::new(tcp_timeout_connect_cb), 5000);
}

// ---------------------------------------------------------------------------
// phase 10: TCP connect refused
// ---------------------------------------------------------------------------

fn tcp_refused_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    let _ = l;
    println!(
        "  connect cb: eresult={} handle=non-null refs={}",
        sname(code_to_res(eresult)),
        inner.handle_refs(handle)
    );
    next_job(inner, Box::new(phase11_tcp_stop));
}

fn phase10_refused(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 10: TCP connect refused ===");

    let local = SockAddr::loopback(19164);
    let peer = SockAddr::loopback(19159);
    inner.tcpconnect(l, local, peer, Box::new(tcp_refused_connect_cb), 5000);
}

// ---------------------------------------------------------------------------
// phase 11: TCP stoplistening
// ---------------------------------------------------------------------------

fn phase11_tcp_stop(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 11: TCP stoplistening ===");

    let sid = ST.lock().unwrap().tcp_listen_sock.unwrap();
    inner.stoplistening(l, sid);
    println!(
        "  stoplistening: parent active={} closing={} closed={}",
        if inner.sock_active(sid) {
            "true"
        } else {
            "false"
        },
        if inner.sock_closing(sid) {
            "true"
        } else {
            "false"
        },
        if inner.sock_closed(sid) {
            "true"
        } else {
            "false"
        }
    );
    if inner.sock_nchildren(sid) > 0 {
        let (a, c, cl) = inner.sock_child_lifecycle(sid, 0);
        println!(
            "  child[0]: active={} closing={} closed={}",
            if a { "true" } else { "false" },
            if c { "true" } else { "false" },
            if cl { "true" } else { "false" }
        );
    }

    inner.nmsocket_close(l, &mut ST.lock().unwrap().tcp_listen_sock);
    println!("  nmsocket_close ok");

    next_job(inner, Box::new(phase12_udp));
}

// ---------------------------------------------------------------------------
// phase 12: load-balanced listeners (LISTEN_ALL)
// ---------------------------------------------------------------------------

fn lb_udp_server_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, _eresult: i32) {
    inner.handle_detach(l, &mut Some(handle));
}

fn lb_udp_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        return;
    }
    /* echo back, no prints (runs on any worker loop) */
    let send_h = inner.handle_attach(handle);
    inner.send(l, send_h, &data, Box::new(lb_udp_server_send_cb));
}

fn lb_udp_client_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        return;
    }
    println!("  client recv: data=\"{}\"", String::from_utf8_lossy(&data));
    let mut st = ST.lock().unwrap();
    st.lb_udp_round += 1;
    if st.lb_udp_round < 3 {
        inner.read(l, handle, Box::new(lb_udp_client_recv_cb));
        let msg = format!("lb-{}", st.lb_udp_round + 1);
        let send_h = inner.handle_attach(handle);
        st.lb_send = Some(send_h);
        inner.send(l, send_h, msg.as_bytes(), Box::new(lb_udp_send_cb));
        println!("  client sent \"{}\"", msg);
    } else {
        println!("  UDP load balance: echoes={}", st.lb_udp_round);
        inner.handle_detach(l, &mut st.lb_keep);
        let lsid = st.lb_udp_sock.unwrap();
        drop(st);
        inner.stoplistening(l, lsid);
        inner.nmsocket_close(l, &mut ST.lock().unwrap().lb_udp_sock);
        next_job(inner, Box::new(phase12_tcp));
    }
}

fn lb_udp_send_cb(inner: &mut LoopInner, l: &mut UvLoop, _handle: HandleId, _eresult: i32) {
    inner.handle_detach(l, &mut ST.lock().unwrap().lb_send);
}

fn lb_udp_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    println!("  connect cb: eresult={}", sname(code_to_res(eresult)));
    if eresult != 0 {
        return;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().lb_keep = Some(keep);
    inner.read(l, handle, Box::new(lb_udp_client_recv_cb));

    let msg = b"lb-1";
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().lb_send = Some(send_h);
    inner.send(l, send_h, msg, Box::new(lb_udp_send_cb));
    println!("  client sent \"lb-1\"");
}

fn phase12_udp(inner: &mut LoopInner, l: &mut UvLoop) {
    println!("=== PHASE 12: load-balanced listeners (LISTEN_ALL) ===");
    print!("  UDP listen: ");

    let iface = SockAddr::loopback(19165);

    match inner.listenudp(l, 0, iface, Box::new(lb_udp_recv_cb)) {
        Ok(sid) => {
            print!(
                "success nchildren={} child tids: ",
                inner.sock_nchildren(sid)
            );
            for i in 0..inner.sock_nchildren(sid) {
                print!("{} ", inner.sock_child_tid(sid, i as usize));
            }
            println!();
            ST.lock().unwrap().lb_udp_sock = Some(sid);
        }
        Err(_) => {
            println!("listenudp failed");
            return;
        }
    }

    ST.lock().unwrap().lb_udp_round = 0;
    let local = SockAddr::loopback(19166);
    let peer = SockAddr::loopback(19165);
    inner.udpconnect(l, local, peer, Box::new(lb_udp_connect_cb), 5000);
}

/* TCP load balance */

fn lb_tcp_client_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    _handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        return;
    }
    println!("  client recv: data=\"{}\"", String::from_utf8_lossy(&data));
    let mut st = ST.lock().unwrap();
    st.lb_tcp_round += 1;
    if st.lb_tcp_round < 4 {
        let keep = st.lb_keep.unwrap();
        inner.handle_close(l, keep);
        inner.handle_detach(l, &mut st.lb_keep);
        drop(st);
        lb_tcp_conn_go(inner, l);
    } else {
        println!(
            "  TCP load balance: connects={} echoes={} accepts={}",
            st.lb_tcp_round,
            st.lb_tcp_round,
            LB_TCP_ACCEPTS.load(Ordering::SeqCst)
        );
        let keep = st.lb_keep.unwrap();
        inner.handle_close(l, keep);
        inner.handle_detach(l, &mut st.lb_keep);
        let lsid = st.lb_tcp_sock.unwrap();
        drop(st);
        inner.stoplistening(l, lsid);
        inner.nmsocket_close(l, &mut ST.lock().unwrap().lb_tcp_sock);
        next_job(inner, Box::new(phase13_teardown));
    }
}

fn lb_tcp_conn_go(inner: &mut LoopInner, l: &mut UvLoop) {
    let round = ST.lock().unwrap().lb_tcp_round;
    let local = SockAddr::loopback((19170 + round) as u16);
    let peer = SockAddr::loopback(19167);

    let msg = format!("lt-{}", round + 1);
    ST.lock().unwrap().lb_send_data = msg.clone().into_bytes();

    println!(
        "  client connect {} (local=127.0.0.1#{} -> 127.0.0.1#19167)",
        round + 1,
        19170 + round
    );
    inner.tcpconnect(l, local, peer, Box::new(lb_tcp_connect_cb), 5000);
}

fn lb_tcp_connect_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) {
    let round = ST.lock().unwrap().lb_tcp_round;
    println!(
        "  connect cb {}: eresult={}",
        round + 1,
        sname(code_to_res(eresult))
    );
    if eresult != 0 {
        return;
    }

    let keep = inner.handle_attach(handle);
    ST.lock().unwrap().lb_keep = Some(keep);
    inner.read(l, handle, Box::new(lb_tcp_client_recv_cb));
    let send_h = inner.handle_attach(handle);
    ST.lock().unwrap().lb_send = Some(send_h);
    let data = ST.lock().unwrap().lb_send_data.clone();
    inner.send(l, send_h, &data, Box::new(lb_tcp_send_cb));
    println!("  client sent \"{}\"", String::from_utf8_lossy(&data));
}

fn lb_tcp_send_cb(inner: &mut LoopInner, l: &mut UvLoop, _handle: HandleId, _eresult: i32) {
    inner.handle_detach(l, &mut ST.lock().unwrap().lb_send);
}

fn lb_tcp_server_send_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, _eresult: i32) {
    inner.handle_detach(l, &mut Some(handle));
}

fn lb_tcp_server_recv_cb(
    inner: &mut LoopInner,
    l: &mut UvLoop,
    handle: HandleId,
    eresult: i32,
    data: Vec<u8>,
    _peer: Option<SockAddr>,
) {
    if eresult != 0 {
        inner.handle_detach(l, &mut Some(handle));
        return;
    }
    /* echo (uppercase first byte), no prints */
    let mut echo = data.clone();
    if !echo.is_empty() {
        echo[0] ^= 0x20;
    }
    let send_h = inner.handle_attach(handle);
    inner.send(l, send_h, &echo, Box::new(lb_tcp_server_send_cb));
}

fn lb_tcp_accept_cb(inner: &mut LoopInner, l: &mut UvLoop, handle: HandleId, eresult: i32) -> i32 {
    if eresult != 0 {
        return eresult;
    }

    LB_TCP_ACCEPTS.fetch_add(1, Ordering::SeqCst);

    /* the C's readhandle (the cbarg): a probe-held ref that keeps the
     * connection's handle alive; never detached (like the C probe) */
    let _readhandle = inner.handle_attach(handle);
    inner.read(l, handle, Box::new(lb_tcp_server_recv_cb));

    0
}

fn phase12_tcp(inner: &mut LoopInner, l: &mut UvLoop) {
    print!("  TCP listen: ");

    let iface = SockAddr::loopback(19167);

    match inner.listentcp(l, 0, iface, Box::new(lb_tcp_accept_cb), 10) {
        Ok(sid) => {
            print!(
                "success nchildren={} child tids: ",
                inner.sock_nchildren(sid)
            );
            for i in 0..inner.sock_nchildren(sid) {
                print!("{} ", inner.sock_child_tid(sid, i as usize));
            }
            println!();
            ST.lock().unwrap().lb_tcp_sock = Some(sid);
        }
        Err(_) => {
            println!("listentcp failed");
            return;
        }
    }

    ST.lock().unwrap().lb_tcp_round = 0;
    lb_tcp_conn_go(inner, l);
}

// ---------------------------------------------------------------------------
// phase 13: teardown
// ---------------------------------------------------------------------------

fn phase13_teardown(inner: &mut LoopInner, _l: &mut UvLoop) {
    let _ = inner;
    println!("=== PHASE 13: teardown ===");
    // isc_loopmgr_shutdown(loopmgr): the loop-0 teardown job prints "loop 0
    // teardown cb" during the shutdown pass.
    LOOPMGR.get().unwrap().shutdown();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    println!("=== PHASE 1: netmgr lifecycle ===");
    println!("main: isc_mem_create ok");

    let loopmgr = Loopmgr::new(3);
    let _ = LOOPMGR.set(loopmgr);
    println!("main: isc_loopmgr_create(3) ok");

    let nm = NetmgrShared::create(LOOPMGR.get().unwrap());
    println!("main: isc_netmgr_create ok");

    // isc_loop_setup(mainloop, phase1_setup, NULL).
    LOOPMGR
        .get()
        .unwrap()
        .setup_main(Arc::new(|inner, l| phase1_setup(inner, l)));
    // isc_loop_teardown(mainloop, loop0_teardown, NULL).
    LOOPMGR.get().unwrap().teardown(
        0,
        Arc::new(|_inner, _l| {
            println!("loop 0 teardown cb");
        }),
    );

    LOOPMGR.get().unwrap().run(nm.clone());
    println!("main: isc_loopmgr_run returned");

    LOOPMGR.get().unwrap().destroy();
    println!("main: isc_loopmgr_destroy ok");

    // isc_netmgr_destroy(&netmgr): the shared state's teardown jobs already
    // ran during the loop shutdown; drop the last reference.
    drop(nm);
    println!("main: isc_netmgr_destroy ok");

    println!("main: isc_mem_destroy ok");
}
