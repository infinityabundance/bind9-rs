//! compat/netmgr — native safe-Rust mirror of BIND 9.20.26's `isc_nm_*`
//! network manager (court NETMGR-0001), the async socket engine the query
//! pipeline runs on.
//!
//! The C surface (`lib/isc/netmgr/{netmgr.c,udp.c,tcp.c,socket.c,timer.c}`
//! + `lib/isc/loop.c` + `lib/isc/async.c` + `lib/isc/job.c`) is consumed
//! here on top of `compat::libuv` (LIBUV-0001):
//!
//!  - `Loopmgr` — the per-worker event-loop model (`isc_loopmgr_t`):
//!    `nloops` worker threads, each owning a `UvLoop`; loop 0 runs on the
//!    caller's thread; cross-thread dispatch through a per-loop mailbox
//!    (`isc_async_run`, fired in the poll phase) and an idle-pass job queue
//!    (`isc_job_run`); setup/teardown jobs; shutdown via a per-loop
//!    `uv_async` trigger.
//!  - `NetmgrShared` — the shared atomic state (`struct isc_nm`): timeouts,
//!    maxudp, netbuffers, load-balance flag, refcount, shutting-down.
//!  - `LoopInner` — the per-loop mutable state (`isc_loop_t` +
//!    `isc__networker_t` + the sockets/handles): the socket state machine
//!    (`struct isc_nmsocket`), the handle refcount lifecycle (`struct
//!    isc_nmhandle` incl. the inactive-handle pool and the statichandle
//!    rule), the uvreq attach/detach dance (`isc__nm_uvreq_t`), and the
//!    parent/child listener model (children live on their own worker loops;
//!    child results return through the listen barrier).
//!
//! Every libc call goes through `platform::linux` (the audited unsafe
//! boundary); this module is safe Rust.  The court is deterministic: fixed
//! loopback ports, fixed worker tids, fixed callback orderings.
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]

use crate::compat::libuv::*;
use crate::platform::linux as lx;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// socket types (`isc_socktype_t` for the courted subset)
// ---------------------------------------------------------------------------

/// `isc_socktype_t` for the courted `isc_nm_checkaddr` surface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockType {
    Tcp,
    Udp,
    Raw,
}

// ---------------------------------------------------------------------------
// result codes (the courted subset of isc_result_t)
// ---------------------------------------------------------------------------

/// `isc_result_t` subset the netmgr court observes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Res {
    Success,
    TimedOut,
    Canceled,
    ShuttingDown,
    AddrInUse,
    ConnRefused,
    NotImplemented,
    Eof,
    ConnReset,
    Unset,
}

impl Res {
    /// The probe's `SNAME` spellings (the courted `isc_result_totext`
    /// subset).
    pub fn name(self) -> &'static str {
        match self {
            Res::Success => "success",
            Res::TimedOut => "timed out",
            Res::Canceled => "canceled",
            Res::ShuttingDown => "shutting down",
            Res::AddrInUse => "address in use",
            Res::ConnRefused => "connection refused",
            Res::NotImplemented => "not implemented",
            Res::Eof => "eof",
            Res::ConnReset => "connection reset",
            Res::Unset => "unset",
        }
    }
}

fn res_to_code(r: Res) -> i32 {
    match r {
        Res::Success => 0,
        Res::TimedOut => -1,
        Res::Canceled => -2,
        Res::ShuttingDown => -3,
        Res::NotImplemented => -4,
        Res::AddrInUse => -5,
        Res::Eof => -6,
        Res::ConnReset => -7,
        Res::ConnRefused => -libc::ECONNREFUSED as i32,
        Res::Unset => -1000,
    }
}

pub fn code_to_res(c: i32) -> Res {
    match c {
        0 => Res::Success,
        -1 => Res::TimedOut,
        -2 => Res::Canceled,
        -3 => Res::ShuttingDown,
        -4 => Res::NotImplemented,
        -5 => Res::AddrInUse,
        -6 => Res::Eof,
        -7 => Res::ConnReset,
        c if c == -libc::ECONNREFUSED as i32 => Res::ConnRefused,
        _ => Res::Unset,
    }
}

// ---------------------------------------------------------------------------
// addresses
// ---------------------------------------------------------------------------

/// `isc_sockaddr_t` for the courted surface: the loopback IPv4 literal with
/// a fixed port (the determinism contract forbids kernel-assigned ports in
/// the transcript; every probe address is 127.0.0.1#fixed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SockAddr {
    pub port: u16,
}

impl SockAddr {
    pub const fn loopback(port: u16) -> SockAddr {
        SockAddr { port }
    }

    /// `isc_sockaddr_format` for the courted address.
    pub fn fmt(&self) -> String {
        format!("127.0.0.1#{}", self.port)
    }
}

fn sockaddr_in(a: SockAddr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: a.port.to_be(),
        // `from_be(0x7f00_0001)`: the BE value stored on a LE machine is
        // the memory bytes 7f 00 00 01 — 127.0.0.1 in network byte order.
        sin_addr: libc::in_addr {
            s_addr: u32::from_be(0x7f00_0001),
        },
        sin_zero: [0; 8],
    }
}

// ---------------------------------------------------------------------------
// socket type names
// ---------------------------------------------------------------------------

/// `isc_nmsocket_type` for the courted subset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockKind {
    UdpSocket,
    UdpListener,
    TcpSocket,
    TcpListener,
}

impl SockKind {
    /// The probe's `STYPE` spellings.
    pub fn name(&self) -> &'static str {
        match self {
            SockKind::UdpSocket => "udpsocket",
            SockKind::UdpListener => "udplistener",
            SockKind::TcpSocket => "tcpsocket",
            SockKind::TcpListener => "tcplistener",
        }
    }
}

// ---------------------------------------------------------------------------
// ids, callbacks, jobs
// ---------------------------------------------------------------------------

pub type SocketId = usize;
pub type HandleId = usize;

/// The user recv callback (`isc_nm_recv_cb_t`): `(inner, loop, handle,
/// eresult, data, peer)`.
pub type RecvCb =
    Box<dyn FnMut(&mut LoopInner, &mut UvLoop, HandleId, i32, Vec<u8>, Option<SockAddr>) + Send>;
/// The user send/connect callback (`isc_nm_cb_t`).
pub type SendCb = Box<dyn FnMut(&mut LoopInner, &mut UvLoop, HandleId, i32) + Send>;
/// The user accept callback (`isc_nm_accept_cb_t`).
pub type AcceptCb = Box<dyn FnMut(&mut LoopInner, &mut UvLoop, HandleId, i32) -> i32 + Send>;
/// A one-shot job scheduled on a loop (`isc_async_run`/`isc_job_run`).
pub type Job = Box<dyn FnOnce(&mut LoopInner, &mut UvLoop) + Send>;
/// A reusable setup/teardown job (`isc_loopmgr_setup`/`isc_loopmgr_teardown`).
pub type SetupJob = Arc<dyn Fn(&mut LoopInner, &mut UvLoop) + Send + Sync>;

// ---------------------------------------------------------------------------
// the per-worker mailbox (cross-thread dispatch; `isc_async_run`)
// ---------------------------------------------------------------------------

/// The Send half of one worker loop: the job queue and the loop's async
/// wake token (filled by the loop driver after `uv_async_init`).
pub struct WorkerMailbox {
    pub tid: u32,
    jobs: Mutex<VecDeque<Job>>,
    wake: OnceLock<AsyncWake>,
}

impl WorkerMailbox {
    fn new(tid: u32) -> Arc<WorkerMailbox> {
        Arc::new(WorkerMailbox {
            tid,
            jobs: Mutex::new(VecDeque::new()),
            wake: OnceLock::new(),
        })
    }

    /// `isc_async_run`: enqueue + `uv_async_send`.
    pub fn send(&self, job: Job) {
        self.jobs.lock().unwrap().push_back(job);
        if let Some(w) = self.wake.get() {
            let _ = w.send();
        }
    }

    /// Drain on the loop thread (called from the async callback).
    fn drain(&self) -> Vec<Job> {
        let mut q = self.jobs.lock().unwrap();
        q.drain(..).collect()
    }
}

// ---------------------------------------------------------------------------
// the loop manager (`isc_loopmgr_t`)
// ---------------------------------------------------------------------------

struct LoopmgrInner {
    nloops: u32,
    shuttingdown: AtomicBool,
    running: AtomicBool,
    mailboxes: Vec<Arc<WorkerMailbox>>,
    setup_main: Mutex<VecDeque<SetupJob>>,
    setup_all: Mutex<VecDeque<SetupJob>>,
    teardown: Mutex<Vec<VecDeque<SetupJob>>>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

/// The loop manager: creates the worker loops, runs them, shuts them down.
pub struct Loopmgr {
    inner: Arc<LoopmgrInner>,
}

impl Loopmgr {
    /// `isc_loopmgr_create(mctx, nloops, &loopmgr)`.
    pub fn new(nloops: u32) -> Loopmgr {
        assert!(nloops > 0);
        let mut mailboxes = Vec::new();
        for tid in 0..nloops {
            mailboxes.push(WorkerMailbox::new(tid));
        }
        Loopmgr {
            inner: Arc::new(LoopmgrInner {
                nloops,
                shuttingdown: AtomicBool::new(false),
                running: AtomicBool::new(false),
                mailboxes,
                setup_main: Mutex::new(VecDeque::new()),
                setup_all: Mutex::new(VecDeque::new()),
                teardown: Mutex::new(vec![VecDeque::new(); nloops as usize]),
                threads: Mutex::new(Vec::new()),
            }),
        }
    }

    /// `isc_loopmgr_nloops`.
    pub fn nloops(&self) -> u32 {
        self.inner.nloops
    }

    /// `isc_loop_setup(mainloop, cb, arg)`: a job run on loop 0 at start.
    pub fn setup_main(&self, job: SetupJob) {
        self.inner.setup_main.lock().unwrap().push_back(job);
    }

    /// `isc_loopmgr_setup`: a job run on every loop at start.
    pub fn setup_all(&self, job: SetupJob) {
        self.inner.setup_all.lock().unwrap().push_back(job);
    }

    /// `isc_loop_teardown(loop, cb, arg)`: a job run on loop `tid` at
    /// shutdown.
    pub fn teardown(&self, tid: u32, job: SetupJob) {
        self.inner.teardown.lock().unwrap()[tid as usize].push_back(job);
    }

    /// `isc_loopmgr_teardown`: a job run on every loop at shutdown.
    pub fn teardown_all(&self, job: SetupJob) {
        for tid in 0..self.inner.nloops {
            self.teardown(tid, job.clone());
        }
    }

    /// `isc_loopmgr_shutdown`: wake every loop's shutdown trigger.
    pub fn shutdown(&self) {
        if self
            .inner
            .shuttingdown
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        for mb in &self.inner.mailboxes {
            mb.send(Box::new(|inner, l| {
                inner.shutdown_trigger_cb(l);
            }));
        }
    }

    /// `isc_loopmgr_run`: spawn threads 1..n-1; run loop 0 on this thread.
    /// `nm` is the netmgr shared state created before the run.
    pub fn run(&self, nm: Arc<NetmgrShared>) {
        let prev = self.inner.running.swap(true, Ordering::AcqRel);
        assert!(!prev, "loopmgr already running");
        for tid in 1..self.inner.nloops {
            let lm = self.inner.clone();
            let nm = nm.clone();
            let h = std::thread::spawn(move || {
                run_loop(lm, tid, nm);
            });
            self.inner.threads.lock().unwrap().push(h);
        }
        run_loop(self.inner.clone(), 0, nm);
    }

    /// `isc_loopmgr_destroy`: join the worker threads.
    pub fn destroy(&self) {
        let threads = std::mem::take(&mut *self.inner.threads.lock().unwrap());
        for t in threads {
            t.join().expect("worker loop thread");
        }
    }
}

// ---------------------------------------------------------------------------
// the shared netmgr state (`struct isc_nm` atomics)
// ---------------------------------------------------------------------------

/// The shared, thread-safe netmgr state — the `isc_nm_t` atomics.
pub struct NetmgrShared {
    pub nloops: u32,
    pub load_balance: bool,
    pub maxudp: AtomicU32,
    pub references: AtomicU32,
    pub init: AtomicU32,
    pub idle: AtomicU32,
    pub keepalive: AtomicU32,
    pub advertised: AtomicU32,
    pub recv_tcp_buffer_size: AtomicI32,
    pub send_tcp_buffer_size: AtomicI32,
    pub recv_udp_buffer_size: AtomicI32,
    pub send_udp_buffer_size: AtomicI32,
    pub shuttingdown: AtomicBool,
}

impl NetmgrShared {
    /// `isc_netmgr_create`: create the shared state and register the
    /// per-loop teardown (netmgr_teardown + networker_teardown).
    pub fn create(loopmgr: &Loopmgr) -> Arc<NetmgrShared> {
        let nloops = loopmgr.nloops();
        let nm = Arc::new(NetmgrShared {
            nloops,
            load_balance: true,
            maxudp: AtomicU32::new(0),
            references: AtomicU32::new(1),
            init: AtomicU32::new(30000),
            idle: AtomicU32::new(30000),
            keepalive: AtomicU32::new(30000),
            advertised: AtomicU32::new(30000),
            recv_tcp_buffer_size: AtomicI32::new(0),
            send_tcp_buffer_size: AtomicI32::new(0),
            recv_udp_buffer_size: AtomicI32::new(0),
            send_udp_buffer_size: AtomicI32::new(0),
            shuttingdown: AtomicBool::new(false),
        });

        // isc_netmgr_create: each worker holds an attach (`isc_nm_attach`
        // per loop), so the reference count the probe observes is
        // 1 + nloops.
        for _ in 0..nloops {
            nm.attach();
        }

        // isc_loopmgr_teardown(loopmgr, netmgr_teardown, netmgr).
        let nm2 = nm.clone();
        loopmgr.teardown_all(Arc::new(move |_inner, _l| {
            nm2.shuttingdown.store(true, Ordering::Relaxed);
        }));

        // networker_teardown per loop: walk and shut down the sockets.
        loopmgr.teardown_all(Arc::new(|inner, l| {
            inner.worker_shutdown(l);
        }));

        nm
    }

    /// `isc_nm_attach`/`isc_nm_detach` (the refcount the probe prints).
    pub fn attach(&self) {
        self.references.fetch_add(1, Ordering::AcqRel);
    }

    pub fn detach(&self) {
        self.references.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn refs(&self) -> u32 {
        self.references.load(Ordering::Acquire)
    }

    /// `isc_nm_settimeouts`/`isc_nm_gettimeouts`.
    pub fn settimeouts(&self, init: u32, idle: u32, keepalive: u32, advertised: u32) {
        self.init.store(init, Ordering::Relaxed);
        self.idle.store(idle, Ordering::Relaxed);
        self.keepalive.store(keepalive, Ordering::Relaxed);
        self.advertised.store(advertised, Ordering::Relaxed);
    }

    pub fn gettimeouts(&self) -> (u32, u32, u32, u32) {
        (
            self.init.load(Ordering::Relaxed),
            self.idle.load(Ordering::Relaxed),
            self.keepalive.load(Ordering::Relaxed),
            self.advertised.load(Ordering::Relaxed),
        )
    }

    /// `isc_nm_setnetbuffers`.
    pub fn setnetbuffers(&self, r_tcp: i32, s_tcp: i32, r_udp: i32, s_udp: i32) {
        self.recv_tcp_buffer_size.store(r_tcp, Ordering::Relaxed);
        self.send_tcp_buffer_size.store(s_tcp, Ordering::Relaxed);
        self.recv_udp_buffer_size.store(r_udp, Ordering::Relaxed);
        self.send_udp_buffer_size.store(s_udp, Ordering::Relaxed);
    }

    /// `isc_nm_maxudp`.
    pub fn maxudp(&self, v: u32) {
        self.maxudp.store(v, Ordering::Relaxed);
    }

    /// `isc_nm_checkaddr`: bind-probe a loopback port (socket+bind+close).
    pub fn checkaddr(addr: SockAddr, ty: SockType) -> Res {
        match ty {
            SockType::Tcp => Self::checkaddr_impl(addr, libc::SOCK_STREAM),
            SockType::Udp => Self::checkaddr_impl(addr, libc::SOCK_DGRAM),
            // `isc_nm_checkaddr`'s raw/default arm.
            SockType::Raw => Res::NotImplemented,
        }
    }

    fn checkaddr_impl(addr: SockAddr, ty: i32) -> Res {
        let fd = match lx::socket(libc::AF_INET, ty, 0) {
            Ok(fd) => fd,
            Err(e) => return errno_to_res(e),
        };
        let sa = sockaddr_in(addr);
        let r = match lx::bind(fd, &sa) {
            Ok(()) => Res::Success,
            Err(e) => errno_to_res(e),
        };
        lx::close(fd);
        r
    }
}

fn errno_to_res(e: i32) -> Res {
    match e {
        libc::EADDRINUSE => Res::AddrInUse,
        libc::ECONNREFUSED => Res::ConnRefused,
        _ => Res::Unset,
    }
}

// ---------------------------------------------------------------------------
// per-loop state: sockets, handles, queues
// ---------------------------------------------------------------------------

/// A child slot of a multi-worker listener (`sock->children[i]`).
struct ChildSlot {
    tid: u32,
    result: Arc<AtomicI32>,
    /// The child's socket id in its own worker's arena, set by the child
    /// job before the listen barrier.
    socket_id: Arc<Mutex<Option<SocketId>>>,
}

/// One socket (`struct isc_nmsocket` for the courted subset).
struct Socket {
    kind: SockKind,
    tid: u32,
    refs: u32,
    parent: Option<SocketId>,
    server: Option<SocketId>,
    /// The rsock refcount for this socket's tree, shared between the
    /// listener parent (loop 0) and its children (loops 1..n) through an
    /// Arc — the C's atomic isc_refcount on the shared isc_nmsocket_t.
    /// Children attach/detach against the parent through their own copy, so
    /// no cross-loop Vec indexing is needed.  Standalone sockets (UDP/TCP
    /// clients, accepted connections) leave this None and use `refs`.
    shared_refs: Option<Arc<AtomicU32>>,
    children: Vec<ChildSlot>,
    nchildren: u32,
    listen_barrier: Option<Arc<Barrier>>,
    stop_barrier: Option<Arc<Barrier>>,
    iface: SockAddr,
    peer: SockAddr,
    active: bool,
    closing: bool,
    closed: bool,
    destroying: bool,
    connecting: bool,
    connected: bool,
    accepting: bool,
    reading: bool,

    timedout: bool,
    client: bool,
    keepalive: bool,
    manual_read_timer: bool,
    statichandle: Option<HandleId>,
    active_handles: Vec<HandleId>,
    active_handles_cur: u32,
    inactive_handles: VecDeque<HandleId>,
    inactive_handles_cur: u32,
    uv_udp: Option<Handle>,
    uv_tcp: Option<Handle>,
    read_timer: Option<Handle>,
    /// Shared listener/connected-socket callbacks.  The listener's cb is
    /// wrapped in `Arc<Mutex<>>` so each child loop can hold its own copy
    /// (the C's `csock->accept_cb = sock->accept_cb` pointer copy) and so
    /// the accept cb survives across accepts — it is never consumed.
    recv_cb: Option<Arc<Mutex<RecvCb>>>,
    accept_cb: Option<Arc<Mutex<AcceptCb>>>,
    connect_cb: Option<SendCb>,
    read_timeout: u64,
    connect_timeout: u64,
    write_timeout: u64,
    /// The C's per-write timeout timer (`isc_nm_timer_create` in
    /// tcp_send_direct) holds its own handle ref, released when the
    /// timer's uv_close completes — after the send cb.  Mirrored as a
    /// ref-per-pending-uv_write count, released in the write completion
    /// (and on close for any write the close cancelled).
    pending_write_timers: u32,
    closehandle_cb: bool,
    timer_armed: bool,
    active_uvreqs: u32,
}

/// One handle (`struct isc_nmhandle` for the courted subset).
struct HandleObj {
    refs: u32,
    sock: Option<SocketId>,
    peer: SockAddr,
    local: SockAddr,
}

type Weak = std::rc::Weak<RefCell<LoopInner>>;

/// The per-loop state.  NOT Send: it owns the netmgr's mutable state for
/// one worker loop and is only touched on that loop's thread (the courted
/// invariant `sock->tid == isc_tid()`).
pub struct LoopInner {
    pub tid: u32,
    pub shuttingdown: bool,
    self_weak: Weak,
    pub nm: Arc<NetmgrShared>,
    /// All worker mailboxes (indexed by tid) for cross-worker dispatch.
    all_mailboxes: Arc<Vec<Arc<WorkerMailbox>>>,
    setup_jobs: VecDeque<SetupJob>,
    teardown_jobs: VecDeque<SetupJob>,
    /// The `isc_job_run` jobs — drained in the idle pass.
    run_jobs: VecDeque<Job>,
    async_trigger: Handle,
    shutdown_trigger: Handle,
    run_trigger: Handle,
    quiescent: Handle,
    // The C's per-worker recv buffer (`worker->recvbuf`) is replaced by a
    // per-call buffer in `alloc_cb`; the behavior is identical for the
    // court (the buffer pointer never appears in the transcript).
    sockets: Vec<Socket>,
    handles: Vec<HandleObj>,
    /// The sockets ever created on this loop (the teardown walk).
    active_sockets: Vec<SocketId>,
}

// ---------------------------------------------------------------------------
// the loop driver
// ---------------------------------------------------------------------------

fn run_loop(lm: Arc<LoopmgrInner>, tid: u32, nm: Arc<NetmgrShared>) {
    let mut l = UvLoop::default();

    let inner = Rc::new(RefCell::new(LoopInner {
        tid,
        shuttingdown: false,
        self_weak: Weak::new(),
        nm,
        all_mailboxes: Arc::new(lm.mailboxes.clone()),
        setup_jobs: VecDeque::new(),
        teardown_jobs: VecDeque::new(),
        run_jobs: VecDeque::new(),
        async_trigger: Handle(0),
        shutdown_trigger: Handle(0),
        run_trigger: Handle(0),
        quiescent: Handle(0),

        sockets: Vec::new(),
        handles: Vec::new(),
        active_sockets: Vec::new(),
    }));
    inner.borrow_mut().self_weak = Rc::downgrade(&inner);

    // Loop init: async_trigger (mailbox drain), shutdown_trigger,
    // run_trigger (idle, the isc_job_run queue), quiescent (prepare).
    let weak = Rc::downgrade(&inner);
    let mut async_trigger = Handle(0);
    l.uv_async_init(
        &mut async_trigger,
        Box::new(move |l: &mut UvLoop| {
            if let Some(rc) = weak.upgrade() {
                let mut inner = rc.borrow_mut();
                inner.async_cb(l);
            }
        }),
    );
    let weak = Rc::downgrade(&inner);
    let mut shutdown_trigger = Handle(0);
    l.uv_async_init(
        &mut shutdown_trigger,
        Box::new(move |l: &mut UvLoop| {
            if let Some(rc) = weak.upgrade() {
                let mut inner = rc.borrow_mut();
                inner.shutdown_trigger_cb(l);
            }
        }),
    );
    let weak = Rc::downgrade(&inner);
    let mut run_trigger = Handle(0);
    l.uv_idle_init(&mut run_trigger);
    l.uv_idle_start(
        run_trigger,
        Box::new(move |l: &mut UvLoop| {
            if let Some(rc) = weak.upgrade() {
                let mut inner = rc.borrow_mut();
                inner.job_cb(l);
            }
        }),
    );
    let weak = Rc::downgrade(&inner);
    let mut quiescent = Handle(0);
    l.uv_prepare_init(&mut quiescent);
    l.uv_prepare_start(
        quiescent,
        Box::new(move |_l: &mut UvLoop| {
            if let Some(rc) = weak.upgrade() {
                let mut inner = rc.borrow_mut();
                inner.quiescent_cb();
            }
        }),
    );

    // Fill this loop's mailbox wake token.
    let wake = l.async_wake(async_trigger);
    let mailbox = lm.mailboxes[tid as usize].clone();
    let _ = mailbox.wake.set(wake);

    {
        let mut inner = inner.borrow_mut();
        inner.async_trigger = async_trigger;
        inner.shutdown_trigger = shutdown_trigger;
        inner.run_trigger = run_trigger;
        inner.quiescent = quiescent;
        // Setup jobs: loop 0 runs the main + all-loops setup; other loops
        // run the all-loops setup.
        let mut setup = VecDeque::new();
        if tid == 0 {
            setup.append(&mut lm.setup_main.lock().unwrap());
        }
        setup.append(&mut lm.setup_all.lock().unwrap());
        let mut teardown = lm.teardown.lock().unwrap()[tid as usize].clone();
        inner.setup_jobs.append(&mut setup);
        inner.teardown_jobs.append(&mut teardown);
    }

    // The first wake: the setup jobs run before the first poll round.
    mailbox.send(Box::new(|_inner, _l| {}));

    let _ = l.uv_run(RunMode::Default);

    // uv_loop_close: the teardown closed the sockets and the loop's own
    // handles, so the loop is empty.
    let _ = l.uv_loop_close();
}

// ---------------------------------------------------------------------------
// LoopInner: the netmgr API
// ---------------------------------------------------------------------------

impl LoopInner {
    /// `isc_tid()`.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// The loop's `isc_async_run` — schedule a job on this loop (the
    /// probe's `next_job`); safe from any thread.
    pub fn async_dispatch(&self, job: Job) {
        self.mailbox_self().send(job);
    }

    fn mailbox_self(&self) -> &Arc<WorkerMailbox> {
        &self.all_mailboxes[self.tid as usize]
    }

    /// `isc_job_run` — schedule a job for the idle pass.
    pub fn job_dispatch(&mut self, l: &mut UvLoop, job: Job) {
        let empty = self.run_jobs.is_empty();
        self.run_jobs.push_back(job);
        if empty {
            let weak = self.self_weak.clone();
            let _ = l.uv_idle_start(
                self.run_trigger,
                Box::new(move |l: &mut UvLoop| {
                    if let Some(rc) = weak.upgrade() {
                        let mut inner = rc.borrow_mut();
                        inner.job_cb(l);
                    }
                }),
            );
        }
    }

    /// `isc__async_cb`: drain the mailbox and run the jobs.  The setup
    /// jobs (`isc_loop_setup`/`isc_loopmgr_setup`) run at loop start,
    /// before any queued job; the teardown jobs are spliced only by the
    /// shutdown trigger.
    fn async_cb(&mut self, l: &mut UvLoop) {
        let setup = std::mem::take(&mut self.setup_jobs);
        for job in setup {
            job(self, l);
        }
        let jobs = self.mailbox_self().drain();
        for job in jobs {
            job(self, l);
        }
    }

    /// `shutdown_cb`: close the shutdown trigger, mark shutting down,
    /// splice the teardown jobs, and close the loop's own handles last.
    fn shutdown_trigger_cb(&mut self, l: &mut UvLoop) {
        l.uv_close(self.shutdown_trigger, None);
        self.shuttingdown = true;
        let teardown = std::mem::take(&mut self.teardown_jobs);
        for job in teardown {
            let j = job.clone();
            self.async_dispatch(Box::new(move |inner, l| j(inner, l)));
        }
        self.async_dispatch(Box::new(|inner, l| {
            inner.close_loop_handles(l);
        }));
    }

    /// `isc__job_cb`: drain the run_jobs queue (idle pass).
    fn job_cb(&mut self, l: &mut UvLoop) {
        let jobs = std::mem::take(&mut self.run_jobs);
        for job in jobs {
            job(self, l);
        }
        if self.run_jobs.is_empty() {
            let _ = l.uv_idle_stop(self.run_trigger);
        }
    }

    /// The prepare-pass no-op (`quiescent_cb`).
    fn quiescent_cb(&mut self) {}

    /// Close the loop's own handles so `uv_run` can return.
    fn close_loop_handles(&mut self, l: &mut UvLoop) {
        l.uv_close(self.shutdown_trigger, None);
        l.uv_close(self.async_trigger, None);
        let _ = l.uv_idle_stop(self.run_trigger);
        l.uv_close(self.run_trigger, None);
        let _ = l.uv_prepare_stop(self.quiescent);
        l.uv_close(self.quiescent, None);
    }

    /// `networker_teardown`: shut down every remaining socket.
    fn worker_shutdown(&mut self, l: &mut UvLoop) {
        self.shuttingdown = true;
        let socks: Vec<SocketId> = self.active_sockets.clone();
        for sid in socks {
            self.socket_shutdown(l, sid);
        }
    }

    /// `isc__nm_closing(worker)`.
    pub fn nm_closing(&self) -> bool {
        self.shuttingdown
    }

    // -- internal state accessors (the probe's netmgr-int.h observations) --

    pub fn sock_kind(&self, sid: SocketId) -> SockKind {
        self.sockets[sid].kind
    }
    pub fn sock_active(&self, sid: SocketId) -> bool {
        self.sockets[sid].active
    }
    pub fn sock_closing(&self, sid: SocketId) -> bool {
        self.sockets[sid].closing
    }
    pub fn sock_closed(&self, sid: SocketId) -> bool {
        self.sockets[sid].closed
    }
    pub fn sock_connected(&self, sid: SocketId) -> bool {
        self.sockets[sid].connected
    }
    pub fn sock_connecting(&self, sid: SocketId) -> bool {
        self.sockets[sid].connecting
    }
    pub fn sock_reading(&self, sid: SocketId) -> bool {
        self.sockets[sid].reading
    }
    pub fn sock_client(&self, sid: SocketId) -> bool {
        self.sockets[sid].client
    }
    pub fn sock_refs(&self, sid: SocketId) -> u32 {
        // The probe prints `sock->references` — the socket's OWN refcount.
        // For a listener child the attaches count against the parent (the
        // shared cell), so its own field stays at the initial 1.
        self.sockets[sid].refs
    }
    pub fn sock_nchildren(&self, sid: SocketId) -> u32 {
        self.sockets[sid].nchildren
    }
    pub fn sock_child_tid(&self, sid: SocketId, i: usize) -> u32 {
        self.sockets[sid].children[i].tid
    }
    pub fn sock_child_result(&self, sid: SocketId, i: usize) -> Res {
        code_to_res(self.sockets[sid].children[i].result.load(Ordering::Acquire))
    }

    /// `sock->children[i]`'s lifecycle flags — the C probe's direct struct
    /// read.  Only the child owned by this loop's arena (tid == self.tid,
    /// i.e. child[0]) is observable; the other loops' children live in
    /// their own arenas.
    pub fn sock_child_lifecycle(&self, sid: SocketId, i: usize) -> (bool, bool, bool) {
        let slot = &self.sockets[sid].children[i];
        if slot.tid != self.tid {
            return (false, false, false);
        }
        match *slot.socket_id.lock().unwrap() {
            Some(cid) => {
                let s = &self.sockets[cid];
                (s.active, s.closing, s.closed)
            }
            None => (false, false, false),
        }
    }
    pub fn sock_active_handles(&self, sid: SocketId) -> u32 {
        self.sockets[sid].active_handles_cur
    }
    pub fn sock_statichandle(&self, sid: SocketId) -> bool {
        self.sockets[sid].statichandle.is_some()
    }
    pub fn sock_read_timeout(&self, sid: SocketId) -> u64 {
        self.sockets[sid].read_timeout
    }
    pub fn handle_refs(&self, h: HandleId) -> u32 {
        self.handles[h].refs
    }
    pub fn handle_sock(&self, h: HandleId) -> SocketId {
        self.handles[h].sock.expect("live handle")
    }
    pub fn handle_peer(&self, h: HandleId) -> SockAddr {
        self.handles[h].peer
    }
    pub fn handle_local(&self, h: HandleId) -> SockAddr {
        self.handles[h].local
    }

    /// `isc_nmhandle_netmgr(handle) == netmgr`: the mirror's LoopInner owns
    /// exactly one netmgr, and every handle in it belongs to that netmgr
    /// (the C's worker->netmgr back-pointer), so the probe's check is true
    /// by construction.
    pub fn handle_netmgr_match(&self, _h: HandleId) -> bool {
        true
    }

    // -- netmgr API --------------------------------------------------

    /// `isc_nm_listenudp`.
    pub fn listenudp(
        &mut self,
        l: &mut UvLoop,
        workers: u32,
        iface: SockAddr,
        cb: RecvCb,
    ) -> Result<SocketId, Res> {
        assert_eq!(self.tid, 0, "isc_nm_listenudp requires isc_tid() == 0");
        if self.nm_closing() {
            return Err(Res::ShuttingDown);
        }
        let workers = if workers == 0 {
            self.nm.nloops
        } else {
            workers
        };
        assert!(workers <= self.nm.nloops);

        let parent = self.socket_new(SockKind::UdpListener, iface, None);
        let nchildren = workers;
        let listen_barrier = Arc::new(Barrier::new(nchildren as usize));
        let stop_barrier = Arc::new(Barrier::new(nchildren as usize));

        let mut children = Vec::new();
        for tid in 0..nchildren {
            children.push(ChildSlot {
                tid,
                result: Arc::new(AtomicI32::new(res_to_code(Res::Unset))),
                socket_id: Arc::new(Mutex::new(None)),
            });
        }
        {
            let sock = &mut self.sockets[parent];
            sock.nchildren = nchildren;
            sock.children = children;
            sock.listen_barrier = Some(listen_barrier.clone());
            sock.stop_barrier = Some(stop_barrier.clone());
            sock.recv_cb = Some(Arc::new(Mutex::new(cb)));
            // The tree's shared refcount starts at the parent's initial
            // refs=1; children attach/detach against this same cell.
            sock.shared_refs = Some(Arc::new(AtomicU32::new(1)));
        }

        self.start_udp_child(l, parent, 0);
        let result = self.sockets[parent].children[0]
            .result
            .load(Ordering::Acquire);
        debug_assert_ne!(result, res_to_code(Res::Unset));
        for tid in 1..nchildren {
            self.start_udp_child(l, parent, tid);
        }
        listen_barrier.wait();

        let mut result = code_to_res(result);
        for i in 1..nchildren {
            let r = self.sockets[parent].children[i as usize]
                .result
                .load(Ordering::Acquire);
            if result == Res::Success && code_to_res(r) != Res::Success {
                result = code_to_res(r);
            }
        }

        if result != Res::Success {
            self.sockets[parent].active = false;
            self.udp_stoplistening(l, parent);
            self.socket_detach(l, parent);
            return Err(result);
        }

        self.sockets[parent].active = true;
        Ok(parent)
    }

    /// `start_udp_child`: create + init the child socket on its own worker.
    fn start_udp_child(&mut self, l: &mut UvLoop, parent: SocketId, tid: u32) {
        let iface = self.sockets[parent].iface;
        let cb = self.sockets[parent]
            .recv_cb
            .clone()
            .expect("listenudp recv cb");
        // The tree's shared refcount (children count against the parent
        // through their own copy of this Arc).
        let shared = self.sockets[parent].shared_refs.clone().unwrap();
        let slot_result = self.sockets[parent].children[tid as usize].result.clone();
        let slot_id = self.sockets[parent].children[tid as usize]
            .socket_id
            .clone();
        let barrier = self.sockets[parent].listen_barrier.clone().unwrap();

        let job: Job = Box::new(move |inner, l| {
            let child = inner.socket_new(SockKind::UdpSocket, iface, Some(parent));
            inner.sockets[child].shared_refs = Some(shared);
            *slot_id.lock().unwrap() = Some(child);
            inner.udp_child_open(l, child, cb, &slot_result, tid != 0, barrier);
        });
        if tid == 0 {
            job(self, l);
        } else {
            let mailbox = self.all_mailboxes[tid as usize].clone();
            mailbox.send(job);
        }
    }

    /// `start_udp_child_job`'s body.
    fn udp_child_open(
        &mut self,
        l: &mut UvLoop,
        child: SocketId,
        recv_cb: Arc<Mutex<RecvCb>>,
        result: &Arc<AtomicI32>,
        wait_barrier: bool,
        barrier: Arc<Barrier>,
    ) {
        let mut udp = Handle(0);
        let rc = l.uv_udp_init_ex(&mut udp, 0);
        debug_assert_eq!(rc, 0);
        let mut timer = Handle(0);
        let _ = l.uv_timer_init(&mut timer);
        {
            // The self-keep attach counts against the parent (rsock rule) —
            // through the child's copy of the shared cell.
            self.rsock_attach(child);
            let sock = &mut self.sockets[child];
            sock.uv_udp = Some(udp);
            sock.read_timer = Some(timer);
            sock.recv_cb = Some(recv_cb);
        }

        let fd = match lx::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                result.store(res_to_code(Res::Unset), Ordering::Release);
                if wait_barrier {
                    barrier.wait();
                }
                return;
            }
        };
        // isc__nm_udp_lb_socket (udp.c): SO_REUSEADDR on every listener,
        // plus SO_REUSEPORT when load balancing, so the nloops children can
        // bind the same address.
        let mut on = 1;
        let _ = lx::socket_sockopt(fd, libc::SO_REUSEADDR, &mut on);
        if self.nm.load_balance {
            let _ = lx::socket_sockopt(fd, libc::SO_REUSEPORT, &mut on);
        }
        let rc = l.uv_udp_open(udp, fd);
        if rc < 0 {
            lx::close(fd);
            result.store(res_to_code(Res::Unset), Ordering::Release);
            if wait_barrier {
                barrier.wait();
            }
            return;
        }
        // The UDP listener binds the interface address and starts receiving
        // immediately (`start_udp_child_job`'s uv_udp_recv_start).
        let iface = self.sockets[child].iface;
        let _ = l.uv_udp_bind(udp, &Addr::v4_loopback(iface.port));
        self.set_network_buffers(l, child);
        let weak = self.self_weak.clone();
        let _ = l.uv_udp_recv_start(
            udp,
            Box::new(alloc_cb),
            Box::new(
                move |l: &mut UvLoop,
                      nread: i64,
                      buf: &mut Buf,
                      addr: Option<&Addr>,
                      _flags: u32| {
                    let n = nread.max(0) as usize;
                    let data = buf.data[..n.min(buf.data.len())].to_vec();
                    let peer = addr.map(|a| match a {
                        Addr::Inet4 { port } => SockAddr::loopback(*port),
                    });
                    if let Some(rc) = weak.upgrade() {
                        let mut inner = rc.borrow_mut();
                        inner.udp_recv_event(l, child, nread, data, peer);
                    }
                },
            ),
        );
        result.store(res_to_code(Res::Success), Ordering::Release);
        if wait_barrier {
            barrier.wait();
        }
    }

    /// `isc_nm_udpconnect`.
    pub fn udpconnect(
        &mut self,
        l: &mut UvLoop,
        local: SockAddr,
        peer: SockAddr,
        cb: SendCb,
        timeout: u32,
    ) {
        if self.nm_closing() {
            return;
        }
        let sock = self.socket_new(SockKind::UdpSocket, local, None);
        {
            let s = &mut self.sockets[sock];
            s.connect_cb = Some(cb);
            s.read_timeout = u64::from(timeout);
            s.peer = peer;
            s.client = true;
        }
        // isc__nm_uvreq_get(sock) + req->handle = isc__nmhandle_get(...).
        self.socket_attach_ref(sock);
        self.sockets[sock].active_uvreqs += 1;
        let handle = self.handle_get(l, sock, Some(peer), Some(local));
        {
            let s = &mut self.sockets[sock];
            s.connecting = true;
            s.active = true;
        }
        let result = self.udp_connect_direct(l, sock, peer);
        if result != Res::Success {
            self.sockets[sock].active = false;
            self.udp_failed_connect_cb(l, sock, handle, result, true);
            self.socket_detach(l, sock);
            return;
        }
        {
            let s = &mut self.sockets[sock];
            s.connecting = false;
            s.connected = true;
        }
        // isc__nm_connectcb(..., true): dispatched through isc_job_run.
        let cb = self.sockets[sock]
            .connect_cb
            .take()
            .expect("udp connect cb");
        self.nm_connectcb(l, sock, handle, cb, Res::Success, true);
        self.socket_detach(l, sock);
    }

    fn udp_connect_direct(&mut self, l: &mut UvLoop, sock: SocketId, peer: SockAddr) -> Res {
        let mut udp = Handle(0);
        let rc = l.uv_udp_init(&mut udp);
        debug_assert_eq!(rc, 0);
        let mut timer = Handle(0);
        let _ = l.uv_timer_init(&mut timer);
        {
            let s = &mut self.sockets[sock];
            s.uv_udp = Some(udp);
            s.read_timer = Some(timer);
        }
        let fd = match lx::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(_) => return Res::Unset,
        };
        let rc = l.uv_udp_open(udp, fd);
        if rc != 0 {
            return code_to_res(rc);
        }
        let local = self.sockets[sock].iface;
        if let Err(_) = lx::bind(fd, &sockaddr_in(local)) {
            return Res::AddrInUse;
        }
        self.set_network_buffers(l, sock);
        // uv_udp_connect: the connect(2) and the libuv connected flag (the
        // send path's `uv__udp_check_before_send` reads it).
        let rc = l.uv_udp_connect(udp, Some(&Addr::v4_loopback(peer.port)));
        if rc != 0 {
            return code_to_res(rc);
        }
        Res::Success
    }

    /// `isc__nm_udp_failed_connect_cb` (the UDP connect failure path).
    fn udp_failed_connect_cb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        result: Res,
        async_: bool,
    ) {
        self.sockets[sock].connecting = false;
        self.timer_stop(l, sock);
        let cb = self.sockets[sock].connect_cb.take();
        if let Some(cb) = cb {
            self.socket_clearcb(sock);
            self.nm_connectcb(l, sock, handle, cb, result, async_);
        }
        self.socket_prep_destroy(l, sock);
    }

    /// `isc__nm_connectcb`: fire the connect cb, then put the uvreq (which
    /// detaches the req's handle and the req's socket).  The cb lives in
    /// the req (`isc__nm_uvreq_t`), so it is passed explicitly — the
    /// failure path clears the socket's copy first.
    fn nm_connectcb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        result: Res,
        async_: bool,
    ) {
        if async_ {
            let job = Box::new(move |inner: &mut LoopInner, l: &mut UvLoop| {
                let mut cb = cb;
                cb(&mut *inner, &mut *l, handle, res_to_code(result));
                inner.uvreq_put(l, sock, handle);
            });
            self.job_dispatch(l, job);
        } else {
            let mut cb = cb;
            cb(self, l, handle, res_to_code(result));
            self.uvreq_put(l, sock, handle);
        }
    }

    // -- handle lifecycle ---------------------------------------------

    /// `isc__nmhandle_get`.
    fn handle_get(
        &mut self,
        _l: &mut UvLoop,
        sock: SocketId,
        peer: Option<SockAddr>,
        local: Option<SockAddr>,
    ) -> HandleId {
        let h = if let Some(h) = self.sockets[sock].inactive_handles.pop_front() {
            self.sockets[sock].inactive_handles_cur -= 1;
            self.handles[h].refs = 1;
            h
        } else {
            let h = self.handles.len();
            self.handles.push(HandleObj {
                refs: 1,
                sock: None,
                peer: SockAddr::loopback(0),
                local: SockAddr::loopback(0),
            });
            h
        };
        // isc___nmsocket_attach (rsock rule).
        self.rsock_attach(sock);
        {
            let hobj = &mut self.handles[h];
            hobj.sock = Some(sock);
            hobj.peer = peer.unwrap_or(self.sockets[sock].peer);
            hobj.local = local.unwrap_or(self.sockets[sock].iface);
        }
        self.sockets[sock].active_handles.push(h);
        self.sockets[sock].active_handles_cur += 1;
        let is_client = self.sockets[sock].client;
        let is_tcp = self.sockets[sock].kind == SockKind::TcpSocket;
        if is_client || is_tcp {
            debug_assert!(self.sockets[sock].statichandle.is_none());
            self.sockets[sock].statichandle = Some(h);
        }
        h
    }

    /// `isc_nmhandle_attach(handle, &h2)`.
    pub fn handle_attach(&mut self, h: HandleId) -> HandleId {
        self.handles[h].refs += 1;
        h
    }

    /// `isc_nmhandle_detach(&h)`.
    pub fn handle_detach(&mut self, l: &mut UvLoop, h: &mut Option<HandleId>) {
        let Some(h) = h.take() else { return };
        self.handle_detach_inner(l, h);
    }

    fn handle_detach_inner(&mut self, l: &mut UvLoop, h: HandleId) {
        self.handles[h].refs -= 1;
        if self.handles[h].refs == 0 {
            self.handle_destroy(l, h);
        }
    }

    /// `isc_nmhandle_ref`/`unref`.
    pub fn handle_ref(&mut self, h: HandleId) {
        self.handles[h].refs += 1;
    }

    pub fn handle_unref(&mut self, l: &mut UvLoop, h: HandleId) {
        self.handle_detach_inner(l, h);
    }

    /// `nmhandle_destroy`.
    fn handle_destroy(&mut self, l: &mut UvLoop, h: HandleId) {
        let sock = self.handles[h].sock.expect("live handle sock");
        let closehandle = self.sockets[sock].closehandle_cb;
        if self.sockets[sock].statichandle == Some(h) {
            self.sockets[sock].statichandle = None;
        }
        if let Some(pos) = self.sockets[sock]
            .active_handles
            .iter()
            .position(|&x| x == h)
        {
            self.sockets[sock].active_handles.remove(pos);
            self.sockets[sock].active_handles_cur -= 1;
        }
        if closehandle {
            // isc_job_run(loop, &handle->job, isc__nm_closehandle_job, handle).
            self.job_dispatch(
                l,
                Box::new(move |inner, l| {
                    inner.handle_free_or_pool(l, sock, h);
                }),
            );
            return;
        }
        self.handle_free_or_pool(l, sock, h);
    }

    /// `nmhandle__destroy`: pool (socket active) or free, then socket detach.
    fn handle_free_or_pool(&mut self, l: &mut UvLoop, sock: SocketId, h: HandleId) {
        let active = self.sockets[sock].active;
        let poolable = active && self.sockets[sock].inactive_handles_cur < 64;
        self.handles[h].sock = None;
        if poolable {
            self.sockets[sock].inactive_handles_cur += 1;
            self.sockets[sock].inactive_handles.push_back(h);
        }
        self.socket_detach(l, sock);
    }

    // -- socket lifecycle ---------------------------------------------

    /// `isc__nmsocket_init`: a fresh socket with refs=1.
    fn socket_new(
        &mut self,
        kind: SockKind,
        iface: SockAddr,
        parent: Option<SocketId>,
    ) -> SocketId {
        let id = self.sockets.len();
        self.sockets.push(Socket {
            kind,
            tid: self.tid,
            refs: 1,
            parent,
            server: None,
            shared_refs: None,
            children: Vec::new(),
            nchildren: 0,
            listen_barrier: None,
            stop_barrier: None,
            iface,
            peer: SockAddr::loopback(0),
            active: true,
            closing: false,
            closed: false,
            destroying: false,
            connecting: false,
            connected: false,
            accepting: false,
            reading: false,

            timedout: false,
            client: false,
            keepalive: false,
            manual_read_timer: false,
            statichandle: None,
            active_handles: Vec::new(),
            active_handles_cur: 0,
            inactive_handles: VecDeque::new(),
            inactive_handles_cur: 0,
            uv_udp: None,
            uv_tcp: None,
            read_timer: None,
            recv_cb: None,
            accept_cb: None,
            connect_cb: None,
            read_timeout: 0,
            connect_timeout: 0,
            write_timeout: 0,
            pending_write_timers: 0,
            closehandle_cb: false,
            timer_armed: false,
            active_uvreqs: 0,
        });
        if parent.is_none() {
            self.active_sockets.push(id);
        }
        id
    }

    fn socket_attach_ref(&mut self, sock: SocketId) {
        self.rsock_attach(sock);
    }

    /// The rsock attach: the shared cell when this socket is a listener-tree
    /// member, else the parent (or itself) plain field.
    fn rsock_attach(&mut self, sock: SocketId) {
        if let Some(arc) = self.sockets[sock].shared_refs.clone() {
            arc.fetch_add(1, Ordering::AcqRel);
        } else {
            let rsock = self.sockets[sock].parent.unwrap_or(sock);
            self.sockets[rsock].refs += 1;
        }
    }

    /// The rsock detach; returns true when the refcount hit zero (the C's
    /// isc_refcount_decrement pre-decrement == 1).
    fn rsock_detach(&mut self, sock: SocketId) -> bool {
        if let Some(arc) = self.sockets[sock].shared_refs.clone() {
            let prev = arc.fetch_sub(1, Ordering::AcqRel);
            return prev == 1;
        }
        let rsock = self.sockets[sock].parent.unwrap_or(sock);
        self.sockets[rsock].refs -= 1;
        self.sockets[rsock].refs == 0
    }

    /// The rsock refcount (for the probe's `sock refs` prints).
    fn rsock_refs(&self, sock: SocketId) -> u32 {
        if let Some(arc) = &self.sockets[sock].shared_refs {
            return arc.load(Ordering::Acquire);
        }
        let rsock = self.sockets[sock].parent.unwrap_or(sock);
        self.sockets[rsock].refs
    }

    /// `isc__nm_set_network_buffers`: apply the configured SO_RCVBUF/
    /// SO_SNDBUF to a freshly opened socket.  The court's
    /// setnetbuffers(1024,2048,4096,8192) shrinks the TCP buffers so the
    /// 131072-byte writes take the uv_write path (partial uv_try_write) and
    /// the probe observes the write-timer handle ref — exactly like the
    /// oracle.  Accepted sockets are NOT configured (the C's
    /// accept_connection doesn't call this); their writes still throttle on
    /// the client's small receive window.
    fn set_network_buffers(&mut self, l: &mut UvLoop, sock: SocketId) {
        let (r, s) = match self.sockets[sock].kind {
            SockKind::TcpSocket | SockKind::TcpListener => (
                self.nm.recv_tcp_buffer_size.load(Ordering::Relaxed),
                self.nm.send_tcp_buffer_size.load(Ordering::Relaxed),
            ),
            SockKind::UdpSocket | SockKind::UdpListener => (
                self.nm.recv_udp_buffer_size.load(Ordering::Relaxed),
                self.nm.send_udp_buffer_size.load(Ordering::Relaxed),
            ),
        };
        let h = match self.sockets[sock].kind {
            SockKind::UdpSocket | SockKind::UdpListener => self.sockets[sock].uv_udp,
            _ => self.sockets[sock].uv_tcp,
        };
        let Some(h) = h else { return };
        if r > 0 {
            let mut v = r;
            let _ = l.uv_recv_buffer_size(h, &mut v);
        }
        if s > 0 {
            let mut v = s;
            let _ = l.uv_send_buffer_size(h, &mut v);
        }
    }

    /// `isc__nmsocket_detach`.
    pub fn socket_detach(&mut self, l: &mut UvLoop, sock: SocketId) {
        if !self.rsock_detach(sock) {
            return;
        }
        // The last ref is gone.  For a listener-tree member the destroyed
        // socket is the parent, which lives on loop 0 (the listener loops
        // assert isc_tid() == 0); dispatch the destroy there.  Standalone
        // sockets destroy on their own loop.
        let rsock = self.sockets[sock].parent.unwrap_or(sock);
        if self.sockets[sock].shared_refs.is_some() && self.sockets[sock].parent.is_some() {
            let mailbox = self.all_mailboxes[0].clone();
            mailbox.send(Box::new(move |inner, l| {
                inner.socket_prep_destroy(l, rsock);
            }));
        } else {
            self.socket_prep_destroy(l, rsock);
        }
    }

    /// `isc___nmsocket_prep_destroy`: the final external reference to the
    /// socket is gone.  Mark it inactive; if it is a live socket that was
    /// never closed, run the type-specific close (needs the loop) and stop.
    /// Otherwise try to destroy the socket once the inflight handles are
    /// done.
    fn socket_prep_destroy(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].active = false;
        if !self.sockets[sock].closing && !self.sockets[sock].closed {
            match self.sockets[sock].kind {
                SockKind::UdpSocket => {
                    self.udp_close(l, sock);
                    return;
                }
                SockKind::TcpSocket => {
                    self.tcp_close(l, sock);
                    return;
                }
                SockKind::UdpListener | SockKind::TcpListener => {}
            }
        }
        self.socket_maybe_destroy_unloop(sock);
    }

    /// `nmsocket_maybe_destroy`.
    fn socket_maybe_destroy_unloop(&mut self, sock: SocketId) {
        if let Some(parent) = self.sockets[sock].parent {
            self.socket_maybe_destroy_unloop(parent);
            return;
        }
        if !self.sockets[sock].closed {
            return;
        }
        if self.rsock_refs(sock) != 0 {
            return;
        }
        if self.sockets[sock].statichandle.is_none()
            && !self.sockets[sock].active_handles.is_empty()
        {
            return;
        }
        self.socket_cleanup(sock);
    }

    /// `nmsocket_cleanup`.
    fn socket_cleanup(&mut self, sock: SocketId) {
        self.sockets[sock].destroying = true;
        if self.sockets[sock].parent.is_none() {
            for i in 0..self.sockets[sock].nchildren as usize {
                let sid = *self.sockets[sock].children[i].socket_id.lock().unwrap();
                if let Some(cid) = sid {
                    self.socket_cleanup(cid);
                }
            }
        }
        while let Some(h) = self.sockets[sock].inactive_handles.pop_front() {
            self.sockets[sock].inactive_handles_cur -= 1;
            self.handles[h].sock = None;
        }
        if self.sockets[sock].parent.is_none() {
            if let Some(pos) = self.active_sockets.iter().position(|&x| x == sock) {
                self.active_sockets.remove(pos);
            }
        }
    }

    /// `isc__nmsocket_closing` (the C's active||closing||worker-shutdown ||
    /// server-inactive rule).
    fn socket_is_closing(&self, sock: SocketId) -> bool {
        !self.sockets[sock].active
            || self.sockets[sock].closing
            || self.nm_closing()
            || (self.sockets[sock].server.is_some()
                && !self.sockets[self.sockets[sock].server.unwrap()].active)
    }

    /// `isc__nmsocket_timer_running`.
    pub fn socket_timer_running(&self, sock: SocketId) -> bool {
        self.sockets[sock].timer_armed
    }

    fn timer_start(&mut self, l: &mut UvLoop, sock: SocketId, timeout: u64, connect: bool) {
        let timer = self.sockets[sock].read_timer.unwrap();
        let weak = self.self_weak.clone();
        let _ = l.uv_timer_start(
            timer,
            Some(Box::new(move |l: &mut UvLoop| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    if connect {
                        inner.connect_timeout_cb(l, sock);
                    } else {
                        inner.read_timeout_cb(l, sock);
                    }
                }
            })),
            timeout,
            0,
        );
        self.sockets[sock].timer_armed = true;
    }

    fn timer_stop(&mut self, l: &mut UvLoop, sock: SocketId) {
        if let Some(timer) = self.sockets[sock].read_timer {
            let _ = l.uv_timer_stop(timer);
        }
        self.sockets[sock].timer_armed = false;
    }

    /// `isc__nmsocket_timer_restart`.
    fn timer_restart(&mut self, l: &mut UvLoop, sock: SocketId) {
        if self.sockets[sock].connecting {
            let ct = self.sockets[sock].connect_timeout;
            if ct == 0 {
                return;
            }
            self.timer_start(l, sock, ct + 10, true);
        } else {
            let rt = self.sockets[sock].read_timeout;
            if rt == 0 {
                return;
            }
            self.timer_start(l, sock, rt, false);
        }
    }

    /// `isc__nmsocket_connecttimeout_cb`.
    fn connect_timeout_cb(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.timer_stop(l, sock);
        self.sockets[sock].timedout = true;
        self.socket_shutdown(l, sock);
    }

    /// `isc__nmsocket_readtimeout_cb`.
    fn read_timeout_cb(&mut self, l: &mut UvLoop, sock: SocketId) {
                if self.sockets[sock].client {
            self.timer_stop(l, sock);
            if self.sockets[sock].recv_cb.is_some() {
                let cb = self.sockets[sock].recv_cb.take();
                let handle = self.get_read_req_handle(l, sock, None);
                self.nm_readcb(
                    l,
                    sock,
                    handle,
                    cb,
                    Vec::new(),
                    None,
                    res_to_code(Res::TimedOut),
                    false,
                );
            }
            if !self.socket_timer_running(sock) {
                self.socket_clearcb(sock);
                self.udp_failed_read_cb(l, sock, Res::TimedOut, false);
            }
        } else {
            self.udp_failed_read_cb(l, sock, Res::TimedOut, false);
        }
    }

    /// `isc__nmsocket_clearcb`.
    fn socket_clearcb(&mut self, sock: SocketId) {
        let s = &mut self.sockets[sock];
        s.recv_cb = None;
        s.accept_cb = None;
        s.connect_cb = None;
    }

    /// `isc__nmsocket_shutdown` dispatch.
    fn socket_shutdown(&mut self, l: &mut UvLoop, sock: SocketId) {
        match self.sockets[sock].kind {
            SockKind::UdpSocket => self.udp_shutdown(l, sock),
            SockKind::TcpSocket => self.tcp_shutdown(l, sock),
            SockKind::UdpListener | SockKind::TcpListener => {}
        }
    }

    // -- the read/send/connect dispatch glue --------------------------

    /// `isc__nm_get_read_req`: attach the statichandle (TCP client or server,
    /// and UDP client) or get a fresh handle (UDP server, peer = the
    /// datagram source).  The read req also holds a socket ref
    /// (`isc__nm_uvreq_get`), released by `read_req_put`.
    fn get_read_req_handle(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        peer: Option<SockAddr>,
    ) -> HandleId {
        let is_tcp = self.sockets[sock].kind == SockKind::TcpSocket;
        self.socket_attach_ref(sock);
        if self.sockets[sock].statichandle.is_some() && (is_tcp || self.sockets[sock].client) {
            let h = self.sockets[sock].statichandle.unwrap();
            self.handles[h].refs += 1;
            h
        } else {
            self.handle_get(l, sock, peer, None)
        }
    }

    /// `isc__nm_uvreq_put` for read reqs: detach the handle and the req's
    /// socket ref (the mirror of `isc__nm_uvreq_get`'s socket attach).
    fn read_req_put(&mut self, l: &mut UvLoop, sock: SocketId, handle: HandleId) {
        self.handle_detach_inner(l, handle);
        self.socket_detach(l, sock);
    }

    /// `isc__nm_readcb`: fire the recv cb, then put the read req (handle
    /// detach).  The caller captures the cb before any clearcb; the put is
    /// done here (`isc__nm_uvreq_put` is folded into the caller), so the
    /// socket id is only needed for the async job's closure.
    fn nm_readcb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: Option<Arc<Mutex<RecvCb>>>,
        data: Vec<u8>,
        peer: Option<SockAddr>,
        result: i32,
        async_: bool,
    ) {
        if async_ {
            let job = make_recv_job(cb, sock, handle, result, data, peer);
            self.job_dispatch(l, job);
        } else if let Some(cb) = cb {
            let mut guard = cb.lock().unwrap();
            guard(self, l, handle, result, data, peer);
            drop(guard);
            self.read_req_put(l, sock, handle);
        }
    }

    /// `isc__nm_sendcb` — the send completion; cb + uvreq_put (the C's
    /// `isc___nm_sendcb`).
    fn nm_sendcb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        result: i32,
        async_: bool,
    ) {
        if async_ {
            let job = Box::new(move |inner: &mut LoopInner, l: &mut UvLoop| {
                let mut cb = cb;
                cb(&mut *inner, &mut *l, handle, result);
                inner.uvreq_put(l, sock, handle);
            });
            self.job_dispatch(l, job);
        } else {
            let mut cb = cb;
            cb(self, l, handle, result);
            self.uvreq_put(l, sock, handle);
        }
    }

    /// `isc__nm_uvreq_put`: detach the req's handle and the req's socket.
    fn uvreq_put(&mut self, l: &mut UvLoop, sock: SocketId, handle: HandleId) {
        self.sockets[sock].active_uvreqs = self.sockets[sock].active_uvreqs.saturating_sub(1);
        self.handle_detach_inner(l, handle);
        self.socket_detach(l, sock);
    }

    // -- UDP paths ----------------------------------------------------

    /// `isc__nm_udp_read`.
    pub fn udp_read(&mut self, l: &mut UvLoop, handle: HandleId, cb: RecvCb) {
        let sock = self.handles[handle].sock.unwrap();
        debug_assert_eq!(self.sockets[sock].kind, SockKind::UdpSocket);
        debug_assert_eq!(self.sockets[sock].statichandle, Some(handle));
        self.sockets[sock].recv_cb = Some(Arc::new(Mutex::new(cb)));
        self.sockets[sock].reading = true;
        let result = if self.nm_closing() {
            Res::ShuttingDown
        } else if self.socket_is_closing(sock) {
            Res::Canceled
        } else {
            let rc = self.start_reading(l, sock);
            if rc != 0 {
                Res::Unset
            } else {
                self.timer_restart(l, sock);
                return;
            }
        };
        // fail path: `sock->reading = true; isc__nm_failed_read_cb(..., true)`.
        self.sockets[sock].reading = true;
        self.udp_failed_read_cb(l, sock, result, true);
    }

    /// `isc__nm_udp_send`.
    pub fn udp_send(&mut self, l: &mut UvLoop, handle: HandleId, data: &[u8], cb: SendCb) {
        let sock = self.handles[handle].sock.unwrap();
        debug_assert_eq!(self.sockets[sock].kind, SockKind::UdpSocket);
        let peer = self.handles[handle].peer;
        let maxudp = self.nm.maxudp.load(Ordering::Relaxed);
        if maxudp != 0 && data.len() as u32 > maxudp {
            // The firewall simulation: the netmgr detaches the handle the
            // caller passed; the send cb never fires.
            self.handle_detach_inner(l, handle);
            return;
        }
        // isc__nm_uvreq_get(sock) + isc_nmhandle_attach(handle, &req->handle).
        self.socket_attach_ref(sock);
        self.handles[handle].refs += 1;
        self.sockets[sock].active_uvreqs += 1;
        if self.nm_closing() {
            self.failed_udp_send(l, sock, handle, cb, Res::ShuttingDown, true);
            return;
        }
        if self.socket_is_closing(sock) {
            self.failed_udp_send(l, sock, handle, cb, Res::Canceled, true);
            return;
        }
        let udp = self.sockets[sock].uv_udp.unwrap();
        let sa = if self.sockets[sock].connected {
            None
        } else {
            Some(Addr::v4_loopback(peer.port))
        };
        let queue = l.uv_udp_get_send_queue_size(udp);
        if queue > 65535 {
            // The kernel send queue is full: try_send synchronously.
            let n = l.uv_udp_try_send(udp, data, sa.as_ref());
            if n < 0 {
                self.failed_udp_send(l, sock, handle, cb, Res::Unset, true);
                return;
            }
            self.nm_sendcb(l, sock, handle, cb, res_to_code(Res::Success), true);
        } else {
            // The uvreq's cb slot: the deferred uv callback and the
            // immediate failure path each consume it exactly once (the C's
            // `udp_send_cb` / `fail:` label on the same req).
            let cbcell = Rc::new(RefCell::new(Some(cb)));
            let cbcell_cb = cbcell.clone();
            let weak = self.self_weak.clone();
            let udp_cb: UdpSendCb = Box::new(move |l: &mut UvLoop, status: i32| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    let cb = cbcell_cb.borrow_mut().take().expect("udp send cb");
                    inner.udp_send_complete(l, sock, handle, cb, status);
                }
            });
            let rc = l.uv_udp_send(udp, &[data.to_vec()], sa.as_ref(), udp_cb);
            if rc < 0 {
                let cb = cbcell.borrow_mut().take().expect("udp send cb");
                self.failed_udp_send(l, sock, handle, cb, Res::Unset, true);
            }
        }
    }

    fn udp_send_complete(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        status: i32,
    ) {
                let result = if status < 0 {
            code_to_res(status)
        } else {
            Res::Success
        };
        self.nm_sendcb(l, sock, handle, cb, res_to_code(result), false);
    }

    fn failed_udp_send(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        result: Res,
        async_: bool,
    ) {
        self.nm_sendcb(l, sock, handle, cb, res_to_code(result), async_);
    }

    /// `isc__nm_udp_read_cb`: a datagram arrived on the UDP handle.
    pub fn udp_recv_event(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        nread: i64,
        data: Vec<u8>,
        peer: Option<SockAddr>,
    ) {
                let maxudp = self.nm.maxudp.load(Ordering::Relaxed);
        if maxudp != 0 && nread as u32 > maxudp {
            return; // the datagram is dropped (firewall simulation)
        }
        if nread < 0 {
            self.udp_failed_read_cb(l, sock, Res::Unset, false);
            return;
        }
        if self.nm_closing() {
            self.udp_failed_read_cb(l, sock, Res::ShuttingDown, false);
            return;
        }
        if !self.sockets[sock].active {
            self.udp_failed_read_cb(l, sock, Res::Canceled, false);
            return;
        }
        if nread == 0 && peer.is_none() {
            return; // the EAGAIN drain marker
        }
        let handle = self.get_read_req_handle(l, sock, peer);
        self.sockets[sock].reading = false;
        // The cb is captured into the read req before the client cleanup
        // (isc__nm_get_read_req copies sock->recv_cb before the clearcb).
        // The server's recv_cb is permanent (set at listen; the Arc stays in
        // the socket); the client's is cleared by the clearcb and re-armed
        // by the next isc_nm_read.
        let cb = self.sockets[sock].recv_cb.clone();
        if self.sockets[sock].client {
            self.timer_stop(l, sock);
            self.stop_reading(l, sock);
            self.socket_clearcb(sock);
        }
        let result = res_to_code(Res::Success);
        if let Some(cb) = cb {
            let mut guard = cb.lock().unwrap();
            guard(self, l, handle, result, data, peer);
            drop(guard);
            self.read_req_put(l, sock, handle);
        }
    }

    /// `isc__nm_udp_failed_read_cb`.
    fn udp_failed_read_cb(&mut self, l: &mut UvLoop, sock: SocketId, result: Res, async_: bool) {
        if self.sockets[sock].client {
            self.timer_stop(l, sock);
            self.stop_reading(l, sock);
        }
        if self.sockets[sock].reading {
            self.sockets[sock].reading = false;
            if self.sockets[sock].recv_cb.is_some() {
                let cb = self.sockets[sock].recv_cb.take();
                let handle = self.get_read_req_handle(l, sock, None);
                self.nm_readcb(
                    l,
                    sock,
                    handle,
                    cb,
                    Vec::new(),
                    None,
                    res_to_code(result),
                    async_,
                );
            }
        }
        if self.sockets[sock].client {
            self.socket_clearcb(sock);
            self.socket_prep_destroy(l, sock);
        }
    }

    /// `isc__nm_udp_close`.
    fn udp_close(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closing = true;
        self.socket_clearcb(sock);
        self.timer_stop(l, sock);
        self.stop_reading(l, sock);
        let udp = self.sockets[sock].uv_udp.unwrap();
        let weak = self.self_weak.clone();
        l.uv_close(
            udp,
            Some(Box::new(move |l: &mut UvLoop| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    inner.udp_close_cb(l, sock);
                }
            })),
        );
        if let Some(timer) = self.sockets[sock].read_timer {
            l.uv_close(timer, None);
        }
    }

    /// `udp_close_cb`.
    fn udp_close_cb(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closed = true;
        if self.sockets[sock].parent.is_some() {
            self.socket_detach(l, sock);
        } else {
            self.sockets[sock].connected = false;
            self.socket_prep_destroy(l, sock);
        }
    }

    /// `isc__nm_udp_shutdown`.
    fn udp_shutdown(&mut self, l: &mut UvLoop, sock: SocketId) {
        if !self.sockets[sock].active {
            return;
        }
        self.sockets[sock].active = false;
        if self.sockets[sock].statichandle.is_some() {
            self.udp_failed_read_cb(l, sock, Res::ShuttingDown, false);
            return;
        }
        if self.sockets[sock].parent.is_none() {
            self.socket_prep_destroy(l, sock);
            return;
        }
        // The parent lives on the loop that created it, and the listeners
        // assert isc_tid() == 0 — so a child on loop 0 shares its loop with
        // the parent and runs the parent's destroy here; children on other
        // loops leave it to loop 0's teardown.
        if self.sockets[sock].tid == 0 {
            self.socket_prep_destroy(l, self.sockets[sock].parent.unwrap());
        }
    }

    /// `isc__nm_udp_stoplistening`.
    fn udp_stoplistening(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closing = true;
        self.sockets[sock].active = false;
        let nchildren = self.sockets[sock].nchildren;
        for i in 1..nchildren {
            let tid = self.sockets[sock].children[i as usize].tid;
            let sid = *self.sockets[sock].children[i as usize]
                .socket_id
                .lock()
                .unwrap();
            let bar = self.sockets[sock].stop_barrier.clone().unwrap();
            let mailbox = self.all_mailboxes[tid as usize].clone();
            mailbox.send(Box::new(move |inner, l| {
                if let Some(cid) = sid {
                    inner.stop_udp_child_job(l, cid, bar);
                }
            }));
        }
        let sid0 = *self.sockets[sock].children[0].socket_id.lock().unwrap();
        let bar = self.sockets[sock].stop_barrier.clone().unwrap();
        if let Some(cid) = sid0 {
            self.stop_udp_child_job(l, cid, bar);
        }
        self.sockets[sock].closed = true;
        self.socket_prep_destroy(l, sock);
    }

    fn stop_udp_child_job(&mut self, l: &mut UvLoop, sock: SocketId, bar: Arc<Barrier>) {
        self.sockets[sock].active = false;
        self.udp_close(l, sock);
        bar.wait();
    }

    // -- TCP paths ----------------------------------------------------

    /// `isc_nm_listentcp`.
    pub fn listentcp(
        &mut self,
        l: &mut UvLoop,
        workers: u32,
        iface: SockAddr,
        cb: AcceptCb,
        backlog: i32,
    ) -> Result<SocketId, Res> {
        assert_eq!(self.tid, 0, "isc_nm_listentcp requires isc_tid() == 0");
        if self.nm_closing() {
            return Err(Res::ShuttingDown);
        }
        let workers = if workers == 0 {
            self.nm.nloops
        } else {
            workers
        };
        assert!(workers <= self.nm.nloops);

        let parent = self.socket_new(SockKind::TcpListener, iface, None);
        let nchildren = workers;
        let listen_barrier = Arc::new(Barrier::new(nchildren as usize));
        let stop_barrier = Arc::new(Barrier::new(nchildren as usize));

        let mut children = Vec::new();
        for tid in 0..nchildren {
            children.push(ChildSlot {
                tid,
                result: Arc::new(AtomicI32::new(res_to_code(Res::Unset))),
                socket_id: Arc::new(Mutex::new(None)),
            });
        }
        {
            let sock = &mut self.sockets[parent];
            sock.nchildren = nchildren;
            sock.children = children;
            sock.listen_barrier = Some(listen_barrier.clone());
            sock.stop_barrier = Some(stop_barrier.clone());
            sock.accept_cb = Some(Arc::new(Mutex::new(cb)));
            // The tree's shared refcount starts at the parent's initial
            // refs=1; children attach/detach against this same cell.
            sock.shared_refs = Some(Arc::new(AtomicU32::new(1)));
        }

        self.start_tcp_child(l, parent, 0, backlog);
        let result = self.sockets[parent].children[0]
            .result
            .load(Ordering::Acquire);
        for tid in 1..nchildren {
            self.start_tcp_child(l, parent, tid, backlog);
        }
        listen_barrier.wait();

        let mut result = code_to_res(result);
        for i in 1..nchildren {
            let r = self.sockets[parent].children[i as usize]
                .result
                .load(Ordering::Acquire);
            if result == Res::Success && code_to_res(r) != Res::Success {
                result = code_to_res(r);
            }
        }

        if result != Res::Success {
            self.sockets[parent].active = false;
            self.tcp_stoplistening(l, parent);
            self.socket_detach(l, parent);
            return Err(result);
        }

        self.sockets[parent].active = true;
        Ok(parent)
    }

    fn start_tcp_child(&mut self, l: &mut UvLoop, parent: SocketId, tid: u32, backlog: i32) {
        let iface = self.sockets[parent].iface;
        // The shared accept cb (isc__nm_tcp_listen's `csock->accept_cb =
        // sock->accept_cb`): each child holds a copy of the same Arc.
        let cb = self.sockets[parent]
            .accept_cb
            .clone()
            .expect("listentcp accept cb");
        // The tree's shared refcount (children count against the parent
        // through their own copy of this Arc).
        let shared = self.sockets[parent].shared_refs.clone().unwrap();
        let slot_result = self.sockets[parent].children[tid as usize].result.clone();
        let slot_id = self.sockets[parent].children[tid as usize]
            .socket_id
            .clone();
        let barrier = self.sockets[parent].listen_barrier.clone().unwrap();

        let job: Job = Box::new(move |inner, l| {
            let child = inner.socket_new(SockKind::TcpSocket, iface, Some(parent));
            inner.sockets[child].shared_refs = Some(shared);
            *slot_id.lock().unwrap() = Some(child);
            inner.tcp_child_open(l, child, cb, &slot_result, tid != 0, barrier, backlog);
        });
        if tid == 0 {
            job(self, l);
        } else {
            let mailbox = self.all_mailboxes[tid as usize].clone();
            mailbox.send(job);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_child_open(
        &mut self,
        l: &mut UvLoop,
        child: SocketId,
        accept_cb: Arc<Mutex<AcceptCb>>,
        result: &Arc<AtomicI32>,
        wait_barrier: bool,
        barrier: Arc<Barrier>,
        backlog: i32,
    ) {
        let mut tcp = Handle(0);
        let rc = l.uv_tcp_init(&mut tcp);
        debug_assert_eq!(rc, 0);
        let mut timer = Handle(0);
        let _ = l.uv_timer_init(&mut timer);
        {
            // The self-keep attach counts against the parent (rsock rule) —
            // through the child's copy of the shared cell.
            self.rsock_attach(child);
            let sock = &mut self.sockets[child];
            sock.uv_tcp = Some(tcp);
            sock.read_timer = Some(timer);
            sock.accept_cb = Some(accept_cb);
        }

        let fd = match lx::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                result.store(res_to_code(Res::Unset), Ordering::Release);
                if wait_barrier {
                    barrier.wait();
                }
                return;
            }
        };
        // isc__nm_tcp_lb_socket (tcp.c): SO_REUSEADDR on every listener,
        // plus SO_REUSEPORT when load balancing, so the nloops children can
        // bind the same address.
        let mut on = 1;
        let _ = lx::socket_sockopt(fd, libc::SO_REUSEADDR, &mut on);
        if self.nm.load_balance {
            let _ = lx::socket_sockopt(fd, libc::SO_REUSEPORT, &mut on);
        }
        let rc = l.uv_tcp_open(tcp, fd);
        if rc < 0 {
            lx::close(fd);
            result.store(res_to_code(Res::Unset), Ordering::Release);
            if wait_barrier {
                barrier.wait();
            }
            return;
        }
        let iface = self.sockets[child].iface;
        let rc = l.uv_tcp_bind(tcp, &Addr::v4_loopback(iface.port));
        if rc < 0 {
            result.store(res_to_code(Res::Unset), Ordering::Release);
            if wait_barrier {
                barrier.wait();
            }
            return;
        }
        self.set_network_buffers(l, child);
        let weak = self.self_weak.clone();
        let rc = l.uv_listen(
            tcp,
            backlog,
            Box::new(move |l: &mut UvLoop| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    inner.tcp_connection_cb(l, child);
                }
            }),
        );
        if rc != 0 {
            result.store(res_to_code(Res::Unset), Ordering::Release);
            if wait_barrier {
                barrier.wait();
            }
            return;
        }
        result.store(res_to_code(Res::Success), Ordering::Release);
        if wait_barrier {
            barrier.wait();
        }
    }

    /// `tcp_connection_cb` + `accept_connection`.
    fn tcp_connection_cb(&mut self, l: &mut UvLoop, ssock: SocketId) {
        let csock = self.socket_new(SockKind::TcpSocket, self.sockets[ssock].iface, None);
        self.sockets[csock].server = Some(ssock);
        // isc__nmsocket_attach(ssock, &csock->server).
        self.sockets[ssock].refs += 1;
        let _ = self.accept_connection(l, csock);
    }

    fn accept_connection(&mut self, l: &mut UvLoop, csock: SocketId) -> Res {
        let ssock = self.sockets[csock].server.unwrap();
        self.sockets[csock].accepting = true;
        self.sockets[csock].recv_cb = None;
        self.sockets[csock].read_timeout = u64::from(self.nm.init.load(Ordering::Relaxed));

        let mut tcp = Handle(0);
        let _ = l.uv_tcp_init(&mut tcp);
        let mut timer = Handle(0);
        let _ = l.uv_timer_init(&mut timer);
        {
            let s = &mut self.sockets[csock];
            s.uv_tcp = Some(tcp);
            s.read_timer = Some(timer);
        }
        let srv = self.sockets[ssock].uv_tcp.unwrap();
        let rc = l.uv_accept(srv, &mut tcp);
                if rc != 0 {
            self.accept_failure(l, csock);
            return code_to_res(rc);
        }
        self.sockets[csock].connected = false;
        self.sockets[csock].client = false;
        // The local address is the listener's; the peer is the accepted
        // connection's source (uv_tcp_getpeername).
        let local = self.sockets[csock].iface;
        let tcp = self.sockets[csock].uv_tcp.unwrap();
        let peer_port = l.uv_tcp_getpeername(tcp);
        self.sockets[csock].peer = SockAddr::loopback(peer_port);

        let handle = self.handle_get(l, csock, None, Some(local));
        debug_assert_eq!(self.sockets[csock].statichandle, Some(handle));

        // isc__nm_acceptcb: the accept callback is copied to the child
        // listener at start_tcp_child (`csock->accept_cb = sock->accept_cb`)
        // and called for every accepted connection — it is never consumed.
        let cb = self.sockets[ssock].accept_cb.clone();
        let result = if let Some(cb) = cb {
            let mut guard = cb.lock().unwrap();
            let r = guard(self, l, handle, res_to_code(Res::Success));
            r
        } else {
            0
        };
        if result != 0 {
            self.handle_detach_inner(l, handle);
            self.accept_failure(l, csock);
            return Res::Unset;
        }
        self.sockets[csock].accepting = false;
        // The netmgr detaches its accept handle after the cb.
        self.handle_detach_inner(l, handle);
        self.socket_detach(l, csock);
        Res::Success
    }

    fn accept_failure(&mut self, l: &mut UvLoop, csock: SocketId) {
        self.sockets[csock].active = false;
        self.sockets[csock].accepting = false;
        self.socket_prep_destroy(l, csock);
        self.socket_detach(l, csock);
    }

    /// `isc_nm_tcpconnect`.
    pub fn tcpconnect(
        &mut self,
        l: &mut UvLoop,
        local: SockAddr,
        peer: SockAddr,
        cb: SendCb,
        timeout: u32,
    ) {
        if self.nm_closing() {
            return;
        }
        let sock = self.socket_new(SockKind::TcpSocket, local, None);
        {
            let s = &mut self.sockets[sock];
            s.connect_timeout = u64::from(timeout);
            s.client = true;
            s.connect_cb = Some(cb);
            s.peer = peer;
        }
        // isc__nm_uvreq_get(sock) + req->handle = isc__nmhandle_get(...).
        self.socket_attach_ref(sock);
        self.sockets[sock].active_uvreqs += 1;
        let handle = self.handle_get(l, sock, Some(peer), Some(local));
        self.sockets[sock].active = true;

        let result = self.tcp_connect_direct(l, sock, handle, peer, local);
        if result != Res::Success {
            self.sockets[sock].active = false;
            let cb = self.sockets[sock]
                .connect_cb
                .take()
                .expect("tcp connect cb");
            self.tcp_close(l, sock);
            self.nm_connectcb(l, sock, handle, cb, result, true);
        }
        self.socket_detach(l, sock);
    }

    fn tcp_connect_direct(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        peer: SockAddr,
        local: SockAddr,
    ) -> Res {
        self.sockets[sock].connecting = true;
        let mut tcp = Handle(0);
        let _ = l.uv_tcp_init(&mut tcp);
        let mut timer = Handle(0);
        let _ = l.uv_timer_init(&mut timer);
        {
            let s = &mut self.sockets[sock];
            s.uv_tcp = Some(tcp);
            s.read_timer = Some(timer);
        }
        let fd = match lx::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(_) => return Res::Unset,
        };
        let rc = l.uv_tcp_open(tcp, fd);
        if rc != 0 {
            lx::close(fd);
            return code_to_res(rc);
        }
        let rc = l.uv_tcp_bind(tcp, &Addr::v4_loopback(local.port));
        if rc != 0 {
            return code_to_res(rc);
        }
        self.set_network_buffers(l, sock);
        let weak = self.self_weak.clone();
        let rc = l.uv_tcp_connect(
            tcp,
            &Addr::v4_loopback(peer.port),
            Box::new(move |l: &mut UvLoop, status: i32| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    inner.tcp_connect_cb(l, sock, handle, status);
                }
            }),
        );
        if rc != 0 {
            return code_to_res(rc);
        }
        self.timer_start(l, sock, self.sockets[sock].connect_timeout + 10, true);
        Res::Success
    }

    /// `tcp_connect_cb`.
    fn tcp_connect_cb(&mut self, l: &mut UvLoop, sock: SocketId, handle: HandleId, status: i32) {
        let result = if self.sockets[sock].timedout || status == -110 {
            Res::TimedOut
        } else if self.nm_closing() {
            Res::ShuttingDown
        } else if self.socket_is_closing(sock) {
            Res::Canceled
        } else if status != 0 {
            code_to_res(status)
        } else {
            Res::Success
        };
        if result != Res::Success {
            self.socket_failed_connect_cb(l, sock, handle, result);
            return;
        }
        self.timer_stop(l, sock);
        self.sockets[sock].connecting = false;
        self.sockets[sock].connected = true;
        let cb = self.sockets[sock]
            .connect_cb
            .take()
            .expect("tcp connect cb");
        self.nm_connectcb(l, sock, handle, cb, Res::Success, false);
    }

    /// `isc__nm_failed_connect_cb` (TCP).
    fn socket_failed_connect_cb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        result: Res,
    ) {
        self.sockets[sock].connecting = false;
        self.timer_stop(l, sock);
        let cb = self.sockets[sock].connect_cb.take();
        if let Some(cb) = cb {
            self.socket_clearcb(sock);
            self.nm_connectcb(l, sock, handle, cb, result, false);
        }
        self.socket_prep_destroy(l, sock);
    }

    /// `isc__nm_tcp_read`.
    pub fn tcp_read(&mut self, l: &mut UvLoop, handle: HandleId, cb: RecvCb) {
        let sock = self.handles[handle].sock.unwrap();
        debug_assert_eq!(self.sockets[sock].kind, SockKind::TcpSocket);
        debug_assert_eq!(self.sockets[sock].statichandle, Some(handle));
        self.sockets[sock].recv_cb = Some(Arc::new(Mutex::new(cb)));
        if self.sockets[sock].read_timeout == 0 {
            let v = if self.sockets[sock].keepalive {
                self.nm.keepalive.load(Ordering::Relaxed)
            } else {
                self.nm.idle.load(Ordering::Relaxed)
            };
            self.sockets[sock].read_timeout = u64::from(v);
        }
        if self.socket_is_closing(sock) {
            self.tcp_failed_read_cb(l, sock, Res::Canceled, true);
            return;
        }
        let rc = self.start_reading(l, sock);
        if rc != 0 {
            self.tcp_failed_read_cb(l, sock, Res::Unset, true);
            return;
        }
        self.sockets[sock].reading = true;
        if !self.sockets[sock].manual_read_timer {
            self.timer_start(l, sock, self.sockets[sock].read_timeout, false);
        }
    }

    /// `isc__nm_tcp_read_stop`.
    pub fn tcp_read_stop(&mut self, l: &mut UvLoop, handle: HandleId) {
        let sock = self.handles[handle].sock.unwrap();
        if !self.sockets[sock].manual_read_timer {
            self.timer_stop(l, sock);
        }
        self.stop_reading(l, sock);
        self.sockets[sock].reading = false;
    }

    /// `isc__nm_tcp_failed_read_cb`.
    fn tcp_failed_read_cb(&mut self, l: &mut UvLoop, sock: SocketId, result: Res, async_: bool) {
        self.timer_stop(l, sock);
        self.stop_reading(l, sock);
        self.sockets[sock].reading = false;
        if self.sockets[sock].recv_cb.is_some() {
            let cb = self.sockets[sock].recv_cb.take();
            let handle = self.get_read_req_handle(l, sock, None);
            self.socket_clearcb(sock);
            self.nm_readcb(
                l,
                sock,
                handle,
                cb,
                Vec::new(),
                None,
                res_to_code(result),
                async_,
            );
        }
        self.socket_prep_destroy(l, sock);
    }

    /// `isc__nm_tcp_read_cb` — data arrived on a TCP stream.
    pub fn tcp_recv_event(&mut self, l: &mut UvLoop, sock: SocketId, nread: i64, data: Vec<u8>) {
                if self.socket_is_closing(sock) {
            self.tcp_failed_read_cb(l, sock, Res::Canceled, false);
            return;
        }
        if nread == 0 {
            return;
        }
        if nread < 0 {
            let r = if nread == -4095 {
                Res::Eof
            } else {
                code_to_res(nread as i32)
            };
            self.tcp_failed_read_cb(l, sock, r, false);
            return;
        }
        let handle = self.get_read_req_handle(l, sock, None);
        if !self.sockets[sock].client {
            let v = if self.sockets[sock].keepalive {
                self.nm.keepalive.load(Ordering::Relaxed)
            } else {
                self.nm.idle.load(Ordering::Relaxed)
            };
            self.sockets[sock].read_timeout = u64::from(v);
        }
        let cb = self.sockets[sock].recv_cb.clone();
        let is_client = self.sockets[sock].client;
        if let Some(cb) = cb {
            let mut guard = cb.lock().unwrap();
            guard(self, l, handle, 0, data, None);
            drop(guard);
            self.read_req_put(l, sock, handle);
            // The socket's recv_cb persists across TCP reads (the read req
            // copies it; a new isc_nm_read replaces it) — the Arc stays in
            // the socket.
        }
        if !is_client && self.sockets[sock].reading {
            // the write-queue throttle check (not courted)
        } else if self.socket_timer_running(sock) && !self.sockets[sock].manual_read_timer {
            self.timer_restart(l, sock);
        }
    }

    /// `isc__nm_tcp_send` (raw).
    pub fn tcp_send(&mut self, l: &mut UvLoop, handle: HandleId, data: &[u8], cb: SendCb) {
        let sock = self.handles[handle].sock.unwrap();
        debug_assert_eq!(self.sockets[sock].kind, SockKind::TcpSocket);
        // isc__nm_uvreq_get(sock) + isc_nmhandle_attach(handle, &req->handle).
        self.socket_attach_ref(sock);
        self.handles[handle].refs += 1;
        self.sockets[sock].active_uvreqs += 1;
        if self.sockets[sock].write_timeout == 0 {
            let v = if self.sockets[sock].keepalive {
                self.nm.keepalive.load(Ordering::Relaxed)
            } else {
                self.nm.idle.load(Ordering::Relaxed)
            };
            self.sockets[sock].write_timeout = u64::from(v);
        }
        // The C's `tcp_send_direct` closing check (its only failure), kept
        // in the caller so the req's cb stays owned for the fail label.
        if self.socket_is_closing(sock) {
            self.failed_tcp_send(l, sock, handle, cb, Res::Canceled, true);
            return;
        }
        self.tcp_send_direct(l, sock, handle, data, cb);
    }

    fn tcp_send_direct(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        data: &[u8],
        cb: SendCb,
    ) {
        let tcp = self.sockets[sock].uv_tcp.unwrap();
        // uv_try_write first (the immediate-write path).
        let n = l.uv_try_write(tcp, data);
        if n == data.len() as i32 {
            // wrote everything: isc__nm_sendcb(..., true) via isc_job_run.
            self.nm_sendcb(l, sock, handle, cb, res_to_code(Res::Success), true);
            return;
        }
        // partial or EAGAIN: uv_write with the write timer.  The req's cb
        // slot is consumed by the (single) write callback.  The C's
        // tcp_send_direct creates the write-timeout timer here, which holds
        // its own handle ref (`isc_nm_timer_create` ->
        // isc_nmhandle_attach) released only when the timer's uv_close
        // completes — i.e. after the send cb — so the probe observes +1
        // refs inside the big-send cb.
        self.handles[handle].refs += 1;
        self.sockets[sock].pending_write_timers += 1;
        // Only the unwritten remainder reaches uv_write (the head already
        // went out via uv_try_write); uv_write writes the head of THAT and
        // queues the rest, so no byte is written twice.
        let start = if n > 0 { n as usize } else { 0 };
        let cbcell = Rc::new(RefCell::new(Some(cb)));
        let weak = self.self_weak.clone();
        let _ = l.uv_write(
            tcp,
            &[data[start..].to_vec()],
            Box::new(move |l: &mut UvLoop, status: i32| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    let cb = cbcell.borrow_mut().take().expect("tcp write cb");
                    inner.tcp_write_cb(l, sock, handle, cb, status);
                }
            }),
        );
    }

    fn tcp_write_cb(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        status: i32,
    ) {
        if status < 0 {
            self.failed_tcp_send(l, sock, handle, cb, code_to_res(status), false);
        } else {
            self.nm_sendcb(l, sock, handle, cb, res_to_code(Res::Success), false);
        }
        // The write-timer handle ref (released after the send cb).
        if self.sockets[sock].pending_write_timers > 0 {
            self.sockets[sock].pending_write_timers -= 1;
            self.handles[handle].refs = self.handles[handle].refs.saturating_sub(1);
        }
    }

    fn failed_tcp_send(
        &mut self,
        l: &mut UvLoop,
        sock: SocketId,
        handle: HandleId,
        cb: SendCb,
        result: Res,
        async_: bool,
    ) {
        self.nm_sendcb(l, sock, handle, cb, res_to_code(result), async_);
    }

    /// `isc__nm_tcp_close`.
    fn tcp_close(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closing = true;
        self.socket_clearcb(sock);
        self.stop_reading(l, sock);
        self.sockets[sock].reading = false;
        // Writes cancelled by the close never complete: release their
        // write-timer handle refs (the C's timer_destroy on close).
        let n = self.sockets[sock].pending_write_timers;
        if n > 0 {
            self.sockets[sock].pending_write_timers = 0;
            if let Some(h) = self.sockets[sock].statichandle {
                self.handles[h].refs = self.handles[h].refs.saturating_sub(n);
            }
        }
        let tcp = self.sockets[sock].uv_tcp.unwrap();
        let weak = self.self_weak.clone();
        l.uv_close(
            tcp,
            Some(Box::new(move |l: &mut UvLoop| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    inner.tcp_close_cb(l, sock);
                }
            })),
        );
        self.timer_stop(l, sock);
        if let Some(timer) = self.sockets[sock].read_timer {
            l.uv_close(timer, None);
        }
    }

    fn tcp_close_cb(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closed = true;
        self.sockets[sock].connected = false;
        if let Some(server) = self.sockets[sock].server {
            self.socket_detach(l, server);
        }
        self.socket_prep_destroy(l, sock);
    }

    /// `isc__nm_tcp_shutdown`.
    fn tcp_shutdown(&mut self, l: &mut UvLoop, sock: SocketId) {
        if !self.sockets[sock].active {
            return;
        }
        self.sockets[sock].active = false;
        if self.sockets[sock].connecting {
            let tcp = self.sockets[sock].uv_tcp.unwrap();
            l.uv_close(tcp, None);
            self.socket_prep_destroy(l, sock);
            return;
        }
        if self.sockets[sock].statichandle.is_some() {
            self.tcp_failed_read_cb(l, sock, Res::ShuttingDown, false);
            return;
        }
        if self.sockets[sock].parent.is_none() {
            self.socket_prep_destroy(l, sock);
            return;
        }
        // The parent lives on the loop that created it, and the listeners
        // assert isc_tid() == 0 — so a child on loop 0 shares its loop with
        // the parent and runs the parent's destroy here; children on other
        // loops leave it to loop 0's teardown.
        if self.sockets[sock].tid == 0 {
            self.socket_prep_destroy(l, self.sockets[sock].parent.unwrap());
        }
    }

    /// `isc__nm_tcp_stoplistening`.
    fn tcp_stoplistening(&mut self, l: &mut UvLoop, sock: SocketId) {
        self.sockets[sock].closing = true;
        self.sockets[sock].active = false;
        let nchildren = self.sockets[sock].nchildren;
        for i in 1..nchildren {
            let tid = self.sockets[sock].children[i as usize].tid;
            let sid = *self.sockets[sock].children[i as usize]
                .socket_id
                .lock()
                .unwrap();
            let bar = self.sockets[sock].stop_barrier.clone().unwrap();
            let mailbox = self.all_mailboxes[tid as usize].clone();
            mailbox.send(Box::new(move |inner, l| {
                if let Some(cid) = sid {
                    inner.stop_tcp_child_job(l, cid, bar);
                }
            }));
        }
        let sid0 = *self.sockets[sock].children[0].socket_id.lock().unwrap();
        let bar = self.sockets[sock].stop_barrier.clone().unwrap();
        if let Some(cid) = sid0 {
            self.stop_tcp_child_job(l, cid, bar);
        }
        self.sockets[sock].closed = true;
        self.socket_prep_destroy(l, sock);
    }

    fn stop_tcp_child_job(&mut self, l: &mut UvLoop, sock: SocketId, bar: Arc<Barrier>) {
        self.sockets[sock].active = false;
        self.sockets[sock].closing = true;
        self.socket_clearcb(sock);
        self.stop_reading(l, sock);
        let tcp = self.sockets[sock].uv_tcp.unwrap();
        let weak = self.self_weak.clone();
        l.uv_close(
            tcp,
            Some(Box::new(move |l: &mut UvLoop| {
                if let Some(rc) = weak.upgrade() {
                    let mut inner = rc.borrow_mut();
                    inner.sockets[sock].closed = true;
                    inner.socket_detach(l, sock);
                }
            })),
        );
        self.timer_stop(l, sock);
        if let Some(timer) = self.sockets[sock].read_timer {
            l.uv_close(timer, None);
        }
        bar.wait();
    }

    // -- shared plumbing ----------------------------------------------

    /// `isc__nm_start_reading`.
    fn start_reading(&mut self, l: &mut UvLoop, sock: SocketId) -> i32 {
        match self.sockets[sock].kind {
            SockKind::UdpSocket => {
                let udp = self.sockets[sock].uv_udp.unwrap();
                if l.uv_is_active(udp) != 0 {
                    return 0;
                }
                let weak = self.self_weak.clone();
                l.uv_udp_recv_start(
                    udp,
                    Box::new(alloc_cb),
                    Box::new(
                        move |l: &mut UvLoop,
                              nread: i64,
                              buf: &mut Buf,
                              addr: Option<&Addr>,
                              _flags: u32| {
                            let n = nread.max(0) as usize;
                            let data = buf.data[..n.min(buf.data.len())].to_vec();
                            let peer = addr.map(|a| match a {
                                Addr::Inet4 { port } => SockAddr::loopback(*port),
                            });
                            if let Some(rc) = weak.upgrade() {
                                let mut inner = rc.borrow_mut();
                                inner.udp_recv_event(l, sock, nread, data, peer);
                            }
                        },
                    ),
                )
            }
            SockKind::TcpSocket => {
                let tcp = self.sockets[sock].uv_tcp.unwrap();
                if l.uv_is_active(tcp) != 0 {
                    return 0;
                }
                let weak = self.self_weak.clone();
                l.uv_read_start(
                    tcp,
                    Box::new(alloc_cb),
                    Box::new(move |l: &mut UvLoop, nread: i64, buf: &mut Buf| {
                        let n = nread.max(0) as usize;
                        let data = buf.data[..n.min(buf.data.len())].to_vec();
                        if let Some(rc) = weak.upgrade() {
                            let mut inner = rc.borrow_mut();
                            inner.tcp_recv_event(l, sock, nread, data);
                        }
                    }),
                )
            }
            SockKind::UdpListener | SockKind::TcpListener => 0,
        }
    }

    /// `isc__nm_stop_reading`.
    fn stop_reading(&mut self, l: &mut UvLoop, sock: SocketId) {
        match self.sockets[sock].kind {
            SockKind::UdpSocket => {
                let udp = self.sockets[sock].uv_udp.unwrap();
                if l.uv_is_active(udp) == 0 {
                    return;
                }
                let _ = l.uv_udp_recv_stop(udp);
            }
            SockKind::TcpSocket => {
                let tcp = self.sockets[sock].uv_tcp.unwrap();
                if l.uv_is_active(tcp) == 0 {
                    return;
                }
                let _ = l.uv_read_stop(tcp);
            }
            _ => {}
        }
    }

    /// `isc_nm_read` dispatch.
    pub fn read(&mut self, l: &mut UvLoop, handle: HandleId, cb: RecvCb) {
        let sock = self.handles[handle].sock.unwrap();
        match self.sockets[sock].kind {
            SockKind::UdpSocket => self.udp_read(l, handle, cb),
            SockKind::TcpSocket => self.tcp_read(l, handle, cb),
            _ => {}
        }
    }

    /// `isc_nm_send` dispatch.
    pub fn send(&mut self, l: &mut UvLoop, handle: HandleId, data: &[u8], cb: SendCb) {
        let sock = self.handles[handle].sock.unwrap();
        match self.sockets[sock].kind {
            SockKind::UdpSocket => self.udp_send(l, handle, data, cb),
            SockKind::TcpSocket => self.tcp_send(l, handle, data, cb),
            _ => {}
        }
    }

    /// `isc_nm_read_stop` dispatch.
    pub fn read_stop(&mut self, l: &mut UvLoop, handle: HandleId) {
        let sock = self.handles[handle].sock.unwrap();
        match self.sockets[sock].kind {
            SockKind::TcpSocket => self.tcp_read_stop(l, handle),
            _ => {}
        }
    }

    /// `isc_nm_cancelread` — always dispatched through the async queue.
    pub fn cancelread(&mut self, l: &mut UvLoop, handle: HandleId) {
        // The C's `sock = handle->sock; REQUIRE(VALID_NMSOCK(sock))` (the
        // panic below is the mirror's REQUIRE).
        let _sock = self.handles[handle].sock.unwrap();
        let _ = l;
        // isc_nmhandle_ref(handle); isc_async_run(loop, cancelread_cb, handle).
        self.handles[handle].refs += 1;
        let target = self.handles[handle].sock.unwrap();
        let target_tid = self.sockets[target].tid;
        self.all_mailboxes[target_tid as usize].send(Box::new(move |inner, l| {
            let sock = inner.handles[handle].sock.unwrap();
            inner.udp_failed_read_cb(l, sock, Res::Canceled, false);
            inner.handle_detach_inner(l, handle);
        }));
    }

    /// `isc_nm_stoplistening` dispatch.
    pub fn stoplistening(&mut self, l: &mut UvLoop, sock: SocketId) {
        match self.sockets[sock].kind {
            SockKind::UdpListener => self.udp_stoplistening(l, sock),
            SockKind::TcpListener => self.tcp_stoplistening(l, sock),
            _ => {}
        }
    }

    /// `isc_nmsocket_close`.
    pub fn nmsocket_close(&mut self, l: &mut UvLoop, sock: &mut Option<SocketId>) {
        let Some(sock) = sock.take() else { return };
        self.socket_detach(l, sock);
    }

    /// `isc_nmhandle_close`.
    pub fn handle_close(&mut self, l: &mut UvLoop, handle: HandleId) {
        let sock = self.handles[handle].sock.unwrap();
        self.socket_clearcb(sock);
        self.socket_prep_destroy(l, sock);
    }

    /// `isc_nmhandle_settimeout`.
    pub fn handle_settimeout(&mut self, l: &mut UvLoop, handle: HandleId, timeout: u32) {
        let sock = self.handles[handle].sock.unwrap();
        self.sockets[sock].read_timeout = u64::from(timeout);
        self.timer_restart(l, sock);
    }

    /// `isc_nmhandle_cleartimeout`.
    pub fn handle_cleartimeout(&mut self, l: &mut UvLoop, handle: HandleId) {
        let sock = self.handles[handle].sock.unwrap();
        self.sockets[sock].read_timeout = 0;
        if self.socket_timer_running(sock) {
            self.timer_stop(l, sock);
        }
    }

    /// `isc_nmhandle_timer_running`.
    pub fn handle_timer_running(&self, handle: HandleId) -> bool {
        let sock = self.handles[handle].sock.unwrap();
        self.socket_timer_running(sock)
    }

    /// `isc_nmhandle_keepalive`.
    pub fn handle_keepalive(&mut self, handle: HandleId, value: bool) {
        let sock = self.handles[handle].sock.unwrap();
        self.sockets[sock].keepalive = value;
        self.sockets[sock].read_timeout = if value {
            u64::from(self.nm.keepalive.load(Ordering::Relaxed))
        } else {
            u64::from(self.nm.idle.load(Ordering::Relaxed))
        };
        self.sockets[sock].write_timeout = self.sockets[sock].read_timeout;
    }

    /// `isc_nmhandle_is_stream`.
    pub fn handle_is_stream(&self, handle: HandleId) -> bool {
        let sock = self.handles[handle].sock.unwrap();
        self.sockets[sock].kind == SockKind::TcpSocket
    }
}

// ---------------------------------------------------------------------------
// free helpers
// ---------------------------------------------------------------------------

/// The alloc callback (`isc__nm_alloc_cb`): assign the worker recv buffer.
fn alloc_cb(_l: &mut UvLoop, _size: usize, buf: &mut Buf) {
    buf.data = vec![0u8; 65535];
}

fn make_recv_job(
    cb: Option<Arc<Mutex<RecvCb>>>,
    sock: SocketId,
    handle: HandleId,
    result: i32,
    data: Vec<u8>,
    peer: Option<SockAddr>,
) -> Job {
    Box::new(move |inner, l| {
        if let Some(cb) = cb {
            let mut guard = cb.lock().unwrap();
            guard(inner, l, handle, result, data, peer);
            drop(guard);
            inner.read_req_put(l, sock, handle);
        } else {
            inner.read_req_put(l, sock, handle);
        }
    })
}
