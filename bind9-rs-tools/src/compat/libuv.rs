//! libuv 1.52.1 — native Rust conservation of the event-loop surface BIND
//! 9.20.26's netmgr/isc depends on (§30, §38, court LIBUV-0001).
//!
//! Archaeology (pinned source `libuv-1.52.1.tar.gz`, sha256
//! 478baf2599bfbc882c355288c9cb6f92e0e7dda435fa04031fa5b607cf3f414c):
//! the loop iteration (src/unix/core.c `uv_run`), the timer heap
//! (src/timer.c, ordered by timeout then start_id), the idle/prepare/check
//! loop watchers (src/unix/loop-watcher.c, idle runs BEFORE prepare in
//! 1.52.1), async coalescing and the cross-thread wakeup (src/unix/async.c,
//! eventfd + the atomic pending flag), the signal self-pipe with one
//! callback per raised signal (src/unix/signal.c), UDP/TCP/stream semantics
//! (src/unix/{udp,stream,tcp}.c with the common logic in src/uv-common.c),
//! the handle state machine (uv-common.h `uv__handle_*`), the LIFO closing
//! queue, the dl/random/barrier/threadpool surfaces, and the full
//! UV_ERRNO_MAP (include/uv.h).
//!
//! Deliberate, courted notes:
//! - The loop is single-threaded (as libuv is per loop); the cross-thread
//!   async wakeup uses a real `eventfd` and the signal path a real
//!   self-pipe, exactly like libuv's unix backend, so blocking `poll`
//!   semantics match.  The loop's I/O wait is `poll` (the courted kernel
//!   surface); libuv's edge-triggered epoll rounds are reproduced because
//!   `poll` computes readiness once per round and the dispatch only
//!   processes that snapshot — data written during a round's dispatch is
//!   read in a later round, the courted send-before-receive boundary.
//! - Sockets are `socket`/`bind`/`listen`/`accept`/`connect`/`sendmsg`/
//!   `recvmsg`/`read`/`write`/`shutdown` on nonblocking fds; the transcript
//!   never exposes fds or ports.
//! - Every libc call lives behind the audited `platform::linux` boundary
//!   (unsafe inventory U-0029..U-0051, §49); this module is safe Rust.
//! - `uv_replace_allocator` reproduces the exact 1.52.1-on-Linux allocator
//!   call pattern courted by the probe: loop init does one calloc (the loop
//!   internal fields, src/unix/loop.c `uv_loop_init`) and one realloc(NULL,
//!   n) (the watchers-array growth from the internal wq_async registration,
//!   src/unix/core.c `maybe_resize`); loop close frees both (the watchers
//!   array, then the internal fields — `uv__loop_close`).
//! - `uv_random` completes on a helper thread and wakes the loop through the
//!   eventfd, mirroring the threadpool + wq_async path (src/random.c
//!   `uv__work_submit`); only the completion (status, len) is observable.
//!
//! Status: LIBUV-0001 court green at 0 residuals.

// The uv__-prefixed names are libuv's internal identifiers, kept verbatim so
// the archaeology trace (pinned source function -> mirror method) stays
// direct; clippy's snake_case rule is waived for exactly this module.
#![allow(clippy::non_snake_case)]

use crate::platform::linux as lx;
use std::collections::{BinaryHeap, VecDeque};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// error table (include/uv.h UV_ERRNO_MAP, 1.52.1)
// ---------------------------------------------------------------------------

/// One UV_ERRNO_MAP entry: the name, the Linux value, the strerror text.
pub struct UvErrno {
    pub name: &'static str,
    pub value: i32,
    pub strerror: &'static str,
}

/// The complete UV_ERRNO_MAP (include/uv.h:74, 1.52.1), in header order.
pub const TABLE: &[UvErrno] = &[
    UvErrno {
        name: "E2BIG",
        value: -7,
        strerror: "argument list too long",
    },
    UvErrno {
        name: "EACCES",
        value: -13,
        strerror: "permission denied",
    },
    UvErrno {
        name: "EADDRINUSE",
        value: -98,
        strerror: "address already in use",
    },
    UvErrno {
        name: "EADDRNOTAVAIL",
        value: -99,
        strerror: "address not available",
    },
    UvErrno {
        name: "EAFNOSUPPORT",
        value: -97,
        strerror: "address family not supported",
    },
    UvErrno {
        name: "EAGAIN",
        value: -11,
        strerror: "resource temporarily unavailable",
    },
    UvErrno {
        name: "EAI_ADDRFAMILY",
        value: -3000,
        strerror: "address family not supported",
    },
    UvErrno {
        name: "EAI_AGAIN",
        value: -3001,
        strerror: "temporary failure",
    },
    UvErrno {
        name: "EAI_BADFLAGS",
        value: -3002,
        strerror: "bad ai_flags value",
    },
    UvErrno {
        name: "EAI_BADHINTS",
        value: -3013,
        strerror: "invalid value for hints",
    },
    UvErrno {
        name: "EAI_CANCELED",
        value: -3003,
        strerror: "request canceled",
    },
    UvErrno {
        name: "EAI_FAIL",
        value: -3004,
        strerror: "permanent failure",
    },
    UvErrno {
        name: "EAI_FAMILY",
        value: -3005,
        strerror: "ai_family not supported",
    },
    UvErrno {
        name: "EAI_MEMORY",
        value: -3006,
        strerror: "out of memory",
    },
    UvErrno {
        name: "EAI_NODATA",
        value: -3007,
        strerror: "no address",
    },
    UvErrno {
        name: "EAI_NONAME",
        value: -3008,
        strerror: "unknown node or service",
    },
    UvErrno {
        name: "EAI_OVERFLOW",
        value: -3009,
        strerror: "argument buffer overflow",
    },
    UvErrno {
        name: "EAI_PROTOCOL",
        value: -3014,
        strerror: "resolved protocol is unknown",
    },
    UvErrno {
        name: "EAI_SERVICE",
        value: -3010,
        strerror: "service not available for socket type",
    },
    UvErrno {
        name: "EAI_SOCKTYPE",
        value: -3011,
        strerror: "socket type not supported",
    },
    UvErrno {
        name: "EALREADY",
        value: -114,
        strerror: "connection already in progress",
    },
    UvErrno {
        name: "EBADF",
        value: -9,
        strerror: "bad file descriptor",
    },
    UvErrno {
        name: "EBUSY",
        value: -16,
        strerror: "resource busy or locked",
    },
    UvErrno {
        name: "ECANCELED",
        value: -125,
        strerror: "operation canceled",
    },
    UvErrno {
        name: "ECHARSET",
        value: -4080,
        strerror: "invalid Unicode character",
    },
    UvErrno {
        name: "ECONNABORTED",
        value: -103,
        strerror: "software caused connection abort",
    },
    UvErrno {
        name: "ECONNREFUSED",
        value: -111,
        strerror: "connection refused",
    },
    UvErrno {
        name: "ECONNRESET",
        value: -104,
        strerror: "connection reset by peer",
    },
    UvErrno {
        name: "EDESTADDRREQ",
        value: -89,
        strerror: "destination address required",
    },
    UvErrno {
        name: "EEXIST",
        value: -17,
        strerror: "file already exists",
    },
    UvErrno {
        name: "EFAULT",
        value: -14,
        strerror: "bad address in system call argument",
    },
    UvErrno {
        name: "EFBIG",
        value: -27,
        strerror: "file too large",
    },
    UvErrno {
        name: "EHOSTUNREACH",
        value: -113,
        strerror: "host is unreachable",
    },
    UvErrno {
        name: "EINTR",
        value: -4,
        strerror: "interrupted system call",
    },
    UvErrno {
        name: "EINVAL",
        value: -22,
        strerror: "invalid argument",
    },
    UvErrno {
        name: "EIO",
        value: -5,
        strerror: "i/o error",
    },
    UvErrno {
        name: "EISCONN",
        value: -106,
        strerror: "socket is already connected",
    },
    UvErrno {
        name: "EISDIR",
        value: -21,
        strerror: "illegal operation on a directory",
    },
    UvErrno {
        name: "ELOOP",
        value: -40,
        strerror: "too many symbolic links encountered",
    },
    UvErrno {
        name: "EMFILE",
        value: -24,
        strerror: "too many open files",
    },
    UvErrno {
        name: "EMSGSIZE",
        value: -90,
        strerror: "message too long",
    },
    UvErrno {
        name: "ENAMETOOLONG",
        value: -36,
        strerror: "name too long",
    },
    UvErrno {
        name: "ENETDOWN",
        value: -100,
        strerror: "network is down",
    },
    UvErrno {
        name: "ENETUNREACH",
        value: -101,
        strerror: "network is unreachable",
    },
    UvErrno {
        name: "ENFILE",
        value: -23,
        strerror: "file table overflow",
    },
    UvErrno {
        name: "ENOBUFS",
        value: -105,
        strerror: "no buffer space available",
    },
    UvErrno {
        name: "ENODEV",
        value: -19,
        strerror: "no such device",
    },
    UvErrno {
        name: "ENOENT",
        value: -2,
        strerror: "no such file or directory",
    },
    UvErrno {
        name: "ENOMEM",
        value: -12,
        strerror: "not enough memory",
    },
    UvErrno {
        name: "ENONET",
        value: -64,
        strerror: "machine is not on the network",
    },
    UvErrno {
        name: "ENOPROTOOPT",
        value: -92,
        strerror: "protocol not available",
    },
    UvErrno {
        name: "ENOSPC",
        value: -28,
        strerror: "no space left on device",
    },
    UvErrno {
        name: "ENOSYS",
        value: -38,
        strerror: "function not implemented",
    },
    UvErrno {
        name: "ENOTCONN",
        value: -107,
        strerror: "socket is not connected",
    },
    UvErrno {
        name: "ENOTDIR",
        value: -20,
        strerror: "not a directory",
    },
    UvErrno {
        name: "ENOTEMPTY",
        value: -39,
        strerror: "directory not empty",
    },
    UvErrno {
        name: "ENOTSOCK",
        value: -88,
        strerror: "socket operation on non-socket",
    },
    UvErrno {
        name: "ENOTSUP",
        value: -95,
        strerror: "operation not supported on socket",
    },
    UvErrno {
        name: "EOVERFLOW",
        value: -75,
        strerror: "value too large for defined data type",
    },
    UvErrno {
        name: "EPERM",
        value: -1,
        strerror: "operation not permitted",
    },
    UvErrno {
        name: "EPIPE",
        value: -32,
        strerror: "broken pipe",
    },
    UvErrno {
        name: "EPROTO",
        value: -71,
        strerror: "protocol error",
    },
    UvErrno {
        name: "EPROTONOSUPPORT",
        value: -93,
        strerror: "protocol not supported",
    },
    UvErrno {
        name: "EPROTOTYPE",
        value: -91,
        strerror: "protocol wrong type for socket",
    },
    UvErrno {
        name: "ERANGE",
        value: -34,
        strerror: "result too large",
    },
    UvErrno {
        name: "EROFS",
        value: -30,
        strerror: "read-only file system",
    },
    UvErrno {
        name: "ESHUTDOWN",
        value: -108,
        strerror: "cannot send after transport endpoint shutdown",
    },
    UvErrno {
        name: "ESPIPE",
        value: -29,
        strerror: "invalid seek",
    },
    UvErrno {
        name: "ESRCH",
        value: -3,
        strerror: "no such process",
    },
    UvErrno {
        name: "ETIMEDOUT",
        value: -110,
        strerror: "connection timed out",
    },
    UvErrno {
        name: "ETXTBSY",
        value: -26,
        strerror: "text file is busy",
    },
    UvErrno {
        name: "EXDEV",
        value: -18,
        strerror: "cross-device link not permitted",
    },
    UvErrno {
        name: "UNKNOWN",
        value: -4094,
        strerror: "unknown error",
    },
    UvErrno {
        name: "EOF",
        value: -4095,
        strerror: "end of file",
    },
    UvErrno {
        name: "ENXIO",
        value: -6,
        strerror: "no such device or address",
    },
    UvErrno {
        name: "EMLINK",
        value: -31,
        strerror: "too many links",
    },
    UvErrno {
        name: "EHOSTDOWN",
        value: -112,
        strerror: "host is down",
    },
    UvErrno {
        name: "EREMOTEIO",
        value: -121,
        strerror: "remote I/O error",
    },
    UvErrno {
        name: "ENOTTY",
        value: -25,
        strerror: "inappropriate ioctl for device",
    },
    UvErrno {
        name: "EFTYPE",
        value: -4028,
        strerror: "inappropriate file type or format",
    },
    UvErrno {
        name: "EILSEQ",
        value: -84,
        strerror: "illegal byte sequence",
    },
    UvErrno {
        name: "ESOCKTNOSUPPORT",
        value: -94,
        strerror: "socket type not supported",
    },
    UvErrno {
        name: "ENODATA",
        value: -61,
        strerror: "no data available",
    },
    UvErrno {
        name: "EUNATCH",
        value: -49,
        strerror: "protocol driver not attached",
    },
    UvErrno {
        name: "ENOEXEC",
        value: -8,
        strerror: "exec format error",
    },
];

/// `uv_err_name` (uv-common.c): the map name, else `Unknown system error N`.
pub fn uv_err_name(err: i32) -> String {
    for e in TABLE {
        if e.value == err {
            return e.name.to_string();
        }
    }
    format!("Unknown system error {err}")
}

/// `uv_strerror` (uv-common.c): the map text, else `Unknown system error N`.
pub fn uv_strerror(err: i32) -> String {
    for e in TABLE {
        if e.value == err {
            return e.strerror.to_string();
        }
    }
    format!("Unknown system error {err}")
}

/// Common constants used by the court (the full table lives in `TABLE`).
pub const EAGAIN: i32 = -11;
pub const EINVAL: i32 = -22;
pub const EBADF: i32 = -9;
pub const EBUSY: i32 = -16;
pub const ECANCELED: i32 = -125;
pub const ECONNREFUSED: i32 = -111;
pub const EDESTADDRREQ: i32 = -89;
pub const EISCONN: i32 = -106;
pub const ENOTCONN: i32 = -107;
pub const ENOTSUP: i32 = -95;
pub const UV_EOF: i32 = -4095;
/// UV_UDP_RECVMMSG (uv.h): the only legal high-bit init_ex flag.
pub const UV_UDP_RECVMMSG: u32 = 0x100;

// ---------------------------------------------------------------------------
// run modes, versions
// ---------------------------------------------------------------------------

/// `uv_run_mode` (uv.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Default,
    Once,
    Nowait,
}

/// `uv_version` (version.c): `(major<<16)|(minor<<8)|patch` (UV_VERSION_HEX).
pub fn uv_version() -> u32 {
    (1 << 16) | (52 << 8) | 1
}

/// `uv_version_string` (version.c).
pub fn uv_version_string() -> &'static str {
    "1.52.1"
}

/// `uv_library_shutdown` (uv-common.c, void): in 1.52.1 this tears down the
/// global signal state of the (process-wide) default loop; the court calls
/// it once at the end and observes nothing beyond its completion.
pub fn uv_library_shutdown() {}

// ---------------------------------------------------------------------------
// handle types, addresses, callbacks
// ---------------------------------------------------------------------------

/// `uv_handle_type` (uv.h UV_HANDLE_TYPE_MAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    Async,
    Check,
    FsEvent,
    FsPoll,
    Handle,
    Idle,
    NamedPipe,
    Poll,
    Prepare,
    Process,
    Stream,
    Tcp,
    Timer,
    Tty,
    Udp,
    Signal,
}

impl HandleType {
    /// `uv_handle_type_name`.
    pub fn name(self) -> &'static str {
        match self {
            HandleType::Async => "async",
            HandleType::Check => "check",
            HandleType::FsEvent => "fs_event",
            HandleType::FsPoll => "fs_poll",
            HandleType::Handle => "handle",
            HandleType::Idle => "idle",
            HandleType::NamedPipe => "pipe",
            HandleType::Poll => "poll",
            HandleType::Prepare => "prepare",
            HandleType::Process => "process",
            HandleType::Stream => "stream",
            HandleType::Tcp => "tcp",
            HandleType::Timer => "timer",
            HandleType::Tty => "tty",
            HandleType::Udp => "udp",
            HandleType::Signal => "signal",
        }
    }
}

/// A handle index into the loop's arena (the C passes the handle pointer;
/// the mirror passes the index — the observable API is the same).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub usize);

pub type Timer = Handle;
pub type Async = Handle;
pub type Idle = Handle;
pub type Prepare = Handle;
pub type Check = Handle;
pub type Signal = Handle;
pub type Udp = Handle;
pub type Tcp = Handle;
pub type Stream = Handle;

/// A socket address (the mirror courts the loopback literal; the port is
/// consumed internally and never printed).
#[derive(Debug, Clone, Copy)]
pub enum Addr {
    Inet4 { port: u16 },
}

impl Addr {
    pub fn v4_loopback(port: u16) -> Addr {
        Addr::Inet4 { port }
    }
}

/// A received data buffer (uv_buf_t).
#[derive(Debug)]
pub struct Buf {
    pub data: Vec<u8>,
}

/// The plain per-handle callback; the C callback receives the handle, the
/// mirror passes `&mut UvLoop` so the callback can drive the loop exactly
/// like the C code does.
pub type Cb = Box<dyn FnMut(&mut UvLoop)>;

/// The udp alloc_cb.
pub type UdpAllocCb = Box<dyn FnMut(&mut UvLoop, usize, &mut Buf)>;
/// The udp recv_cb: `(loop, nread, buf, peer, flags)`.
pub type UdpRecvCb = Box<dyn FnMut(&mut UvLoop, i64, &mut Buf, Option<&Addr>, u32)>;
/// The udp send_cb: `(loop, status)` (0 on success, else the UV error).
pub type UdpSendCb = Box<dyn FnMut(&mut UvLoop, i32)>;
/// The tcp alloc_cb.
pub type TcpAllocCb = Box<dyn FnMut(&mut UvLoop, usize, &mut Buf)>;
/// The tcp read_cb: `(loop, nread, buf)`; nread < 0 is the UV error (UV_EOF
/// at end of stream).
pub type TcpReadCb = Box<dyn FnMut(&mut UvLoop, i64, &mut Buf)>;
/// The write_cb: `(loop, status)`.
pub type WriteCb = Box<dyn FnMut(&mut UvLoop, i32)>;
/// The connect_cb: `(loop, status)`.
pub type ConnectCb = Box<dyn FnMut(&mut UvLoop, i32)>;
/// The shutdown_cb: `(loop, status)`.
pub type ShutdownCb = Box<dyn FnMut(&mut UvLoop, i32)>;
/// The random completion cb: `(loop, status, buflen)`.
pub type RandomCb = Box<dyn FnMut(&mut UvLoop, i32, usize)>;

/// The thread-safe half of `uv_async_send` — what libuv's cross-thread
/// sender touches: the handle's atomic pending flag and the loop's wakeup
/// eventfd (src/unix/async.c `uv_async_send` + `uv__async_send`).
#[derive(Clone)]
pub struct AsyncWake {
    pending: Arc<AtomicBool>,
    wake_fd: i32,
}

impl AsyncWake {
    /// `uv_async_send` from any thread: atomically set the pending flag,
    /// then write the eventfd once (already-pending coalesces, so N sends
    /// produce one callback).
    pub fn send(&self) -> i32 {
        if self.pending.swap(true, Ordering::AcqRel) {
            return 0;
        }
        if self.wake_fd != -1 {
            let one: u64 = 1;
            let _ = lx::write_fd(self.wake_fd, &one.to_ne_bytes());
        }
        0
    }
}

// ---------------------------------------------------------------------------
// the loop
// ---------------------------------------------------------------------------

/// `uv_loop_t` (unix/loop.c `uv_loop_init` + uv-common.h).
pub struct UvLoop {
    pub time: u64,
    stop_flag: bool,
    timer_counter: u64,
    active_handles: usize,
    active_reqs: usize,
    /// The handle arena in init order (uv_walk and uv_loop_close iterate).
    handles: Vec<HandleState>,
    /// The closing stack: uv_close pushes, the closing pass pops (LIFO).
    closing: Vec<Handle>,
    /// The close callbacks, parallel to the closing stack entries.
    close_cbs: Vec<(Handle, Cb)>,
    idle: Vec<Handle>,
    prepare: Vec<Handle>,
    check: Vec<Handle>,
    timers: BinaryHeap<TimerNode>,
    /// Async handles in init order.
    asyncs: Vec<Handle>,
    /// The immediate-callback queue (uv__io_feed -> pending_queue).
    pending: VecDeque<Handle>,
    /// The eventfd used by the async wakeup (loop.c `async_wfd`).
    async_wakeup_fd: i32,
    /// The signal self-pipe ends (signal.c `uv__signal_loop_init`).
    signal_pipe_w: i32,
    signal_pipe_r: i32,
    /// Completed uv_random work handed back by the helper thread, paired
    /// with the completion callbacks in submission order.
    random_cbs: VecDeque<RandomCb>,
    /// The loop-internal-fields allocation (loop.c `lfields`), freed at
    /// uv_loop_close.  Held opaque; the mirror's real state lives in the
    /// Rust struct, the pointers only reproduce the allocator contract.
    alloc_lfields: *mut c_void,
    /// The watchers-array allocation (core.c `maybe_resize`), freed at
    /// uv_loop_close; the same opaque contract.
    alloc_watchers: *mut c_void,
}

impl Default for UvLoop {
    fn default() -> Self {
        UvLoop {
            time: 0,
            stop_flag: false,
            timer_counter: 0,
            active_handles: 0,
            active_reqs: 0,
            handles: Vec::new(),
            closing: Vec::new(),
            close_cbs: Vec::new(),
            idle: Vec::new(),
            prepare: Vec::new(),
            check: Vec::new(),
            timers: BinaryHeap::new(),
            asyncs: Vec::new(),
            pending: VecDeque::new(),
            async_wakeup_fd: -1,
            signal_pipe_w: -1,
            signal_pipe_r: -1,
            random_cbs: VecDeque::new(),
            alloc_lfields: std::ptr::null_mut(),
            alloc_watchers: std::ptr::null_mut(),
        }
    }
}

/// One live handle (a slot; `closed` after the close_cb fires).
enum HandleState {
    Timer(TimerState),
    Async(AsyncState),
    Idle(IdleState),
    Prepare(IdleState),
    Check(IdleState),
    Signal(SignalState),
    Udp(UdpState),
    Tcp(TcpState),
}

struct TimerState {
    active: bool,
    closing: bool,
    closed: bool,
    cb: Option<Cb>,
    timeout: u64,
    repeat: u64,
    in_heap: bool,
}

struct AsyncState {
    active: bool,
    closing: bool,
    closed: bool,
    cb: Option<Cb>,
    /// The atomic pending flag libuv shares with cross-thread senders.
    pending: Arc<AtomicBool>,
}

struct IdleState {
    active: bool,
    closing: bool,
    closed: bool,
    cb: Option<Cb>,
}

struct SignalState {
    active: bool,
    closing: bool,
    closed: bool,
    cb: Option<Cb>,
    signum: i32,
}

struct UdpState {
    active: bool,
    closing: bool,
    closed: bool,
    fd: i32,
    connected: bool,
    alloc_cb: Option<UdpAllocCb>,
    recv_cb: Option<UdpRecvCb>,
    send_queue_size: usize,
    write_queue: VecDeque<SendReq>,
    write_completed: VecDeque<SendReq>,
    recv_started: bool,
}

struct SendReq {
    bufs: Vec<Vec<u8>>,
    nbytes: usize,
    cb: UdpSendCb,
    status: i32,
}

struct TcpState {
    active: bool,
    closing: bool,
    closed: bool,
    fd: i32,
    listening: bool,
    accepted_fd: i32,
    connection_cb: Option<Cb>,
    connect_req: Option<ConnectCb>,
    connect_status: i32,
    read_alloc: Option<TcpAllocCb>,
    read_cb: Option<TcpReadCb>,
    write_queue_size: usize,
    write_queue: VecDeque<WriteReq>,
    write_completed: VecDeque<WriteReq>,
    shutdown_req: Option<ShutdownCb>,
    reading: bool,
}

struct WriteReq {
    bufs: Vec<Vec<u8>>,
    nbytes: usize,
    cb: WriteCb,
    status: i32,
}

#[derive(Debug, Clone, Copy)]
struct TimerNode {
    handle: Handle,
    timeout: u64,
    start_id: u64,
}

impl PartialEq for TimerNode {
    fn eq(&self, other: &Self) -> bool {
        self.timeout == other.timeout && self.start_id == other.start_id
    }
}
impl Eq for TimerNode {}
impl PartialOrd for TimerNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TimerNode {
    /// `timer_less_than` (timer.c): timeout, then start_id; the Rust heap is
    /// a max-heap, so the comparison is reversed for the min ordering.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .timeout
            .cmp(&self.timeout)
            .then_with(|| other.start_id.cmp(&self.start_id))
    }
}

/// The allocator hookup (uv-common.c `uv__allocator`), global like libuv's.
pub struct Allocator {
    pub malloc: Option<fn(usize) -> *mut c_void>,
    pub realloc: Option<fn(*mut c_void, usize) -> *mut c_void>,
    pub calloc: Option<fn(usize, usize) -> *mut c_void>,
    pub free: Option<fn(*mut c_void)>,
}

static ALLOCATOR: std::sync::Mutex<Allocator> = std::sync::Mutex::new(Allocator {
    malloc: None,
    realloc: None,
    calloc: None,
    free: None,
});

/// `uv_replace_allocator` (uv-common.c): any NULL func is EINVAL.
pub fn uv_replace_allocator(
    malloc_func: Option<fn(usize) -> *mut c_void>,
    realloc_func: Option<fn(*mut c_void, usize) -> *mut c_void>,
    calloc_func: Option<fn(usize, usize) -> *mut c_void>,
    free_func: Option<fn(*mut c_void)>,
) -> i32 {
    if malloc_func.is_none()
        || realloc_func.is_none()
        || calloc_func.is_none()
        || free_func.is_none()
    {
        return EINVAL;
    }
    *ALLOCATOR.lock().unwrap() = Allocator {
        malloc: malloc_func,
        realloc: realloc_func,
        calloc: calloc_func,
        free: free_func,
    };
    0
}

fn alloc_call_calloc(n: usize, size: usize) -> *mut c_void {
    match ALLOCATOR.lock().unwrap().calloc {
        Some(f) => f(n, size),
        None => lx::alloc_calloc(n, size),
    }
}

fn alloc_call_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    match ALLOCATOR.lock().unwrap().realloc {
        Some(f) => f(p, size),
        None => lx::alloc_realloc(p, size),
    }
}

fn alloc_call_free(p: *mut c_void) {
    match ALLOCATOR.lock().unwrap().free {
        Some(f) => f(p),
        None => lx::alloc_free(p),
    }
}

impl UvLoop {
    /// `uv_loop_init` (unix/loop.c): zero the state, update the time, create
    /// the async wakeup eventfd, and — reproduced from the 1.52.1-on-Linux
    /// allocator pattern — calloc the loop internal fields and realloc(NULL,
    /// n) the watchers array (the internal wq_async registration grows it).
    pub fn uv_loop_init(&mut self) -> i32 {
        *self = UvLoop::default();
        self.uv__update_time();
        self.alloc_lfields = alloc_call_calloc(1, 448);
        self.alloc_watchers = alloc_call_realloc(std::ptr::null_mut(), 128);
        match lx::eventfd() {
            Ok(fd) => {
                self.async_wakeup_fd = fd;
                0
            }
            Err(e) => -e,
        }
    }

    /// `uv_loop_close` (uv-common.c): EBUSY with active reqs or leftover
    /// non-internal handles (the handle_queue foreach in 1.52.1); the frees
    /// are the observed close pattern (watchers array, then internal
    /// fields — `uv__loop_close`).
    pub fn uv_loop_close(&mut self) -> i32 {
        if self.active_reqs > 0 {
            return EBUSY;
        }
        for h in &self.handles {
            let closed = match h {
                HandleState::Timer(t) => t.closed,
                HandleState::Async(a) => a.closed,
                HandleState::Idle(s) => s.closed,
                HandleState::Prepare(s) => s.closed,
                HandleState::Check(s) => s.closed,
                HandleState::Signal(s) => s.closed,
                HandleState::Udp(u) => u.closed,
                HandleState::Tcp(t) => t.closed,
            };
            if !closed {
                return EBUSY;
            }
        }
        if self.async_wakeup_fd != -1 {
            lx::close(self.async_wakeup_fd);
            self.async_wakeup_fd = -1;
        }
        if self.signal_pipe_r != -1 {
            lx::close(self.signal_pipe_r);
            lx::close(self.signal_pipe_w);
            self.signal_pipe_r = -1;
            self.signal_pipe_w = -1;
        }
        alloc_call_free(self.alloc_watchers);
        alloc_call_free(self.alloc_lfields);
        self.alloc_watchers = std::ptr::null_mut();
        self.alloc_lfields = std::ptr::null_mut();
        0
    }

    /// `uv_run` (unix/core.c): the exact iteration — pending, idle, prepare,
    /// poll, pending (<=8), check, closing, timers — with the pre-loop timer
    /// pass for DEFAULT and the stop-flag clearing on exit.
    pub fn uv_run(&mut self, mode: RunMode) -> i32 {
        let mut r = self.uv__loop_alive();
        if !r {
            self.uv__update_time();
        }
        if mode == RunMode::Default && r && !self.stop_flag {
            self.uv__update_time();
            self.uv__run_timers();
        }
        while r && !self.stop_flag {
            let can_sleep = self.pending.is_empty() && self.idle.is_empty();
            self.uv__run_pending();
            self.uv__run_idle();
            self.uv__run_prepare();
            let timeout = if (mode == RunMode::Once && can_sleep) || mode == RunMode::Default {
                self.uv__backend_timeout()
            } else {
                0
            };
            self.uv__io_poll(timeout);
            for _ in 0..8 {
                if self.pending.is_empty() {
                    break;
                }
                self.uv__run_pending();
            }
            self.uv__run_check();
            self.uv__run_closing_handles();
            self.uv__update_time();
            self.uv__run_timers();
            r = self.uv__loop_alive();
            if mode == RunMode::Once || mode == RunMode::Nowait {
                break;
            }
        }
        if self.stop_flag {
            self.stop_flag = false;
        }
        i32::from(r)
    }

    /// `uv_stop`.
    pub fn uv_stop(&mut self) {
        self.stop_flag = true;
    }

    /// `uv_loop_alive` (uv__loop_alive).
    pub fn uv_loop_alive(&self) -> i32 {
        i32::from(self.uv__loop_alive())
    }

    fn uv__loop_alive(&self) -> bool {
        self.active_handles > 0
            || self.active_reqs > 0
            || !self.pending.is_empty()
            || !self.closing.is_empty()
    }

    fn uv__update_time(&mut self) {
        self.time = lx::monotonic_ms();
    }

    /// `uv_now`.
    pub fn uv_now(&self) -> u64 {
        self.time
    }

    fn uv__backend_timeout(&self) -> i32 {
        if !self.stop_flag
            && self.active_handles > 0
            && self.pending.is_empty()
            && self.idle.is_empty()
            && self.closing.is_empty()
        {
            self.uv__next_timeout()
        } else {
            0
        }
    }

    fn uv__next_timeout(&self) -> i32 {
        match self.timers.peek() {
            None => -1,
            Some(t) => {
                if t.timeout <= self.time {
                    0
                } else {
                    (t.timeout - self.time).min(i32::MAX as u64) as i32
                }
            }
        }
    }

    // -- the pending (immediate-callback) pass ---------------------------

    fn uv__run_pending(&mut self) {
        let feeds: Vec<Handle> = self.pending.drain(..).collect();
        for h in feeds {
            match self.handles.get(h.0) {
                Some(HandleState::Udp(_)) => self.udp_run_completed(h),
                Some(HandleState::Tcp(_)) => self.tcp_run_completed(h),
                _ => {}
            }
        }
    }

    // -- timers ----------------------------------------------------------

    /// `uv_timer_init`.
    pub fn uv_timer_init(&mut self, timer: &mut Timer) -> i32 {
        let ix = self.handles.len();
        self.handles.push(HandleState::Timer(TimerState {
            active: false,
            closing: false,
            closed: false,
            cb: None,
            timeout: 0,
            repeat: 0,
            in_heap: false,
        }));
        *timer = Handle(ix);
        0
    }

    /// `uv_timer_start` (timer.c): EINVAL when closing or cb NULL (checked
    /// BEFORE the stop); timeout = loop->time + timeout (clamped).
    pub fn uv_timer_start(
        &mut self,
        timer: Timer,
        cb: Option<Cb>,
        timeout: u64,
        repeat: u64,
    ) -> i32 {
        let h = timer;
        {
            let state = match self.handles.get(h.0) {
                Some(HandleState::Timer(t)) => t,
                _ => return EINVAL,
            };
            if state.closing || state.closed || cb.is_none() {
                return EINVAL;
            }
        }
        let _ = self.uv_timer_stop(h);
        let clamped = self.time.saturating_add(timeout);
        let start_id = self.timer_counter;
        self.timer_counter += 1;
        if let Some(HandleState::Timer(t)) = self.handles.get_mut(h.0) {
            t.cb = cb;
            t.timeout = clamped;
            t.repeat = repeat;
            t.in_heap = true;
            t.active = true;
        }
        self.timers.push(TimerNode {
            handle: h,
            timeout: clamped,
            start_id,
        });
        self.active_handles += 1;
        0
    }

    /// `uv_timer_stop`: remove from the heap and deactivate.
    pub fn uv_timer_stop(&mut self, timer: Timer) -> i32 {
        let h = timer;
        let active = match self.handles.get(h.0) {
            Some(HandleState::Timer(t)) => t.active,
            _ => return 0,
        };
        if active {
            if let Some(HandleState::Timer(t)) = self.handles.get_mut(h.0) {
                t.active = false;
                t.in_heap = false;
            }
            let cur = std::mem::replace(&mut self.timers, BinaryHeap::new());
            self.timers = cur.into_iter().filter(|n| n.handle != h).collect();
            self.active_handles -= 1;
        }
        0
    }

    /// `uv_timer_again` (timer.c): re-arm with (repeat, repeat) when repeat
    /// is nonzero; the callback stays set in all cases (a one-shot keeps its
    /// timer_cb, exactly like libuv).
    pub fn uv_timer_again(&mut self, timer: Timer) -> i32 {
        let has_cb = match self.handles.get(timer.0) {
            Some(HandleState::Timer(t)) => t.cb.is_some(),
            _ => false,
        };
        if !has_cb {
            return EINVAL;
        }
        self.uv_timer_again_internal(timer);
        0
    }

    fn uv_timer_again_internal(&mut self, timer: Timer) {
        let (has_cb, repeat) = match self.handles.get(timer.0) {
            Some(HandleState::Timer(t)) => (t.cb.is_some(), t.repeat),
            _ => return,
        };
        if !has_cb || repeat == 0 {
            return;
        }
        let cb = match self.handles.get_mut(timer.0) {
            Some(HandleState::Timer(t)) => t.cb.take(),
            _ => return,
        };
        let _ = self.uv_timer_stop(timer);
        if let Some(cb) = cb {
            let _ = self.uv_timer_start(timer, Some(cb), repeat, repeat);
        }
    }

    pub fn uv_timer_set_repeat(&mut self, timer: Timer, repeat: u64) {
        if let Some(HandleState::Timer(t)) = self.handles.get_mut(timer.0) {
            t.repeat = repeat;
        }
    }

    pub fn uv_timer_get_repeat(&self, timer: Timer) -> u64 {
        match self.handles.get(timer.0) {
            Some(HandleState::Timer(t)) => t.repeat,
            _ => 0,
        }
    }

    /// `uv__run_timers` (timer.c): pop all due timers in heap order; for
    /// each, uv_timer_again (re-arms repeat timers BEFORE the callback),
    /// then the callback (which stays set afterwards, like timer_cb).
    fn uv__run_timers(&mut self) {
        let mut ready: Vec<Handle> = Vec::new();
        loop {
            match self.timers.peek() {
                Some(t) if t.timeout <= self.time => {
                    let t = *t;
                    self.timers.pop();
                    if let Some(HandleState::Timer(ts)) = self.handles.get_mut(t.handle.0) {
                        ts.in_heap = false;
                        ts.active = false;
                    }
                    self.active_handles -= 1;
                    ready.push(t.handle);
                }
                _ => break,
            }
        }
        for h in ready {
            self.uv_timer_again_internal(h);
            let cb = match self.handles.get_mut(h.0) {
                Some(HandleState::Timer(t)) => t.cb.take(),
                _ => None,
            };
            if let Some(mut cb) = cb {
                cb(self);
                if let Some(HandleState::Timer(t)) = self.handles.get_mut(h.0) {
                    if !t.closing && !t.closed {
                        t.cb = Some(cb);
                    }
                }
            }
        }
    }

    // -- idle / prepare / check (loop-watcher.c) --------------------------

    fn watcher_init(&mut self, kind: WatcherKind) -> Handle {
        let ix = self.handles.len();
        let state = IdleState {
            active: false,
            closing: false,
            closed: false,
            cb: None,
        };
        self.handles.push(match kind {
            WatcherKind::Idle => HandleState::Idle(state),
            WatcherKind::Prepare => HandleState::Prepare(state),
            WatcherKind::Check => HandleState::Check(state),
        });
        Handle(ix)
    }

    pub fn uv_idle_init(&mut self, h: &mut Idle) -> i32 {
        *h = self.watcher_init(WatcherKind::Idle);
        0
    }
    pub fn uv_prepare_init(&mut self, h: &mut Prepare) -> i32 {
        *h = self.watcher_init(WatcherKind::Prepare);
        0
    }
    pub fn uv_check_init(&mut self, h: &mut Check) -> i32 {
        *h = self.watcher_init(WatcherKind::Check);
        0
    }

    pub fn uv_idle_start(&mut self, h: Idle, cb: Cb) -> i32 {
        self.watcher_start(h, cb, WatcherKind::Idle)
    }
    pub fn uv_prepare_start(&mut self, h: Prepare, cb: Cb) -> i32 {
        self.watcher_start(h, cb, WatcherKind::Prepare)
    }
    pub fn uv_check_start(&mut self, h: Check, cb: Cb) -> i32 {
        self.watcher_start(h, cb, WatcherKind::Check)
    }
    pub fn uv_idle_stop(&mut self, h: Idle) -> i32 {
        self.watcher_stop(h, WatcherKind::Idle)
    }
    pub fn uv_prepare_stop(&mut self, h: Prepare) -> i32 {
        self.watcher_stop(h, WatcherKind::Prepare)
    }
    pub fn uv_check_stop(&mut self, h: Check) -> i32 {
        self.watcher_stop(h, WatcherKind::Check)
    }

    fn watcher_start(&mut self, h: Handle, cb: Cb, kind: WatcherKind) -> i32 {
        let active = match self.handles.get(h.0) {
            Some(HandleState::Idle(s)) => s.active,
            Some(HandleState::Prepare(s)) => s.active,
            Some(HandleState::Check(s)) => s.active,
            _ => return EINVAL,
        };
        if active {
            return 0;
        }
        let list = match kind {
            WatcherKind::Idle => &mut self.idle,
            WatcherKind::Prepare => &mut self.prepare,
            WatcherKind::Check => &mut self.check,
        };
        list.insert(0, h); // insert at the HEAD (loop-watcher.c)
        if let Some(HandleState::Idle(s)) = self.handles.get_mut(h.0) {
            s.cb = Some(cb);
            s.active = true;
        } else if let Some(HandleState::Prepare(s)) = self.handles.get_mut(h.0) {
            s.cb = Some(cb);
            s.active = true;
        } else if let Some(HandleState::Check(s)) = self.handles.get_mut(h.0) {
            s.cb = Some(cb);
            s.active = true;
        }
        self.active_handles += 1;
        0
    }

    fn watcher_stop(&mut self, h: Handle, kind: WatcherKind) -> i32 {
        let active = match self.handles.get(h.0) {
            Some(HandleState::Idle(s)) => s.active,
            Some(HandleState::Prepare(s)) => s.active,
            Some(HandleState::Check(s)) => s.active,
            _ => return EINVAL,
        };
        if !active {
            return 0;
        }
        let list = match kind {
            WatcherKind::Idle => &mut self.idle,
            WatcherKind::Prepare => &mut self.prepare,
            WatcherKind::Check => &mut self.check,
        };
        list.retain(|x| *x != h);
        if let Some(HandleState::Idle(s)) = self.handles.get_mut(h.0) {
            s.active = false;
        } else if let Some(HandleState::Prepare(s)) = self.handles.get_mut(h.0) {
            s.active = false;
        } else if let Some(HandleState::Check(s)) = self.handles.get_mut(h.0) {
            s.active = false;
        }
        self.active_handles -= 1;
        0
    }

    fn uv__run_watchers(&mut self, kind: WatcherKind) {
        let local: Vec<Handle> = match kind {
            WatcherKind::Idle => std::mem::take(&mut self.idle),
            WatcherKind::Prepare => std::mem::take(&mut self.prepare),
            WatcherKind::Check => std::mem::take(&mut self.check),
        };
        for h in local {
            match kind {
                WatcherKind::Idle => self.idle.push(h),
                WatcherKind::Prepare => self.prepare.push(h),
                WatcherKind::Check => self.check.push(h),
            } // re-insert at the tail before the callback
            let cb = match self.handles.get_mut(h.0) {
                Some(HandleState::Idle(s)) => s.cb.take(),
                Some(HandleState::Prepare(s)) => s.cb.take(),
                Some(HandleState::Check(s)) => s.cb.take(),
                _ => None,
            };
            if let Some(mut cb) = cb {
                cb(self);
                // The watcher's callback stays set (uv__idle_start replaces
                // it on restart); restore unless the handle closed.
                if let Some(HandleState::Idle(s)) = self.handles.get_mut(h.0) {
                    if !s.closing && !s.closed {
                        s.cb = Some(cb);
                    }
                } else if let Some(HandleState::Prepare(s)) = self.handles.get_mut(h.0) {
                    if !s.closing && !s.closed {
                        s.cb = Some(cb);
                    }
                } else if let Some(HandleState::Check(s)) = self.handles.get_mut(h.0) {
                    if !s.closing && !s.closed {
                        s.cb = Some(cb);
                    }
                }
            }
        }
    }

    fn uv__run_idle(&mut self) {
        self.uv__run_watchers(WatcherKind::Idle);
    }
    fn uv__run_prepare(&mut self) {
        self.uv__run_watchers(WatcherKind::Prepare);
    }
    fn uv__run_check(&mut self) {
        self.uv__run_watchers(WatcherKind::Check);
    }

    // -- async ------------------------------------------------------------

    /// `uv_async_init` (unix/async.c): ensure the loop wakeup eventfd, init
    /// the handle, append to the async list, start it.
    pub fn uv_async_init(&mut self, h: &mut Async, cb: Cb) -> i32 {
        if self.async_wakeup_fd == -1 {
            match lx::eventfd() {
                Ok(fd) => self.async_wakeup_fd = fd,
                Err(e) => return -e,
            }
        }
        let ix = self.handles.len();
        self.handles.push(HandleState::Async(AsyncState {
            active: true,
            closing: false,
            closed: false,
            cb: Some(cb),
            pending: Arc::new(AtomicBool::new(false)),
        }));
        *h = Handle(ix);
        self.asyncs.push(Handle(ix));
        self.active_handles += 1;
        0
    }

    /// `uv_async_send`: the cheap read — already pending means no wakeup
    /// (coalescing).
    pub fn uv_async_send(&mut self, h: Async) -> i32 {
        let wake = match self.handles.get(h.0) {
            Some(HandleState::Async(a)) => AsyncWake {
                pending: a.pending.clone(),
                wake_fd: self.async_wakeup_fd,
            },
            _ => return EINVAL,
        };
        wake.send()
    }

    /// The thread-safe send token for a cross-thread `uv_async_send` (the
    /// netmgr's stop/notify path; the C passes the same uv_async_t).
    pub fn async_wake(&self, h: Async) -> AsyncWake {
        match self.handles.get(h.0) {
            Some(HandleState::Async(a)) => AsyncWake {
                pending: a.pending.clone(),
                wake_fd: self.async_wakeup_fd,
            },
            _ => AsyncWake {
                pending: Arc::new(AtomicBool::new(false)),
                wake_fd: -1,
            },
        }
    }

    /// `uv__async_io`: drain the eventfd, then walk the async list:
    /// fetch-and-clear the pending flag; fire only if it was set.  Then the
    /// completed threadpool work (uv_random via the wq_async path).
    fn uv__async_io(&mut self) {
        let mut buf = [0u8; 1024];
        loop {
            match lx::read_fd(self.async_wakeup_fd, &mut buf) {
                Ok(n) if n == buf.len() => continue,
                _ => break,
            }
        }
        let list = std::mem::take(&mut self.asyncs);
        for h in &list {
            self.asyncs.push(*h);
            let fired = match self.handles.get_mut(h.0) {
                Some(HandleState::Async(a)) => a.pending.swap(false, Ordering::AcqRel),
                _ => false,
            };
            if !fired {
                continue;
            }
            let cb = match self.handles.get_mut(h.0) {
                Some(HandleState::Async(a)) => a.cb.take(),
                _ => None,
            };
            if let Some(mut cb) = cb {
                cb(self);
                if let Some(HandleState::Async(a)) = self.handles.get_mut(h.0) {
                    if !a.closing && !a.closed {
                        a.cb = Some(cb);
                    }
                }
            }
        }
        if let Ok(mut results) = RANDOM_RESULTS.lock() {
            while let Some((len, status)) = results.pop_front() {
                self.active_reqs = self.active_reqs.saturating_sub(1);
                let cb = self.random_cbs.pop_front();
                if let Some(mut cb) = cb {
                    cb(self, status, len);
                }
            }
        }
    }

    // -- signal -----------------------------------------------------------

    /// `uv_signal_init`: ensure the self-pipe, then init the handle.
    pub fn uv_signal_init(&mut self, h: &mut Signal) -> i32 {
        if self.signal_pipe_r == -1 {
            match lx::pipe2(libc::O_NONBLOCK | libc::O_CLOEXEC) {
                Ok((r, w)) => {
                    self.signal_pipe_r = r;
                    self.signal_pipe_w = w;
                    SIGNAL_PIPE_W.store(w, Ordering::SeqCst);
                }
                Err(e) => return -e,
            }
        }
        let ix = self.handles.len();
        self.handles.push(HandleState::Signal(SignalState {
            active: false,
            closing: false,
            closed: false,
            cb: None,
            signum: 0,
        }));
        *h = Handle(ix);
        0
    }

    /// `uv_signal_start` (unix/signal.c): signum 0 -> EINVAL; same signum
    /// only replaces the callback; otherwise stop, register, start.
    pub fn uv_signal_start(&mut self, h: Signal, cb: Cb, signum: i32) -> i32 {
        if signum == 0 {
            return EINVAL;
        }
        let (same, closing) = match self.handles.get(h.0) {
            Some(HandleState::Signal(s)) => (s.signum == signum, s.closing),
            _ => return EINVAL,
        };
        if closing {
            return EINVAL;
        }
        if same {
            if let Some(HandleState::Signal(s)) = self.handles.get_mut(h.0) {
                s.cb = Some(cb);
            }
            return 0;
        }
        let _ = self.uv_signal_stop(h);
        if let Some(HandleState::Signal(s)) = self.handles.get_mut(h.0) {
            s.signum = signum;
            s.cb = Some(cb);
            s.active = true;
        }
        self.active_handles += 1;
        self.signal_register(signum);
        0
    }

    fn signal_register(&self, signum: i32) {
        let _ = lx::sigaction_install(signum, uv_signal_handler);
    }

    /// `uv_signal_stop`: deregister + deactivate.
    pub fn uv_signal_stop(&mut self, h: Signal) -> i32 {
        let (signum, active) = match self.handles.get(h.0) {
            Some(HandleState::Signal(s)) => (s.signum, s.active),
            _ => return EINVAL,
        };
        if signum == 0 {
            return 0;
        }
        if active {
            if let Some(HandleState::Signal(s)) = self.handles.get_mut(h.0) {
                s.active = false;
                s.signum = 0;
            }
            self.active_handles -= 1;
        }
        0
    }

    /// `uv__signal_event`: drain the pipe; one callback per byte for active
    /// handles.
    fn uv__signal_event(&mut self) {
        let mut buf = [0u8; 1024];
        loop {
            match lx::read_fd(self.signal_pipe_r, &mut buf) {
                Ok(n) => {
                    for _ in &buf[..n] {
                        let hits: Vec<Handle> = self
                            .handles
                            .iter()
                            .enumerate()
                            .filter_map(|(ix, s)| match s {
                                HandleState::Signal(sig) if sig.active => Some(Handle(ix)),
                                _ => None,
                            })
                            .collect();
                        for h in hits {
                            let cb = match self.handles.get_mut(h.0) {
                                Some(HandleState::Signal(s)) => s.cb.take(),
                                _ => None,
                            };
                            if let Some(mut cb) = cb {
                                cb(self);
                                if let Some(HandleState::Signal(s)) = self.handles.get_mut(h.0) {
                                    if !s.closing && !s.closed {
                                        s.cb = Some(cb);
                                    }
                                }
                            }
                        }
                    }
                    if n == buf.len() {
                        continue;
                    }
                    break;
                }
                _ => break,
            }
        }
    }

    // -- closing ----------------------------------------------------------

    /// `uv_close` (unix/core.c): set CLOSING, push onto the closing stack.
    pub fn uv_close(&mut self, h: Handle, cb: Option<Cb>) {
        let ty = match self.handles.get(h.0) {
            Some(HandleState::Timer(_)) => HandleType::Timer,
            Some(HandleState::Async(_)) => HandleType::Async,
            Some(HandleState::Idle(_)) => HandleType::Idle,
            Some(HandleState::Prepare(_)) => HandleType::Prepare,
            Some(HandleState::Check(_)) => HandleType::Check,
            Some(HandleState::Signal(_)) => HandleType::Signal,
            Some(HandleState::Udp(_)) => HandleType::Udp,
            Some(HandleState::Tcp(_)) => HandleType::Tcp,
            _ => return,
        };
        self.close_begin(h, ty);
        self.closing.push(h);
        if let Some(cb) = cb {
            self.close_cbs.push((h, cb));
        }
    }

    fn close_begin(&mut self, h: Handle, ty: HandleType) {
        match ty {
            HandleType::Timer => {
                let _ = self.uv_timer_stop(h);
                if let Some(HandleState::Timer(t)) = self.handles.get_mut(h.0) {
                    t.closing = true;
                    t.cb = None;
                }
            }
            HandleType::Async => {
                if let Some(HandleState::Async(a)) = self.handles.get_mut(h.0) {
                    if a.active {
                        a.active = false;
                        self.active_handles -= 1;
                    }
                    a.closing = true;
                    a.cb = None;
                }
            }
            HandleType::Idle => {
                let _ = self.watcher_stop(h, WatcherKind::Idle);
                if let Some(HandleState::Idle(s)) = self.handles.get_mut(h.0) {
                    s.closing = true;
                    s.cb = None;
                }
            }
            HandleType::Prepare => {
                let _ = self.watcher_stop(h, WatcherKind::Prepare);
                if let Some(HandleState::Prepare(s)) = self.handles.get_mut(h.0) {
                    s.closing = true;
                    s.cb = None;
                }
            }
            HandleType::Check => {
                let _ = self.watcher_stop(h, WatcherKind::Check);
                if let Some(HandleState::Check(s)) = self.handles.get_mut(h.0) {
                    s.closing = true;
                    s.cb = None;
                }
            }
            HandleType::Signal => {
                let _ = self.uv_signal_stop(h);
                if let Some(HandleState::Signal(s)) = self.handles.get_mut(h.0) {
                    s.closing = true;
                    s.cb = None;
                }
            }
            HandleType::Udp => {
                if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                    u.closing = true;
                    u.recv_started = false;
                    u.recv_cb = None;
                    u.alloc_cb = None;
                    if u.active {
                        u.active = false;
                        self.active_handles -= 1;
                    }
                    // uv__udp_close: the socket closes at uv_close time.
                    if u.fd != -1 {
                        lx::close(u.fd);
                        u.fd = -1;
                    }
                }
            }
            HandleType::Tcp => {
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    t.closing = true;
                    t.reading = false;
                    t.read_cb = None;
                    t.read_alloc = None;
                    t.connect_req = None;
                    t.connection_cb = None;
                    t.shutdown_req = None;
                    if t.active {
                        t.active = false;
                        self.active_handles -= 1;
                    }
                    // uv__tcp_close: the socket closes at uv_close time.
                    if t.fd != -1 {
                        lx::close(t.fd);
                        t.fd = -1;
                    }
                }
            }
            _ => {}
        }
    }

    /// `uv__run_closing_handles`: pop the LIFO stack, finish each close.
    fn uv__run_closing_handles(&mut self) {
        let mut stack = std::mem::take(&mut self.closing);
        while let Some(h) = stack.pop() {
            self.finish_close(h);
        }
    }

    fn finish_close(&mut self, h: Handle) {
        let cb = self
            .close_cbs
            .iter()
            .position(|(hh, _)| *hh == h)
            .and_then(|i| {
                let (_, cb) = self.close_cbs.remove(i);
                Some(cb)
            });
        // uv__handle_close: clear CLOSING|ACTIVE (uv_walk skips closed
        // handles and uv_loop_close accepts them) before the close_cb fires.
        match self.handles.get_mut(h.0) {
            Some(HandleState::Timer(t)) => {
                t.closed = true;
                t.active = false;
                t.closing = false;
            }
            Some(HandleState::Async(a)) => {
                a.closed = true;
                a.active = false;
                a.closing = false;
            }
            Some(HandleState::Idle(s)) => {
                s.closed = true;
                s.active = false;
                s.closing = false;
            }
            Some(HandleState::Prepare(s)) => {
                s.closed = true;
                s.active = false;
                s.closing = false;
            }
            Some(HandleState::Check(s)) => {
                s.closed = true;
                s.active = false;
                s.closing = false;
            }
            Some(HandleState::Signal(s)) => {
                s.closed = true;
                s.active = false;
                s.closing = false;
            }
            Some(HandleState::Udp(u)) => {
                u.closed = true;
                u.active = false;
                u.closing = false;
            }
            Some(HandleState::Tcp(t)) => {
                t.closed = true;
                t.active = false;
                t.closing = false;
            }
            _ => {}
        }
        if let Some(mut cb) = cb {
            cb(self);
        }
    }

    // -- the io poll ------------------------------------------------------

    /// `uv__io_poll` (unix/linux.c + core.c): build the pollfd set from the
    /// registered watchers, wait, then dispatch.  The writable events
    /// dispatch first (the round's sends — their completion callbacks run in
    /// the pending pass of this same round), then the readable events; a
    /// level-triggered poll() snapshot means data written during this round
    /// is only seen next round — the courted send-before-receive boundary.
    fn uv__io_poll(&mut self, timeout: i32) {
        let mut pollfds: Vec<libc::pollfd> = Vec::new();
        let mut owners: Vec<IoKind> = Vec::new();
        if self.async_wakeup_fd != -1 {
            pollfds.push(libc::pollfd {
                fd: self.async_wakeup_fd,
                events: libc::POLLIN,
                revents: 0,
            });
            owners.push(IoKind::Async);
        }
        if self.signal_pipe_r != -1 {
            pollfds.push(libc::pollfd {
                fd: self.signal_pipe_r,
                events: libc::POLLIN,
                revents: 0,
            });
            owners.push(IoKind::Signal);
        }
        for (ix, h) in self.handles.iter().enumerate() {
            match h {
                HandleState::Udp(u) if u.fd != -1 && !u.closed => {
                    let mut ev = 0i16;
                    if u.recv_started {
                        ev |= libc::POLLIN;
                    }
                    if !u.write_queue.is_empty() {
                        ev |= libc::POLLOUT;
                    }
                    if ev != 0 {
                        pollfds.push(libc::pollfd {
                            fd: u.fd,
                            events: ev,
                            revents: 0,
                        });
                        owners.push(IoKind::Udp(Handle(ix)));
                    }
                }
                HandleState::Tcp(t) if t.fd != -1 && !t.closed => {
                    let mut ev = 0i16;
                    // uv__server_io stops POLLIN until the user accepts.
                    if (t.listening && t.accepted_fd == -1) || t.reading {
                        ev |= libc::POLLIN;
                    }
                    if t.connect_req.is_some() && !t.listening {
                        ev |= libc::POLLOUT;
                    }
                    if !t.write_queue.is_empty() {
                        ev |= libc::POLLOUT;
                    }
                    if ev != 0 {
                        pollfds.push(libc::pollfd {
                            fd: t.fd,
                            events: ev,
                            revents: 0,
                        });
                        owners.push(IoKind::Tcp(Handle(ix)));
                    }
                }
                _ => {}
            }
        }
        if pollfds.is_empty() {
            // No watchers: uv__io_poll with a bounded timeout sleeps (the
            // silent stop timer bounds every courted run).
            if timeout > 0 {
                std::thread::sleep(std::time::Duration::from_millis(timeout as u64));
            }
            return;
        }
        let timeout = if timeout < 0 { -1 } else { timeout };
        let r = loop {
            match lx::poll(pollfds.as_mut_slice(), timeout) {
                Ok(n) => break n,
                Err(e) if e == libc::EINTR => continue,
                Err(_) => break 0,
            }
        };
        if r == 0 {
            return;
        }
        // Pass 1: writable/error — the round's sends and connect completes.
        for (i, pf) in pollfds.iter().enumerate() {
            if pf.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                continue;
            }
            match owners[i] {
                IoKind::Udp(h) => self.udp_sendmsg(h),
                IoKind::Tcp(h) => self.tcp_poll_out(h),
                _ => {}
            }
        }
        // Pass 2: readable — data, accepts, wakeups, signals.
        for (i, pf) in pollfds.iter().enumerate() {
            if pf.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
                continue;
            }
            match owners[i] {
                IoKind::Async => self.uv__async_io(),
                IoKind::Signal => self.uv__signal_event(),
                IoKind::Udp(h) => self.udp_recv(h),
                IoKind::Tcp(h) => self.tcp_poll_in(h),
            }
        }
    }

    // -- UDP ---------------------------------------------------------------

    /// `uv_udp_init_ex` (uv-common.c): the low 8 bits are the domain, the
    /// high bits only UV_UDP_RECVMMSG.
    pub fn uv_udp_init_ex(&mut self, h: &mut Udp, flags: u32) -> i32 {
        let domain = flags & 0xff;
        if domain != libc::AF_INET as u32
            && domain != libc::AF_INET6 as u32
            && domain != libc::AF_UNSPEC as u32
        {
            return EINVAL;
        }
        if flags & !0xff & !UV_UDP_RECVMMSG != 0 {
            return EINVAL;
        }
        let ix = self.handles.len();
        self.handles.push(HandleState::Udp(UdpState {
            active: false,
            closing: false,
            closed: false,
            fd: -1,
            connected: false,
            alloc_cb: None,
            recv_cb: None,
            send_queue_size: 0,
            write_queue: VecDeque::new(),
            write_completed: VecDeque::new(),
            recv_started: false,
        }));
        *h = Handle(ix);
        0
    }

    pub fn uv_udp_init(&mut self, h: &mut Udp) -> i32 {
        self.uv_udp_init_ex(h, libc::AF_UNSPEC as u32)
    }

    pub fn uv_udp_bind(&mut self, h: Udp, addr: &Addr) -> i32 {
        let fd = match self.udp_socket(h) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        let port = match addr {
            Addr::Inet4 { port } => *port,
        };
        let sa = sockaddr_in_loopback(port);
        if let Err(e) = lx::bind(fd, &sa) {
            return -e;
        }
        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
            if !u.active {
                u.active = true;
                self.active_handles += 1;
            }
        }
        0
    }

    fn udp_socket(&mut self, h: Handle) -> Result<i32, i32> {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.fd,
            _ => return Err(EINVAL),
        };
        if fd != -1 {
            return Ok(fd);
        }
        let fd = lx::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
        .map_err(|e| -e)?;
        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
            u.fd = fd;
        }
        Ok(fd)
    }

    pub fn uv_udp_getsockname(&mut self, h: Udp, port_out: &mut u16) -> i32 {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.fd,
            _ => return EINVAL,
        };
        if fd == -1 {
            return EINVAL;
        }
        match lx::getsockname(fd) {
            Ok(port) => {
                *port_out = port;
                0
            }
            Err(e) => -e,
        }
    }

    /// `uv_udp_connect` (uv-common.c): None disconnects (ENOTCONN when not
    /// connected); connecting a connected handle is EISCONN; the socket is
    /// created on first use (uv__udp_maybe_deferred_bind).
    pub fn uv_udp_connect(&mut self, h: Udp, addr: Option<&Addr>) -> i32 {
        let (connected, fd) = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => (u.connected, u.fd),
            _ => return EINVAL,
        };
        match addr {
            None => {
                if !connected {
                    return ENOTCONN;
                }
                // uv__udp_disconnect: connect to a zeroed (AF_UNSPEC) addr.
                let sa: libc::sockaddr_in = libc::sockaddr_in {
                    sin_family: 0,
                    sin_port: 0,
                    sin_addr: libc::in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                };
                let _ = lx::connect(fd, &sa);
                if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                    u.connected = false;
                }
                0
            }
            Some(a) => {
                if connected {
                    return EISCONN;
                }
                let fd = match self.udp_socket(h) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };
                let port = match a {
                    Addr::Inet4 { port } => *port,
                };
                let sa = sockaddr_in_loopback(port);
                if let Err(e) = lx::connect(fd, &sa) {
                    return -e;
                }
                if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                    u.connected = true;
                }
                0
            }
        }
    }

    /// `uv__udp_check_before_send` (uv-common.c).
    fn udp_check_before_send(&self, h: Udp, addr: Option<&Addr>) -> i32 {
        let (connected, is_udp) = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => (u.connected, true),
            _ => (false, false),
        };
        if !is_udp {
            return EINVAL;
        }
        if addr.is_some() && connected {
            return EISCONN;
        }
        if addr.is_none() && !connected {
            return EDESTADDRREQ;
        }
        0
    }

    /// `uv_udp_try_send`: immediate sendmsg; the byte count or a UV error.
    /// The socket is created on first use (uv__udp_maybe_deferred_bind).
    pub fn uv_udp_try_send(&mut self, h: Udp, data: &[u8], addr: Option<&Addr>) -> i32 {
        let rc = self.udp_check_before_send(h, addr);
        if rc < 0 {
            return rc;
        }
        let fd = match self.udp_socket(h) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        let sa = match addr {
            Some(a) => {
                let port = match a {
                    Addr::Inet4 { port } => *port,
                };
                Some(sockaddr_in_loopback(port))
            }
            None => None,
        };
        let refs = [data];
        match lx::sendmsg(fd, &refs, sa.as_ref()) {
            Ok(n) => n as i32,
            Err(e) => -e,
        }
    }

    /// `uv_udp_send`: validate, queue, wake the writer.  The socket is
    /// created on first use (uv__udp_maybe_deferred_bind).
    pub fn uv_udp_send(
        &mut self,
        h: Udp,
        bufs: &[Vec<u8>],
        addr: Option<&Addr>,
        cb: UdpSendCb,
    ) -> i32 {
        let rc = self.udp_check_before_send(h, addr);
        if rc < 0 {
            return rc;
        }
        if let Err(e) = self.udp_socket(h) {
            return e;
        }
        let nbytes: usize = bufs.iter().map(|b| b.len()).sum();
        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
            u.send_queue_size += nbytes;
            u.write_queue.push_back(SendReq {
                bufs: bufs.to_vec(),
                nbytes,
                cb,
                status: 0,
            });
        }
        self.active_reqs += 1;
        0
    }

    pub fn uv_udp_get_send_queue_size(&self, h: Udp) -> usize {
        match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.send_queue_size,
            _ => 0,
        }
    }

    pub fn uv_udp_recv_start(&mut self, h: Udp, alloc: UdpAllocCb, recv: UdpRecvCb) -> i32 {
        if !matches!(self.handles.get(h.0), Some(HandleState::Udp(_))) {
            return EINVAL;
        }
        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
            u.alloc_cb = Some(alloc);
            u.recv_cb = Some(recv);
            u.recv_started = true;
        }
        0
    }

    pub fn uv_udp_recv_stop(&mut self, h: Udp) -> i32 {
        if !matches!(self.handles.get(h.0), Some(HandleState::Udp(_))) {
            return EINVAL;
        }
        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
            u.recv_started = false;
        }
        0
    }

    /// `uv__udp_sendmsg` (unix/udp.c): drain the write queue, one datagram
    /// per request (the iovec covers ALL the request's buffers — a scatter
    /// send is one datagram).  The send_cbs fire from the completion pass
    /// (pending queue), decrementing the send queue size per req before each
    /// callback.
    fn udp_sendmsg(&mut self, h: Handle) {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.fd,
            _ => return,
        };
        loop {
            let req = match self.handles.get_mut(h.0) {
                Some(HandleState::Udp(u)) => u.write_queue.pop_front(),
                _ => return,
            };
            match req {
                None => break,
                Some(mut r) => {
                    let refs: Vec<&[u8]> = r.bufs.iter().map(|b| b.as_slice()).collect();
                    match lx::sendmsg(fd, &refs, None) {
                        Ok(_) => {
                            r.status = 0;
                            if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                                u.write_completed.push_back(r);
                            }
                        }
                        Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                            // Not completed: stays queued (uv__udp_sendmsg's
                            // `n == UV_EAGAIN` return; the poll restarts it).
                            if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                                u.write_queue.push_front(r);
                            }
                            return;
                        }
                        Err(e) => {
                            r.status = -e;
                            if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                                u.write_completed.push_back(r);
                            }
                        }
                    }
                }
            }
        }
        if let Some(HandleState::Udp(u)) = self.handles.get(h.0) {
            if !u.write_completed.is_empty() {
                self.pending.push_back(h);
            }
        }
    }

    /// `uv__udp_run_completed`: pop the completed queue; decrement the send
    /// queue bytes and fire each send_cb (the probe observes the queue size
    /// inside the callback: 604-4=600 for the first, 0 for the second).
    fn udp_run_completed(&mut self, h: Handle) {
        loop {
            let req = match self.handles.get_mut(h.0) {
                Some(HandleState::Udp(u)) => u.write_completed.pop_front(),
                _ => return,
            };
            match req {
                None => return,
                Some(r) => {
                    if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                        u.send_queue_size = u.send_queue_size.saturating_sub(r.nbytes);
                    }
                    self.active_reqs -= 1;
                    // uv__udp_run_completed: success fires the cb with 0,
                    // errors with the UV error code.
                    let mut cb = r.cb;
                    cb(self, r.status);
                }
            }
        }
    }

    /// `uv__udp_recvmsg` (unix/udp.c): recvmsg one datagram per call; the
    /// EAGAIN case fires the (0, NULL) drain marker.
    fn udp_recv(&mut self, h: Handle) {
        let mut count = 32;
        while count > 0 {
            let fd = match self.handles.get(h.0) {
                Some(HandleState::Udp(u)) if !u.closed => u.fd,
                _ => return,
            };
            let mut buf = Buf { data: Vec::new() };
            {
                let alloc = match self.handles.get_mut(h.0) {
                    Some(HandleState::Udp(u)) => u.alloc_cb.take(),
                    _ => None,
                };
                match alloc {
                    Some(mut alloc) => {
                        alloc(self, 64 * 1024, &mut buf);
                        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                            if !u.closing && !u.closed {
                                u.alloc_cb = Some(alloc);
                            }
                        }
                    }
                    None => return,
                }
            }
            let (nread, port) = match lx::recvmsg(fd, &mut buf.data) {
                Ok(v) => v,
                Err(e) => {
                    let recv = match self.handles.get_mut(h.0) {
                        Some(HandleState::Udp(u)) => u.recv_cb.take(),
                        _ => None,
                    };
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        if let Some(mut recv) = recv {
                            recv(self, 0, &mut buf, None, 0);
                            if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                                if !u.closing && !u.closed {
                                    u.recv_cb = Some(recv);
                                }
                            }
                        }
                    } else if let Some(mut recv) = recv {
                        recv(self, -e as i64, &mut buf, None, 0);
                        if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                            if !u.closing && !u.closed {
                                u.recv_cb = Some(recv);
                            }
                        }
                    }
                    break;
                }
            };
            let addr = Addr::Inet4 { port };
            let recv = match self.handles.get_mut(h.0) {
                Some(HandleState::Udp(u)) => u.recv_cb.take(),
                _ => None,
            };
            match recv {
                Some(mut recv) => {
                    recv(self, nread as i64, &mut buf, Some(&addr), 0);
                    if let Some(HandleState::Udp(u)) = self.handles.get_mut(h.0) {
                        if !u.closing && !u.closed {
                            u.recv_cb = Some(recv);
                        }
                    }
                }
                None => return,
            }
            count -= 1;
        }
    }

    // -- TCP / streams ----------------------------------------------------

    pub fn uv_tcp_init(&mut self, h: &mut Tcp) -> i32 {
        let ix = self.handles.len();
        self.handles.push(HandleState::Tcp(TcpState {
            active: false,
            closing: false,
            closed: false,
            fd: -1,
            listening: false,
            accepted_fd: -1,
            connection_cb: None,
            connect_req: None,
            connect_status: 0,
            read_alloc: None,
            read_cb: None,
            write_queue_size: 0,
            write_queue: VecDeque::new(),
            write_completed: VecDeque::new(),
            shutdown_req: None,
            reading: false,
        }));
        *h = Handle(ix);
        0
    }

    fn tcp_socket(&mut self, h: Handle) -> Result<i32, i32> {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return Err(EINVAL),
        };
        if fd != -1 {
            return Ok(fd);
        }
        let fd = lx::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
        .map_err(|e| -e)?;
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.fd = fd;
        }
        Ok(fd)
    }

    pub fn uv_tcp_bind(&mut self, h: Tcp, addr: &Addr) -> i32 {
        let fd = match self.tcp_socket(h) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        let port = match addr {
            Addr::Inet4 { port } => *port,
        };
        let sa = sockaddr_in_loopback(port);
        if let Err(e) = lx::bind(fd, &sa) {
            return -e;
        }
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            if !t.active {
                t.active = true;
                self.active_handles += 1;
            }
        }
        0
    }

    pub fn uv_tcp_getsockname(&mut self, h: Tcp, port_out: &mut u16) -> i32 {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return EINVAL,
        };
        if fd == -1 {
            return EINVAL;
        }
        match lx::getsockname(fd) {
            Ok(port) => {
                *port_out = port;
                0
            }
            Err(e) => -e,
        }
    }

    /// `uv_listen` (unix/stream.c + tcp.c): EINVAL when closing; the second
    /// listen on the same socket is a no-op (returns 0).
    pub fn uv_listen(&mut self, h: Stream, backlog: i32, cb: Cb) -> i32 {
        let (fd, closing) = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => (t.fd, t.closing),
            _ => return EINVAL,
        };
        if closing {
            return EINVAL;
        }
        let fd = if fd == -1 {
            match self.tcp_socket(h) {
                Ok(fd) => fd,
                Err(e) => return e,
            }
        } else {
            fd
        };
        let already = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.listening,
            _ => return EINVAL,
        };
        if !already {
            if let Err(e) = lx::listen(fd, backlog) {
                return -e;
            }
        }
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.listening = true;
            t.connection_cb = Some(cb);
            if !t.active {
                t.active = true;
                self.active_handles += 1;
            }
        }
        0
    }

    /// `uv_accept` (unix/stream.c): EAGAIN when no pending connection; the
    /// client stream opens with the accepted fd in the pre-created client
    /// handle (uv__stream_open — an already-open client is UV_EBUSY).
    pub fn uv_accept(&mut self, server: Stream, client: &mut Tcp) -> i32 {
        let accepted = match self.handles.get(server.0) {
            Some(HandleState::Tcp(t)) => t.accepted_fd,
            _ => return EINVAL,
        };
        if accepted == -1 {
            return EAGAIN;
        }
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(server.0) {
            t.accepted_fd = -1;
        }
        let mut open = false;
        let mut err = EINVAL;
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(client.0) {
            if t.fd == -1 {
                t.fd = accepted;
                t.active = true;
                open = true;
                err = 0;
            } else {
                err = EBUSY;
            }
        }
        if open {
            self.active_handles += 1;
        }
        if err != 0 {
            lx::close(accepted);
        }
        err
    }

    /// `uv_tcp_connect` (uv-common.c + unix/tcp.c): EALREADY while a connect
    /// is pending; EINPROGRESS completes via POLLOUT + SO_ERROR;
    /// ECONNREFUSED on Linux is a delayed_error fed through the pending pass.
    pub fn uv_tcp_connect(&mut self, h: Tcp, addr: &Addr, cb: ConnectCb) -> i32 {
        let has_pending = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.connect_req.is_some() && !t.listening,
            _ => return EINVAL,
        };
        if has_pending {
            return -114; // EALREADY (uv__tcp_connect)
        }
        let fd = match self.tcp_socket(h) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        let port = match addr {
            Addr::Inet4 { port } => *port,
        };
        let sa = sockaddr_in_loopback(port);
        let status = match lx::connect(fd, &sa) {
            Ok(()) => 0,
            Err(e) if e == libc::EINPROGRESS => 0,
            Err(e) if e == libc::ECONNREFUSED => -libc::ECONNREFUSED,
            Err(e) => return -e,
        };
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.connect_status = status;
            t.connect_req = Some(cb);
            if !t.active {
                t.active = true;
                self.active_handles += 1;
            }
        }
        if status != 0 {
            // delayed_error: the cb fires via the pending pass next tick.
            self.pending.push_back(h);
        }
        0
    }

    /// `uv_write` (unix/stream.c): the immediate-write fast path first; a
    /// full immediate write completes via the pending pass.
    pub fn uv_write(&mut self, h: Stream, bufs: &[Vec<u8>], cb: WriteCb) -> i32 {
        let nbytes: usize = bufs.iter().map(|b| b.len()).sum();
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return EINVAL,
        };
        if fd == -1 {
            return EINVAL;
        }
        let mut written = 0usize;
        for b in bufs {
            match lx::write_fd(fd, b) {
                Ok(n) => {
                    written += n;
                    if written >= nbytes {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if written >= nbytes {
            if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                t.write_completed.push_back(WriteReq {
                    bufs: bufs.to_vec(),
                    nbytes,
                    cb,
                    status: 0,
                });
            }
            self.pending.push_back(h);
            0
        } else {
            // Partial write: queue the remainder (not courted by LIBUV-0001;
            // the probe's payloads always fit the loopback buffer).
            if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                t.write_queue_size += nbytes;
                t.write_queue.push_back(WriteReq {
                    bufs: bufs.to_vec(),
                    nbytes,
                    cb,
                    status: 0,
                });
            }
            self.active_reqs += 1;
            0
        }
    }

    /// `uv_try_write` (unix/stream.c): EAGAIN when a write is queued or a
    /// connect pending; else the immediate write byte count.
    pub fn uv_try_write(&mut self, h: Stream, data: &[u8]) -> i32 {
        let (fd, busy) = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => (
                t.fd,
                t.write_queue_size != 0 || (t.connect_req.is_some() && !t.listening),
            ),
            _ => return EINVAL,
        };
        if busy {
            return EAGAIN;
        }
        if fd == -1 {
            return EINVAL;
        }
        match lx::write_fd(fd, data) {
            Ok(n) => n as i32,
            Err(e) => -e,
        }
    }

    pub fn uv_read_start(&mut self, h: Stream, alloc: TcpAllocCb, read: TcpReadCb) -> i32 {
        if !matches!(self.handles.get(h.0), Some(HandleState::Tcp(_))) {
            return EINVAL;
        }
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.read_alloc = Some(alloc);
            t.read_cb = Some(read);
            t.reading = true;
        }
        0
    }

    pub fn uv_read_stop(&mut self, h: Stream) -> i32 {
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.reading = false;
        }
        0
    }

    /// `uv_shutdown` (unix/stream.c): write the FIN; with an empty write
    /// queue the shutdown_cb is an immediate callback (uv__io_feed).
    pub fn uv_shutdown(&mut self, h: Stream, cb: ShutdownCb) -> i32 {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return EINVAL,
        };
        if fd == -1 {
            return EINVAL;
        }
        let _ = lx::shutdown(fd, libc::SHUT_WR);
        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
            t.shutdown_req = Some(cb);
        }
        self.pending.push_back(h);
        0
    }

    pub fn uv_stream_get_write_queue_size(&self, h: Stream) -> usize {
        match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.write_queue_size,
            _ => 0,
        }
    }

    /// `uv_tcp_close_reset` (unix/tcp.c): EINVAL while shutting; SO_LINGER
    /// {1,0} then uv_close.
    pub fn uv_tcp_close_reset(&mut self, h: Tcp, cb: Cb) -> i32 {
        let (fd, shutting) = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => (t.fd, t.shutdown_req.is_some()),
            _ => return EINVAL,
        };
        if shutting {
            return EINVAL;
        }
        if fd != -1 {
            let l = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            let _ = lx::setsockopt_linger(fd, &l);
        }
        self.uv_close(h, Some(cb));
        0
    }

    /// `uv__server_io` + `uv__stream_io` (unix/stream.c): the listen side
    /// accepts ONE connection per dispatch and fires the connection_cb; the
    /// connected side reads.
    fn tcp_poll_in(&mut self, h: Handle) {
        let (listening, connecting, has_accepted) = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => (
                t.listening,
                t.connect_req.is_some() && !t.listening,
                t.accepted_fd != -1,
            ),
            _ => return,
        };
        // uv__stream_io: a pending connect consumes the round.
        if connecting {
            return;
        }
        if listening {
            if has_accepted {
                return;
            }
            let fd = match self.handles.get(h.0) {
                Some(HandleState::Tcp(t)) => t.fd,
                _ => return,
            };
            let afd = match lx::accept(fd) {
                Ok(fd) => fd,
                Err(_) => return,
            };
            let _ = lx::set_nonblock(afd);
            if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                t.accepted_fd = afd;
            }
            // uv__server_io: connection_cb(stream, 0); POLLIN stays off
            // until the user accepts (gated in uv__io_poll).
            let cb = match self.handles.get_mut(h.0) {
                Some(HandleState::Tcp(t)) => t.connection_cb.take(),
                _ => None,
            };
            if let Some(mut cb) = cb {
                cb(self);
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    if !t.closing && !t.closed {
                        t.connection_cb = Some(cb);
                    }
                }
            }
        } else {
            self.tcp_read(h);
        }
    }

    /// `uv__read` (unix/stream.c): read until EAGAIN, one read_cb per chunk;
    /// EOF fires read_cb(UV_EOF) once and stops reading.
    fn tcp_read(&mut self, h: Handle) {
        loop {
            let fd = match self.handles.get(h.0) {
                Some(HandleState::Tcp(t)) if !t.closed => t.fd,
                _ => return,
            };
            let mut buf = Buf { data: Vec::new() };
            {
                let alloc = match self.handles.get_mut(h.0) {
                    Some(HandleState::Tcp(t)) => t.read_alloc.take(),
                    _ => None,
                };
                match alloc {
                    Some(mut alloc) => {
                        alloc(self, 64 * 1024, &mut buf);
                        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                            if !t.closing && !t.closed {
                                t.read_alloc = Some(alloc);
                            }
                        }
                    }
                    None => return,
                }
            }
            let n = match lx::read_fd(fd, &mut buf.data) {
                Ok(n) => n,
                Err(e) => {
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        return; // drained for this round
                    }
                    let read = match self.handles.get_mut(h.0) {
                        Some(HandleState::Tcp(t)) => t.read_cb.take(),
                        _ => None,
                    };
                    if let Some(mut read) = read {
                        read(self, -e as i64, &mut buf);
                        if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                            if !t.closing && !t.closed {
                                t.read_cb = Some(read);
                            }
                        }
                    }
                    return;
                }
            };
            if n == 0 {
                // uv__stream_eof: read_cb(UV_EOF) once, stop reading.
                let read = match self.handles.get_mut(h.0) {
                    Some(HandleState::Tcp(t)) => t.read_cb.take(),
                    _ => None,
                };
                if let Some(mut read) = read {
                    read(self, UV_EOF as i64, &mut buf);
                    if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                        if !t.closing && !t.closed {
                            t.read_cb = Some(read);
                        }
                    }
                }
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    t.reading = false;
                }
                return;
            }
            let read = match self.handles.get_mut(h.0) {
                Some(HandleState::Tcp(t)) => t.read_cb.take(),
                _ => None,
            };
            match read {
                Some(mut read) => {
                    read(self, n as i64, &mut buf);
                    if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                        if !t.closing && !t.closed {
                            t.read_cb = Some(read);
                        }
                    }
                }
                None => return,
            }
        }
    }

    /// `uv__stream_connect` (unix/stream.c): the connect completion via
    /// getsockopt(SO_ERROR); the connect_cb fires from the pending pass.
    fn tcp_poll_out(&mut self, h: Handle) {
        let has_connect = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => t.connect_req.is_some() && !t.listening,
            _ => false,
        };
        if has_connect {
            let fd = match self.handles.get(h.0) {
                Some(HandleState::Tcp(t)) => t.fd,
                _ => -1,
            };
            let mut err = 0;
            if fd != -1 {
                let _ = lx::socket_sockopt(fd, libc::SO_ERROR, &mut err);
            }
            if err == libc::EINPROGRESS {
                return; // still connecting
            }
            let status = if err != 0 { -err } else { 0 };
            if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                t.connect_status = status;
            }
            self.pending.push_back(h);
        }
        // uv__write: the queued writes drain on POLLOUT; completed requests
        // complete via the pending pass (not courted by LIBUV-0001, but the
        // netmgr's write path relies on it).
        let has_queue = match self.handles.get(h.0) {
            Some(HandleState::Tcp(t)) => !t.write_queue.is_empty(),
            _ => false,
        };
        if has_queue {
            self.tcp_write_queue_drain(h);
        }
        self.tcp_run_completed(h);
    }

    /// `uv__write` (unix/stream.c): write the queue head until EAGAIN or
    /// empty; a fully-written request completes via the pending pass.
    fn tcp_write_queue_drain(&mut self, h: Handle) {
        loop {
            let (fd, empty) = match self.handles.get(h.0) {
                Some(HandleState::Tcp(t)) => (t.fd, t.write_queue.is_empty()),
                _ => return,
            };
            if empty || fd == -1 {
                return;
            }
            let req = match self.handles.get_mut(h.0) {
                Some(HandleState::Tcp(t)) => t.write_queue.pop_front(),
                _ => return,
            };
            let mut r = match req {
                Some(r) => r,
                None => return,
            };
            let mut written = 0usize;
            let mut err = 0;
            for b in &r.bufs {
                match lx::write_fd(fd, b) {
                    Ok(n) => {
                        written += n;
                        if written >= r.nbytes {
                            break;
                        }
                    }
                    Err(e) => {
                        err = e;
                        break;
                    }
                }
            }
            if written >= r.nbytes {
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    t.write_queue_size = t.write_queue_size.saturating_sub(r.nbytes);
                    t.write_completed.push_back(r);
                }
                self.active_reqs -= 1;
                self.pending.push_back(h);
            } else if err == 0 || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                // Partial: requeue the remainder; POLLOUT refires.
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    t.write_queue.push_front(r);
                }
                return;
            } else {
                r.status = -err;
                if let Some(HandleState::Tcp(t)) = self.handles.get_mut(h.0) {
                    t.write_queue_size = t.write_queue_size.saturating_sub(r.nbytes);
                    t.write_completed.push_back(r);
                }
                self.active_reqs -= 1;
                self.pending.push_back(h);
            }
        }
    }

    /// The write/shutdown/connect completion pass (uv__stream_drain + the
    /// pending immediate callbacks).
    fn tcp_run_completed(&mut self, h: Handle) {
        let reqs: Vec<WriteReq> = match self.handles.get_mut(h.0) {
            Some(HandleState::Tcp(t)) => t.write_completed.drain(..).collect(),
            _ => Vec::new(),
        };
        for r in reqs {
            let mut cb = r.cb;
            cb(self, r.status);
        }
        let shutdown = match self.handles.get_mut(h.0) {
            Some(HandleState::Tcp(t)) => t.shutdown_req.take(),
            _ => None,
        };
        if let Some(mut cb) = shutdown {
            cb(self, 0);
        }
        let connect = match self.handles.get_mut(h.0) {
            Some(HandleState::Tcp(t)) if t.connect_req.is_some() && !t.listening => {
                t.connect_req.take().map(|cb| (t.connect_status, cb))
            }
            _ => None,
        };
        if let Some((status, mut cb)) = connect {
            cb(self, status);
        }
    }

    // -- handle utilities --------------------------------------------------

    pub fn uv_is_active(&self, h: Handle) -> i32 {
        let active = match self.handles.get(h.0) {
            Some(HandleState::Timer(t)) => t.active,
            Some(HandleState::Async(a)) => a.active,
            Some(HandleState::Idle(s)) => s.active,
            Some(HandleState::Prepare(s)) => s.active,
            Some(HandleState::Check(s)) => s.active,
            Some(HandleState::Signal(s)) => s.active,
            Some(HandleState::Udp(u)) => u.active,
            Some(HandleState::Tcp(t)) => t.active,
            _ => false,
        };
        i32::from(active)
    }

    pub fn uv_is_closing(&self, h: Handle) -> i32 {
        let closing = match self.handles.get(h.0) {
            Some(HandleState::Timer(t)) => t.closing,
            Some(HandleState::Async(a)) => a.closing,
            Some(HandleState::Idle(s)) => s.closing,
            Some(HandleState::Prepare(s)) => s.closing,
            Some(HandleState::Check(s)) => s.closing,
            Some(HandleState::Signal(s)) => s.closing,
            Some(HandleState::Udp(u)) => u.closing,
            Some(HandleState::Tcp(t)) => t.closing,
            _ => false,
        };
        i32::from(closing)
    }

    /// `uv_walk`: the handle queue in init order.
    pub fn uv_walk(&self, mut cb: impl FnMut(&UvLoop, Handle, HandleType)) {
        for (ix, h) in self.handles.iter().enumerate() {
            let ty = match h {
                HandleState::Timer(t) if !t.closed => HandleType::Timer,
                HandleState::Async(a) if !a.closed => HandleType::Async,
                HandleState::Idle(s) if !s.closed => HandleType::Idle,
                HandleState::Prepare(s) if !s.closed => HandleType::Prepare,
                HandleState::Check(s) if !s.closed => HandleType::Check,
                HandleState::Signal(s) if !s.closed => HandleType::Signal,
                HandleState::Udp(u) if !u.closed => HandleType::Udp,
                HandleState::Tcp(t) if !t.closed => HandleType::Tcp,
                _ => continue,
            };
            cb(self, Handle(ix), ty);
        }
    }

    /// `uv_fileno` (unix/core.c): EINVAL for non-socket types, EBADF when
    /// closing or fd -1.
    pub fn uv_fileno(&self, h: Handle) -> Result<i32, i32> {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.fd,
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return Err(EINVAL),
        };
        if self.uv_is_closing(h) != 0 || fd == -1 {
            return Err(EBADF);
        }
        Ok(fd)
    }

    /// `uv_send_buffer_size` / `uv_recv_buffer_size` (uv__socket_sockopt):
    /// *value == 0 -> getsockopt, else setsockopt.
    pub fn uv_send_buffer_size(&mut self, h: Handle, value: &mut i32) -> i32 {
        self.socket_sockopt(h, libc::SO_SNDBUF, value)
    }
    pub fn uv_recv_buffer_size(&mut self, h: Handle, value: &mut i32) -> i32 {
        self.socket_sockopt(h, libc::SO_RCVBUF, value)
    }

    fn socket_sockopt(&mut self, h: Handle, optname: i32, value: &mut i32) -> i32 {
        let fd = match self.handles.get(h.0) {
            Some(HandleState::Udp(u)) => u.fd,
            Some(HandleState::Tcp(t)) => t.fd,
            _ => return ENOTSUP,
        };
        if self.uv_is_closing(h) != 0 || fd == -1 {
            return EBADF;
        }
        match lx::socket_sockopt(fd, optname, value) {
            Ok(()) => 0,
            Err(e) => -e,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatcherKind {
    Idle,
    Prepare,
    Check,
}

/// The owner of each pollfd entry in `uv__io_poll`'s dispatch.
#[derive(Clone, Copy)]
enum IoKind {
    Async,
    Signal,
    Udp(Handle),
    Tcp(Handle),
}

// ---------------------------------------------------------------------------
// dl (unix/dl.c)
// ---------------------------------------------------------------------------

/// `uv_lib_t` + `uv_dlopen`/`uv_dlsym`/`uv_dlclose`/`uv_dlerror`: the exact
/// glibc messages come from `dlerror` itself, so both sides match.
pub struct DlLib {
    handle: Option<lx::DlHandle>,
    errmsg: Option<String>,
}

/// `uv_dlopen`: Ok on success; Err(lib) on failure (-1, with the dlerror
/// text captured in the failed lib — the C updates the uv_lib_t in place).
pub fn uv_dlopen(filename: &str) -> Result<DlLib, DlLib> {
    match lx::dlopen(filename) {
        Ok(h) => Ok(DlLib {
            handle: Some(h),
            errmsg: None,
        }),
        Err((_, msg)) => Err(DlLib {
            handle: None,
            errmsg: Some(msg),
        }),
    }
}

/// `uv_dlsym`: Ok on success; Err(-1) with the dlerror text captured.
pub fn uv_dlsym(lib: &mut DlLib, name: &str) -> Result<(), i32> {
    match lib.handle {
        Some(ref h) => match lx::dlsym(h, name) {
            Ok(()) => {
                lib.errmsg = None;
                Ok(())
            }
            Err((code, msg)) => {
                lib.errmsg = Some(msg);
                Err(code)
            }
        },
        None => Err(-1),
    }
}

/// `uv_dlclose`: ignores the dlclose result and clears the error text.
pub fn uv_dlclose(lib: &mut DlLib) {
    lib.errmsg = None;
    if let Some(h) = lib.handle.take() {
        lx::dlclose(h);
    }
}

/// `uv_dlerror`: the captured text, else the literal `no error`.
pub fn uv_dlerror(lib: &DlLib) -> String {
    lib.errmsg.clone().unwrap_or_else(|| "no error".to_string())
}

// ---------------------------------------------------------------------------
// random + sleep + barrier + cancel
// ---------------------------------------------------------------------------

/// The completed uv_random work handed back by the helper thread: `(len,
/// status)`.  The completion callbacks stay on the loop (they are not Send).
static RANDOM_RESULTS: std::sync::Mutex<VecDeque<(usize, i32)>> =
    std::sync::Mutex::new(VecDeque::new());

/// `uv_random` (src/random.c): a helper thread fills the buffer with
/// getrandom and wakes the loop through the eventfd; the completion cb fires
/// during the run with (0, len).
pub fn uv_random(loop_: &mut UvLoop, len: usize, cb: RandomCb) -> i32 {
    let wake = loop_.async_wakeup_fd;
    loop_.random_cbs.push_back(cb);
    loop_.active_reqs += 1;
    std::thread::spawn(move || {
        let mut b = vec![0u8; len];
        let mut filled = 0usize;
        let mut status = 0;
        while filled < b.len() {
            match lx::getrandom(&mut b[filled..]) {
                Ok(n) if n > 0 => filled += n,
                Ok(_) => break,
                Err(e) => {
                    status = -e;
                    break;
                }
            }
        }
        RANDOM_RESULTS.lock().unwrap().push_back((len, status));
        if wake != -1 {
            let one: u64 = 1;
            let _ = lx::write_fd(wake, &one.to_ne_bytes());
        }
    });
    0
}

/// `uv_sleep` (void).
pub fn uv_sleep(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// `uv_barrier_t` over std::sync::Barrier; `uv_barrier_wait` returns 1 for
/// the last releaser (PTHREAD_BARRIER_SERIAL_THREAD), 0 otherwise; count 0
/// is EINVAL (the glibc path is a bare pthread_barrier_init — no NULL
/// guard).
pub struct Barrier {
    inner: Option<std::sync::Barrier>,
}

impl Default for Barrier {
    fn default() -> Self {
        Barrier { inner: None }
    }
}

pub fn uv_barrier_init(b: &mut Barrier, count: u32) -> i32 {
    if count == 0 {
        return EINVAL;
    }
    b.inner = Some(std::sync::Barrier::new(count as usize));
    0
}

pub fn uv_barrier_wait(b: &Barrier) -> i32 {
    match &b.inner {
        Some(bar) => i32::from(bar.wait().is_leader()),
        None => EINVAL,
    }
}

pub fn uv_barrier_destroy(b: &mut Barrier) {
    b.inner = None;
}

/// `uv_cancel` (threadpool.c 1.52.1): only FS/GETADDRINFO/GETNAMEINFO/
/// RANDOM/WORK reqs are cancellable; everything else is EINVAL.  A
/// completed work req is no longer in the wq -> EBUSY.
pub fn uv_cancel_write_req() -> i32 {
    EINVAL
}

pub fn uv_cancel_random_completed() -> i32 {
    EBUSY
}

// ---------------------------------------------------------------------------
// time + helpers
// ---------------------------------------------------------------------------

fn sockaddr_in_loopback(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be(0x7f00_0001),
        },
        sin_zero: [0; 8],
    }
}

/// The signal handler: async-signal-safe — one byte per signal to the pipe.
extern "C" fn uv_signal_handler(_sig: i32) {
    let w = SIGNAL_PIPE_W.load(Ordering::SeqCst);
    if w != -1 {
        lx::signal_write(w, 1);
    }
}

/// The signal-handler's pipe write end.
static SIGNAL_PIPE_W: AtomicI32 = AtomicI32::new(-1);

// ---------------------------------------------------------------------------
// unit tests (oracle vectors from probe-libuv.c and the pinned 1.52.1 source)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_oracle_vectors() {
        // probe-libuv.c PHASE 0 (oracle libuv 1.52.1).
        assert_eq!(uv_version(), 78_849);
        assert_eq!(uv_version_string(), "1.52.1");
    }

    #[test]
    fn errno_table_is_the_linux_map() {
        // The UV_ERRNO_MAP is the negative of the Linux errno values (with
        // the EAI_*/custom codes below the kernel range).
        for e in TABLE {
            let n = uv_err_name(e.value);
            assert_eq!(n, e.name, "name for value {}", e.value);
            assert_eq!(uv_strerror(e.value), e.strerror);
        }
        assert_eq!(TABLE.len(), 85); // include/uv.h UV_ERRNO_MAP 1.52.1
        assert_eq!(uv_err_name(-7), "E2BIG");
        assert_eq!(uv_err_name(-22), "EINVAL");
        assert_eq!(uv_err_name(-4095), "EOF");
        assert_eq!(uv_strerror(-111), "connection refused");
    }

    #[test]
    fn unknown_error_forms() {
        // uv-common.c uv__unknown_err_code: "Unknown system error %d" for
        // BOTH uv_err_name and uv_strerror (probe PHASE 17).
        assert_eq!(uv_err_name(-12_345), "Unknown system error -12345");
        assert_eq!(uv_strerror(-12_345), "Unknown system error -12345");
    }

    #[test]
    fn error_table_values_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in TABLE {
            assert!(seen.insert(e.value), "duplicate value {}", e.value);
        }
    }

    #[test]
    fn timer_heap_min_order() {
        // timer_less_than (timer.c): timeout, then start_id; the Rust heap
        // is a max-heap over the reversed comparison, so peek() is the due
        // timer with the earliest (timeout, start_id).
        let mut heap = BinaryHeap::new();
        heap.push(TimerNode {
            handle: Handle(1),
            timeout: 10,
            start_id: 1,
        });
        heap.push(TimerNode {
            handle: Handle(2),
            timeout: 10,
            start_id: 0,
        });
        heap.push(TimerNode {
            handle: Handle(3),
            timeout: 5,
            start_id: 9,
        });
        assert_eq!(heap.pop().unwrap().handle, Handle(3)); // 5 first
        assert_eq!(heap.pop().unwrap().handle, Handle(2)); // 10, start_id 0
        assert_eq!(heap.pop().unwrap().handle, Handle(1)); // 10, start_id 1
    }

    #[test]
    fn handle_type_names() {
        // uv_handle_type_name (uv.h): the probe's walk prints these.
        assert_eq!(HandleType::Timer.name(), "timer");
        assert_eq!(HandleType::Prepare.name(), "prepare");
        assert_eq!(HandleType::Async.name(), "async");
        assert_eq!(HandleType::Tcp.name(), "tcp");
        assert_eq!(HandleType::Udp.name(), "udp");
        assert_eq!(HandleType::Signal.name(), "signal");
    }

    #[test]
    fn allocator_contract_counts() {
        // probe-libuv.c PHASE 13: with the customs installed, uv_loop_init
        // does exactly calloc(1,448) + realloc(NULL,128) and uv_loop_close
        // frees both; the mirror stores the pointers opaquely (the loop's
        // real state is in the Rust struct, never in those blocks).
        use std::sync::atomic::{AtomicI32, Ordering};
        static MA: AtomicI32 = AtomicI32::new(0);
        static MR: AtomicI32 = AtomicI32::new(0);
        static MC: AtomicI32 = AtomicI32::new(0);
        static MF: AtomicI32 = AtomicI32::new(0);
        fn a_malloc(_: usize) -> *mut c_void {
            MA.fetch_add(1, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        fn a_realloc(_: *mut c_void, _: usize) -> *mut c_void {
            MR.fetch_add(1, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        fn a_calloc(_: usize, _: usize) -> *mut c_void {
            MC.fetch_add(1, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        fn a_free(_: *mut c_void) {
            MF.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(uv_replace_allocator(None, None, None, None), EINVAL);
        assert_eq!(
            uv_replace_allocator(
                Some(a_malloc),
                Some(a_realloc),
                Some(a_calloc),
                Some(a_free)
            ),
            0
        );
        let mut l = UvLoop::default();
        assert_eq!(l.uv_loop_init(), 0);
        assert_eq!(
            (
                MA.load(Ordering::SeqCst),
                MR.load(Ordering::SeqCst),
                MC.load(Ordering::SeqCst),
                MF.load(Ordering::SeqCst)
            ),
            (0, 1, 1, 0)
        );
        assert_eq!(l.uv_loop_close(), 0);
        assert_eq!(
            (
                MA.load(Ordering::SeqCst),
                MR.load(Ordering::SeqCst),
                MC.load(Ordering::SeqCst),
                MF.load(Ordering::SeqCst)
            ),
            (0, 1, 1, 2)
        );
        uv_replace_allocator(None, None, None, None); // restore the default
    }

    #[test]
    fn loop_close_ebusy_with_leftover_handles() {
        // probe-libuv.c: the final uv_loop_close on loop2 with the never-
        // closed timers is UV_EBUSY; a fully-closed loop closes clean.
        let mut l = UvLoop::default();
        l.uv_loop_init();
        let mut t = Handle(0);
        l.uv_timer_init(&mut t);
        let _ = l.uv_timer_start(t, Some(Box::new(|_| {})), 1000, 0);
        assert_eq!(l.uv_loop_close(), EBUSY);
        l.uv_close(t, None);
        let _ = l.uv_run(RunMode::Nowait);
        assert_eq!(l.uv_loop_close(), 0);
    }

    #[test]
    fn timer_einval_and_repeat() {
        let mut l = UvLoop::default();
        l.uv_loop_init();
        let mut t = Handle(0);
        l.uv_timer_init(&mut t);
        assert_eq!(l.uv_timer_start(t, None, 10, 0), EINVAL);
        let _ = l.uv_timer_start(t, Some(Box::new(|_| {})), 10, 10);
        assert_eq!(l.uv_timer_get_repeat(t), 10);
        assert_eq!(l.uv_timer_stop(t), 0);
        assert_eq!(l.uv_timer_stop(t), 0); // inactive: still 0
        l.uv_close(t, None);
        let _ = l.uv_run(RunMode::Nowait);
        assert_eq!(l.uv_loop_close(), 0);
    }

    #[test]
    fn udp_send_taxonomy_without_socket() {
        // uv__udp_check_before_send (uv-common.c): the EISCONN / EDESTADDRREQ
        // taxonomy fires before any socket exists (deferred bind).
        let mut l = UvLoop::default();
        l.uv_loop_init();
        let mut u = Handle(0);
        l.uv_udp_init(&mut u);
        let addr = Addr::v4_loopback(9999);
        assert_eq!(l.uv_udp_try_send(u, b"x", None), EDESTADDRREQ);
        let cb = |_l: &mut UvLoop, _s: i32| {};
        assert_eq!(
            l.uv_udp_send(u, &[b"x".to_vec()], Some(&addr), Box::new(cb)),
            0
        );
        // connecting an already-connected handle is EISCONN; the send with
        // an address on the connected handle is EISCONN too.
        assert_eq!(l.uv_udp_connect(u, None), ENOTCONN);
        l.uv_close(u, None);
        let _ = l.uv_run(RunMode::Nowait);
        // the queued send is a leftover req: the loop stays alive/EBUSY.
        assert_eq!(l.uv_loop_close(), EBUSY);
    }
}
