//! Linux-specific tool behavior (§1 `platform/linux`): capability syscalls
//! (capget/capset), `prctl`, xattr access for file capabilities, and the
//! process primitives the libcap conservation module needs (fork/execve,
//! setuid/setgroups, chroot).
//!
//! This module is one of the TWO audited unsafe boundaries in this crate
//! (`platform::unsafe_boundary` is the registry).  Every `unsafe` block here
//! carries an inventory ID (U-XXXX) and a documented safety invariant
//! (addendum §49).  The callers in `compat::libcap` are safe Rust.
//!
//! Safety doctrine: every libc call receives only well-formed arguments
//! (valid pointers into live buffers of the declared size, valid enum-like
//! ints), errno is captured immediately after each call, and the result is
//! translated into a `Result` so no libc error state leaks upward.

#![allow(unsafe_code)] // audited boundary; inventory in unsafe_boundary.rs

use std::ffi::CString;
use std::os::raw::{c_int, c_long, c_void};

/// A libc errno value captured from the boundary.
pub type Errno = i32;

/// `sysconf(_SC_PAGE_SIZE)` (U-0028): the system page size in bytes, used by
/// the LMDB conservation to size fresh environments (mdb_env_create uses the
/// page size for `me_psize` when creating a new data file).
///
/// # Safety invariant (U-0028)
/// No arguments; returns a positive `long` on success and -1 on failure.
/// Callers must tolerate the 4096 fallback (the minimum any supported Linux
/// page size can be, and what the C's own fallback path effectively yields).
pub fn page_size() -> u32 {
    // SAFETY (U-0028): argument-less sysconf query; result copied before any
    // other call.
    let ps = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    if ps > 0 {
        ps as u32
    } else {
        4096
    }
}

/// Translate a libc return into `Result`, capturing errno (U-0001).
///
/// # Safety invariant (U-0001)
/// `ret < 0` is the libc failure convention for every wrapped call; errno is
/// read immediately (no intervening calls) and is only meaningful after a
/// negative return.
fn check(ret: c_long) -> Result<c_long, Errno> {
    if ret < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(ret)
    }
}

/// `prctl(option, arg1..arg5)` (U-0002).
///
/// # Safety invariant (U-0002)
/// Mirrors `cap_prctl` (cap_proc.c): all six arguments are passed verbatim;
/// the caller (compat::libcap) supplies only integer constants and pointer
/// values it owns.  `prctl` never retains the arguments after returning.
pub fn prctl(
    option: c_int,
    arg1: c_long,
    arg2: c_long,
    arg3: c_long,
    arg4: c_long,
    arg5: c_long,
) -> Result<c_long, Errno> {
    // SAFETY (U-0002): arguments are caller-supplied integers; the kernel
    // copies any pointer arguments synchronously during the call.
    let ret = unsafe { libc::prctl(option, arg1, arg2, arg3, arg4, arg5) };
    check(ret as c_long)
}

/// The kernel `__user_cap_header_struct` (linux/capability.h) — not exposed
/// by the libc crate on this target, so declared here with the exact ABI
/// layout (u32 version, int pid, no padding on x86_64).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CapHeader {
    pub version: u32,
    pub pid: i32,
}

/// The kernel `__user_cap_data_struct` — three u32s, no padding.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `capget(&header, data)` (U-0003).
///
/// # Safety invariant (U-0003)
/// `data` must point to at least `CAP_SET_SIZE` bytes (2 × `__u32` × 3
/// sets); the kernel writes exactly that many bytes for version 3 headers.
/// The caller passes a 6-element `[u32; 6]` (eff0, perm0, inh0, eff1, perm1,
/// inh1 — the kernel's `flat[3]` layout per block).
pub fn capget(header: &mut CapHeader, data: &mut [u32; 6]) -> Result<(), Errno> {
    let mut h = CapHeader {
        version: header.version,
        pid: header.pid,
    };
    let mut d = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY (U-0003): &mut h and &mut d point to valid, aligned objects of
    // the exact kernel ABI layout; the kernel fills them per the version.
    // libc does not bind capget, so we use the raw syscall (SYS_capget).
    let ret = unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut _, d.as_mut_ptr()) };
    header.version = h.version;
    match check(ret) {
        Ok(_) => {
            data[0] = d[0].effective;
            data[1] = d[0].permitted;
            data[2] = d[0].inheritable;
            data[3] = d[1].effective;
            data[4] = d[1].permitted;
            data[5] = d[1].inheritable;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// `capset(&header, data)` (U-0004).
///
/// # Safety invariant (U-0004)
/// Same buffer contract as U-0003; the kernel only reads the data.
pub fn capset(header: &CapHeader, data: &[u32; 6]) -> Result<(), Errno> {
    let h = CapHeader {
        version: header.version,
        pid: header.pid,
    };
    let d = [
        CapData {
            effective: data[0],
            permitted: data[1],
            inheritable: data[2],
        },
        CapData {
            effective: data[3],
            permitted: data[4],
            inheritable: data[5],
        },
    ];
    // SAFETY (U-0004): h and d are fully initialized copies of the ABI
    // structs; the kernel only reads them during the call.
    let ret = unsafe { libc::syscall(libc::SYS_capset, &h as *const _, d.as_ptr()) };
    check(ret).map(|_| ())
}

/// `getxattr(path, name, buf)` (U-0005).
///
/// # Safety invariant (U-0005)
/// `buf` must be valid for writes of `buf.len()` bytes; the kernel writes at
/// most that many.  The return value (<= len, or ERANGE if larger) is
/// returned as the byte count.
pub fn getxattr(path: &CString, name: &CString, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY (U-0005): path/name are NUL-terminated owned CStrings; buf is a
    // live slice; the kernel copies into it bounded by buf.len().
    let ret = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `setxattr(path, name, value)` (U-0006).
///
/// # Safety invariant (U-0006)
/// `value` is a live slice; the kernel reads exactly `value.len()` bytes.
pub fn setxattr(path: &CString, name: &CString, value: &[u8]) -> Result<(), Errno> {
    // SAFETY (U-0006): path/name are NUL-terminated CStrings; value is a
    // live slice of the declared length.
    let ret = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    check(ret as c_long).map(|_| ())
}

/// `removexattr(path, name)` (U-0007).
pub fn removexattr(path: &CString, name: &CString) -> Result<(), Errno> {
    // SAFETY (U-0007): both arguments are NUL-terminated owned CStrings.
    let ret = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };
    check(ret as c_long).map(|_| ())
}

/// `fgetxattr(fd, name, buf)` (U-0008) — buffer contract as U-0005.
pub fn fgetxattr(fd: c_int, name: &CString, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY (U-0008): fd is a valid open descriptor owned by the caller;
    // name is NUL-terminated; buf is a live slice bounded by buf.len().
    let ret = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `fsetxattr(fd, name, value)` (U-0009).
pub fn fsetxattr(fd: c_int, name: &CString, value: &[u8]) -> Result<(), Errno> {
    // SAFETY (U-0009): fd is caller-owned; name NUL-terminated; value is a
    // live slice of the declared length.
    let ret = unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    check(ret as c_long).map(|_| ())
}

/// `fremovexattr(fd, name)` (U-0010).
pub fn fremovexattr(fd: c_int, name: &CString) -> Result<(), Errno> {
    // SAFETY (U-0010): fd caller-owned; name NUL-terminated.
    let ret = unsafe { libc::fremovexattr(fd, name.as_ptr()) };
    check(ret as c_long).map(|_| ())
}

/// `open(path, flags)` (U-0011).
///
/// # Safety invariant (U-0011)
/// `path` is a NUL-terminated CString; flags are caller-chosen constants.
/// Returns the owned fd (caller must close it).
pub fn open(path: &CString, flags: c_int) -> Result<c_int, Errno> {
    // SAFETY (U-0011): path is a NUL-terminated owned CString.
    let ret = unsafe { libc::open(path.as_ptr(), flags) };
    check(ret as c_long).map(|fd| fd as c_int)
}

/// `fstat(fd)` (U-0012): returns the raw st_mode.
pub fn fstat_mode(fd: c_int) -> Result<u32, Errno> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY (U-0012): st is a valid out-parameter of the exact ABI type;
    // fd is caller-owned.
    let ret = unsafe { libc::fstat(fd, &mut st) };
    check(ret as c_long)?;
    Ok(st.st_mode)
}

/// `close(fd)` (U-0013).
pub fn close(fd: c_int) {
    // SAFETY (U-0013): fd is owned by the caller and not used afterwards.
    unsafe {
        libc::close(fd);
    }
}

/// `getuid()`, `geteuid()`, `getgid()`, `getegid()` (U-0014) — no failure
/// mode; safe wrappers over the trivial getters.
pub fn getuid() -> u32 {
    // SAFETY (U-0014): getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn geteuid() -> u32 {
    // SAFETY (U-0014): geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn getgid() -> u32 {
    // SAFETY (U-0014): getgid has no preconditions and cannot fail.
    unsafe { libc::getgid() }
}

pub fn getegid() -> u32 {
    // SAFETY (U-0014): getegid has no preconditions and cannot fail.
    unsafe { libc::getegid() }
}

/// `setuid(uid)` (U-0015).
pub fn setuid(uid: u32) -> Result<(), Errno> {
    // SAFETY (U-0015): plain integer argument.
    let ret = unsafe { libc::setuid(uid) };
    check(ret as c_long).map(|_| ())
}

/// `setgid(gid)` (U-0016).
pub fn setgid(gid: u32) -> Result<(), Errno> {
    // SAFETY (U-0016): plain integer argument.
    let ret = unsafe { libc::setgid(gid) };
    check(ret as c_long).map(|_| ())
}

/// `setgroups(ngroups, groups)` (U-0017).
///
/// # Safety invariant (U-0017)
/// `groups` must have at least `ngroups` elements; the kernel reads exactly
/// that many.
pub fn setgroups(groups: &[u32]) -> Result<(), Errno> {
    // SAFETY (U-0017): groups is a live slice; the kernel reads groups.len()
    // gid_t values (u32 == gid_t on Linux).
    let ret = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    check(ret as c_long).map(|_| ())
}

/// `pipe2(flags)` (U-0018): returns (read_fd, write_fd).
pub fn pipe2(flags: c_int) -> Result<(c_int, c_int), Errno> {
    let mut fds = [0 as c_int; 2];
    // SAFETY (U-0018): fds is a valid 2-element out-array.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };
    check(ret as c_long)?;
    Ok((fds[0], fds[1]))
}

/// `fork()` (U-0019): 0 in the child, child pid in the parent, -1 on error.
pub fn fork() -> Result<c_int, Errno> {
    // SAFETY (U-0019): fork has no arguments; the returned pid is handled by
    // the caller (cap_launch) which is the only fork user in this crate.
    let ret = unsafe { libc::fork() };
    match ret {
        -1 => Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)),
        _ => Ok(ret),
    }
}

/// `execve(arg0, argv, envp)` (U-0020).
///
/// # Safety invariant (U-0020)
/// arg0/argv/envp are NUL-terminated CString arrays built by the caller; on
/// success execve does not return; on failure errno is returned.
pub fn execve(arg0: &CString, argv: &[CString], envp: &[CString]) -> Result<(), Errno> {
    let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    // SAFETY (U-0020): all pointed-to strings are live owned CStrings; the
    // arrays are NUL-terminated; the kernel copies them synchronously.
    unsafe {
        libc::execve(
            arg0.as_ptr(),
            argv_ptrs.as_ptr() as *const *const c_char,
            envp_ptrs.as_ptr() as *const *const c_char,
        )
    };
    Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `waitpid(pid, 0)` (U-0021): returns the pid.
pub fn waitpid(pid: c_int) -> Result<c_int, Errno> {
    let mut status: c_int = 0;
    // SAFETY (U-0021): status is a valid out-parameter.
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    check(ret as c_long).map(|p| p as c_int)
}

/// `chroot(path)` (U-0022).
pub fn chroot(path: &CString) -> Result<(), Errno> {
    // SAFETY (U-0022): path is a NUL-terminated owned CString.
    let ret = unsafe { libc::chroot(path.as_ptr()) };
    check(ret as c_long).map(|_| ())
}

/// `chdir("/")` (U-0023).
pub fn chdir_root() -> Result<(), Errno> {
    let root = CString::new("/").unwrap();
    // SAFETY (U-0023): root is a NUL-terminated owned CString.
    let ret = unsafe { libc::chdir(root.as_ptr()) };
    check(ret as c_long).map(|_| ())
}

/// `read(fd, buf)` (U-0024): returns the byte count (0 = EOF).
pub fn read_fd(fd: c_int, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY (U-0024): fd is caller-owned; buf is a live slice bounded by
    // buf.len(); the kernel copies into it synchronously.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `write(fd, buf)` (U-0025).
pub fn write_fd(fd: c_int, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY (U-0025): fd is caller-owned; buf is a live slice of the
    // declared length; the kernel reads it synchronously.
    let ret = unsafe { libc::write(fd, buf.as_ptr() as *const c_void, buf.len()) };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `open(path, flags, mode)` (U-0026): like `open` but with a creation mode
/// (used when O_CREAT is set, e.g. the gz* layer opening files for writing;
/// gzlib.c passes 0666).
pub fn open_mode(path: &CString, flags: c_int, mode: u32) -> Result<c_int, Errno> {
    // SAFETY (U-0026): path is a NUL-terminated CString; flags and mode are
    // caller-chosen constants.  Returns the owned fd (caller must close it).
    let ret = unsafe { libc::open(path.as_ptr(), flags, mode as libc::c_uint) };
    check(ret as c_long).map(|fd| fd as c_int)
}

/// `lseek(fd, offset, whence)` (U-0027): returns the resulting file offset.
/// `offset` is i64 (the libc off_t on 64-bit Linux); whence is SEEK_SET /
/// SEEK_CUR / SEEK_END.
pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> Result<i64, Errno> {
    // SAFETY (U-0027): fd is caller-owned; offset/whence are plain integers.
    let ret = unsafe { libc::lseek(fd, offset, whence) };
    check(ret as c_long)
}

// ---------------------------------------------------------------------------
// The event-loop boundary (compat::libuv, court LIBUV-0001) — U-0029..U-0049
// ---------------------------------------------------------------------------
//
// The libuv conservation is a loop of nonblocking syscalls over a small set
// of kernel objects (eventfd, self-pipe, UDP/TCP sockets).  Every libc call
// is admitted here with the same doctrine as the rest of this module:
// well-formed arguments (valid pointers into live buffers of the declared
// size, caller-owned fds), errno captured immediately, results translated
// into `Result`.

/// `eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK)` (U-0029): the loop's async-wakeup
/// descriptor (libuv 1.52.1 `uv_loop_init`).  Returns the caller-owned fd.
pub fn eventfd() -> Result<c_int, Errno> {
    // SAFETY (U-0029): no pointer arguments; flags are constants.
    let ret = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    check(ret as c_long).map(|fd| fd as c_int)
}

/// `poll(fds, timeout)` (U-0030): the loop's I/O wait.  `fds` is a live
/// slice; the kernel reads the `events` fields and writes the `revents`
/// fields.  Returns the number of fds with nonzero `revents` (0 on timeout).
pub fn poll(fds: &mut [libc::pollfd], timeout: c_int) -> Result<usize, Errno> {
    // SAFETY (U-0030): fds is a live slice of the declared length; the
    // kernel only touches `events`/`revents` within each element.
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `socket(domain, type, protocol)` (U-0031): returns the caller-owned,
/// nonblocking, close-on-exec fd (the flags are caller constants).
pub fn socket(domain: c_int, ty: c_int, proto: c_int) -> Result<c_int, Errno> {
    // SAFETY (U-0031): no pointer arguments; domain/type/protocol are
    // caller-chosen constants.
    let ret = unsafe { libc::socket(domain, ty, proto) };
    check(ret as c_long).map(|fd| fd as c_int)
}

/// `bind(fd, addr)` (U-0032): `addr` is a fully initialized `sockaddr_in`
/// (family, port, address); the kernel reads it synchronously.
pub fn bind(fd: c_int, addr: &libc::sockaddr_in) -> Result<(), Errno> {
    // SAFETY (U-0032): addr is a live, fully initialized ABI struct; fd is
    // caller-owned; the kernel copies the address during the call.
    let ret = unsafe {
        libc::bind(
            fd,
            addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    check(ret as c_long).map(|_| ())
}

/// `getsockname(fd)` (U-0033): returns the kernel-assigned port in host
/// byte order (the loop consumes it internally; the court never prints it).
pub fn getsockname(fd: c_int) -> Result<u16, Errno> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY (U-0033): sa is a valid zeroed out-parameter of the exact ABI
    // type; fd is caller-owned; the kernel writes at most len bytes.
    let ret = unsafe {
        libc::getsockname(
            fd,
            &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        )
    };
    check(ret as c_long)?;
    Ok(u16::from_be(sa.sin_port))
}

/// `getpeername(fd)` (U-0055): the peer port in host byte order; the netmgr
/// accept path (`uv_tcp_getpeername`) reads it for the accepted handle's
/// peer address.  The court only prints the loopback literal + fixed ports.
pub fn getpeername(fd: c_int) -> Result<u16, Errno> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY (U-0055): sa is a valid zeroed out-parameter of the exact ABI
    // type; fd is a live connected socket; the kernel writes at most len
    // bytes.
    let ret = unsafe {
        libc::getpeername(
            fd,
            &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        )
    };
    check(ret as c_long)?;
    Ok(u16::from_be(sa.sin_port))
}

/// `connect(fd, addr)` (U-0034): `addr` is a fully initialized
/// `sockaddr_in`; the UDP disconnect path passes a zeroed struct (family 0 =
/// AF_UNSPEC), exactly like libuv's `uv__udp_disconnect`.
pub fn connect(fd: c_int, addr: &libc::sockaddr_in) -> Result<(), Errno> {
    // SAFETY (U-0034): addr is a live, fully initialized ABI struct; the
    // kernel reads it synchronously; fd is caller-owned.
    let ret = unsafe {
        libc::connect(
            fd,
            addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    check(ret as c_long).map(|_| ())
}

/// `sendmsg(fd, bufs, addr)` (U-0035): one datagram per call; the iovec
/// covers all `bufs` (a scatter send is a single datagram, matching libuv's
/// `uv__udp_sendmsg1`).  Returns the byte count sent.
pub fn sendmsg(
    fd: c_int,
    bufs: &[&[u8]],
    addr: Option<&libc::sockaddr_in>,
) -> Result<usize, Errno> {
    let mut iov: Vec<libc::iovec> = bufs
        .iter()
        .map(|b| libc::iovec {
            iov_base: b.as_ptr() as *mut c_void,
            iov_len: b.len(),
        })
        .collect();
    let mut sa = match addr {
        Some(a) => *a,
        None => unsafe { std::mem::zeroed() },
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    if addr.is_some() {
        hdr.msg_name = &mut sa as *mut libc::sockaddr_in as *mut c_void;
        hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    }
    hdr.msg_iov = iov.as_mut_ptr();
    hdr.msg_iovlen = iov.len() as _;
    // SAFETY (U-0035): bufs are live slices whose pointers/lengths are
    // copied into the iovec; the kernel reads them synchronously; sa (when
    // used) is a fully initialized copy.
    let ret = unsafe { libc::sendmsg(fd, &hdr, 0) };
    match check(ret as c_long) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// `recvmsg(fd, buf)` (U-0036): receives one datagram into `buf`;
/// returns `(nread, peer_port)`.  `nread == 0` is the EAGAIN drain marker
/// (the peer port is meaningless then).
pub fn recvmsg(fd: c_int, buf: &mut [u8]) -> Result<(usize, u16), Errno> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = &mut sa as *mut libc::sockaddr_in as *mut c_void;
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    // SAFETY (U-0036): buf is a live slice bounded by buf.len(); sa is a
    // valid out-parameter of the exact ABI type; the kernel fills both.
    let ret = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
    match check(ret as c_long) {
        Ok(n) => Ok((n as usize, u16::from_be(sa.sin_port))),
        Err(e) => Err(e),
    }
}

/// `listen(fd, backlog)` (U-0037): fd is a caller-owned bound socket.
pub fn listen(fd: c_int, backlog: c_int) -> Result<(), Errno> {
    // SAFETY (U-0037): plain integer arguments; fd is caller-owned.
    let ret = unsafe { libc::listen(fd, backlog) };
    check(ret as c_long).map(|_| ())
}

/// `accept(fd)` (U-0038): returns the accepted fd (still blocking until
/// the caller sets O_NONBLOCK, exactly like libuv's uv__accept).
pub fn accept(fd: c_int) -> Result<c_int, Errno> {
    // SAFETY (U-0038): fd is caller-owned; no out-parameters.
    let ret = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    check(ret as c_long).map(|fd| fd as c_int)
}

/// `fcntl(fd, F_SETFL, O_NONBLOCK)` (U-0039): the accepted-socket and
/// signal-pipe nonblocking mode (uv__nonblock).
pub fn set_nonblock(fd: c_int) -> Result<(), Errno> {
    // SAFETY (U-0039): fd is caller-owned; the mode is a constant.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    check(ret as c_long).map(|_| ())
}

/// `shutdown(fd, how)` (U-0040): `how` is SHUT_RD/SHUT_WR/SHUT_RDWR.
pub fn shutdown(fd: c_int, how: c_int) -> Result<(), Errno> {
    // SAFETY (U-0040): fd is caller-owned; how is a constant.
    let ret = unsafe { libc::shutdown(fd, how) };
    check(ret as c_long).map(|_| ())
}

/// `setsockopt(fd, SOL_SOCKET, SO_LINGER, {1,0})` (U-0041): the
/// close-with-RST path (uv_tcp_close_reset).
pub fn setsockopt_linger(fd: c_int, l: &libc::linger) -> Result<(), Errno> {
    // SAFETY (U-0041): l is a live, fully initialized ABI struct; fd is
    // caller-owned; the kernel copies it synchronously.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            l as *const libc::linger as *const c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    check(ret as c_long).map(|_| ())
}

/// `uv__socket_sockopt` (U-0042): `*value == 0` -> getsockopt (the kernel
/// writes the value); otherwise setsockopt with `*value`.  Used for
/// SO_SNDBUF/SO_RCVBUF and the connect-completion SO_ERROR query.
pub fn socket_sockopt(fd: c_int, optname: c_int, value: &mut i32) -> Result<(), Errno> {
    // SAFETY (U-0042): fd is caller-owned; value is a live i32; the kernel
    // reads or writes exactly one int through it.
    let ret = if *value == 0 {
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                value as *mut i32 as *mut c_void,
                &mut len,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                value as *const i32 as *const c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        }
    };
    check(ret as c_long).map(|_| ())
}

/// `sigaction(signum, SA_RESTART handler)` (U-0043): installs the
/// event-loop signal handler over an empty mask; the handler must be an
/// async-signal-safe `extern "C" fn(i32)`.  Returns the previous disposition
/// via the standard libc convention.
pub fn sigaction_install(signum: i32, handler: extern "C" fn(i32)) -> Result<(), Errno> {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY (U-0043): sa is a fully zeroed ABI struct, filled below;
    // sigemptyset initializes the mask; the handler is a plain function
    // pointer with the exact `sighandler_t` ABI.
    sa.sa_sigaction = handler as usize;
    sa.sa_flags = libc::SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
    }
    // SAFETY (U-0043): sa is fully initialized; the old action out-param is
    // NULL (not needed); signum is a valid signal number.
    let ret = unsafe { libc::sigaction(signum, &sa, std::ptr::null_mut()) };
    check(ret as c_long).map(|_| ())
}

/// `clock_gettime(CLOCK_MONOTONIC)` (U-0044): the loop clock in
/// milliseconds (libuv's uv__hrtime / 1e6).
pub fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY (U-0044): ts is a valid out-parameter of the exact ABI type;
    // clock_gettime cannot fail for CLOCK_MONOTONIC.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// `getrandom(0)` (U-0045): fills `buf` from the kernel CSPRNG; returns the
/// bytes written (a partial fill is not an error and must be re-issued).
pub fn getrandom(buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY (U-0045): buf is a live slice bounded by buf.len(); the kernel
    // writes at most that many bytes.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
        )
    };
    match check(ret) {
        Ok(n) => Ok(n as usize),
        Err(e) => Err(e),
    }
}

/// An opaque dlopen'd library handle (U-0046).  The raw pointer never
/// crosses back into safe code; every operation on it lives in this module.
pub struct DlHandle {
    handle: *mut c_void,
}

/// `dlopen(path, RTLD_LAZY)` (U-0046): on failure returns -1 with the exact
/// glibc `dlerror` text (libuv's `uv__dlerror` contract).
pub fn dlopen(path: &str) -> Result<DlHandle, (c_int, String)> {
    // SAFETY (U-0046): dlerror() has no preconditions; it resets the error
    // state so the message below belongs to dlopen.
    unsafe {
        libc::dlerror();
    }
    let cpath = CString::new(path).unwrap_or_default();
    // SAFETY (U-0046): cpath is a NUL-terminated owned CString; dlopen
    // copies it synchronously; the returned handle is stored opaque.
    let h = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_LAZY) };
    if h.is_null() {
        Err((-1, dl_error_string()))
    } else {
        Ok(DlHandle { handle: h })
    }
}

/// `dlsym(handle, name)` (U-0047): returns whether the symbol resolves;
/// on failure returns -1 with the exact glibc `dlerror` text.  The symbol
/// value itself is never dereferenced by the conservation.
pub fn dlsym(handle: &DlHandle, name: &str) -> Result<(), (c_int, String)> {
    // SAFETY (U-0047): dlerror() resets the error state so the message
    // below belongs to dlsym.
    unsafe {
        libc::dlerror();
    }
    let csym = CString::new(name).unwrap_or_default();
    // SAFETY (U-0047): csym is a NUL-terminated owned CString; handle is a
    // live library handle; the returned symbol pointer is only NULL-tested.
    let p = unsafe { libc::dlsym(handle.handle, csym.as_ptr()) };
    if p.is_null() {
        Err((-1, dl_error_string()))
    } else {
        Ok(())
    }
}

/// `dlclose(handle)` (U-0048): ignores the result (libuv's contract).
pub fn dlclose(handle: DlHandle) {
    if !handle.handle.is_null() {
        // SAFETY (U-0048): handle is a live library handle; dlclose is the
        // matching destructor; the result is ignored per libuv.
        unsafe {
            libc::dlclose(handle.handle);
        }
    }
}

/// `raise(signum)` (U-0050): the probe's signal-raise op; the handler is
/// installed by `sigaction_install` on the same thread.
pub fn raise(signum: i32) -> Result<(), Errno> {
    // SAFETY (U-0050): plain integer argument; raises the signal on the
    // calling thread, which runs the installed handler synchronously.
    let ret = unsafe { libc::raise(signum) };
    check(ret as c_long).map(|_| ())
}

/// `calloc(n, size)` (U-0052): the allocator fallback when no custom
/// allocator is installed (libuv's default `uv__allocator`).
pub fn alloc_calloc(n: usize, size: usize) -> *mut c_void {
    // SAFETY (U-0052): plain size arguments; returns an owned, zeroed block
    // that the caller frees through `alloc_free`.
    unsafe { libc::calloc(n, size) }
}

/// `realloc(ptr, size)` (U-0053): the allocator fallback; `ptr` may be
/// NULL (malloc semantics), exactly like libuv's default realloc.
pub fn alloc_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY (U-0053): p is either NULL or a block previously returned by
    // the allocator; the result is owned by the caller.
    unsafe { libc::realloc(p, size) }
}

/// `free(ptr)` (U-0054): the allocator fallback; NULL is a no-op.
pub fn alloc_free(p: *mut c_void) {
    // SAFETY (U-0054): p is NULL or a block previously returned by the
    // allocator, not used afterwards.
    unsafe { libc::free(p) }
}

/// `write(fd, one byte)` (U-0051): the async-signal-safe pipe write used by
/// the event-loop signal handler.  Deliberately does NOT read errno or touch
/// any std machinery (the handler may interrupt any thread).
pub fn signal_write(fd: i32, byte: u8) {
    // SAFETY (U-0051): fd is a caller-owned nonblocking pipe write end; the
    // single byte is copied synchronously; the result is ignored because
    // errno must not be read inside a signal handler.
    unsafe {
        libc::write(fd, &byte as *const u8 as *const c_void, 1);
    }
}

/// Reads and clears the glibc `dlerror` text (U-0049): the last dl error as
/// an owned String, or empty when the state was clean.
pub fn dl_error_string() -> String {
    // SAFETY (U-0049): dlerror() returns a pointer to glibc-owned memory
    // valid until the next dlerror call; copied out immediately.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }
}

use std::ffi::c_char;
