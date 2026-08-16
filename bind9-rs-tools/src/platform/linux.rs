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

use std::ffi::c_char;
