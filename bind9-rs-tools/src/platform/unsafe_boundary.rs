//! The audited unsafe boundary (addendum §49) and the unsafe inventory.
//!
//! Every `unsafe` block in this crate lives in `platform::linux` (the sole
//! allowed module) and is registered below.  Policy: unsafe is admitted only
//! for genuinely unavoidable OS/ABI operations, each with an explicit
//! invariant, scope justification, tests, Miri/sanitizer/fuzz coverage where
//! meaningful, and this inventory entry.  Protocol and business logic are
//! always safe Rust (`#![deny(unsafe_code)]` at the crate root makes unsafe a
//! compile error anywhere outside the allowed modules).
//!
//! | ID    | Call site            | Invariant (summary)                                | Tests                    |
//! |-------|----------------------|----------------------------------------------------|--------------------------|
//! | U-0001| linux.rs `check`    | libc -1 failure convention; errno read immediately | libcap proc tests        |
//! | U-0002| linux.rs `prctl`    | caller-supplied ints; kernel copies synchronously  | libcap bound/ambient     |
//! | U-0003| linux.rs `capget`   | valid ABI structs; kernel fills exactly 6 u32s     | libcap get_proc/get_pid  |
//! | U-0004| linux.rs `capset`   | fully initialized ABI structs; kernel reads only   | libcap set_proc          |
//! | U-0005| linux.rs `getxattr` | live slice bounded by len; NUL-terminated names    | libcap file courts       |
//! | U-0006| linux.rs `setxattr` | live slice; kernel reads exactly len bytes         | libcap file courts       |
//! | U-0007| linux.rs `removexattr` | NUL-terminated CStrings                          | libcap file courts       |
//! | U-0008| linux.rs `fgetxattr`| fd caller-owned; slice bounded                     | libcap file courts       |
//! | U-0009| linux.rs `fsetxattr`| fd caller-owned; live slice                        | libcap file courts       |
//! | U-0010| linux.rs `fremovexattr` | fd caller-owned                                | libcap file courts       |
//! | U-0011| linux.rs `open`     | NUL-terminated path; flags from constants          | libcap file courts       |
//! | U-0012| linux.rs `fstat`    | zeroed ABI struct out-parameter                    | libcap file courts       |
//! | U-0013| linux.rs `close`    | caller-owned fd; not used afterwards               | libcap file courts       |
//! | U-0014| linux.rs get*id     | no preconditions; cannot fail                      | libcap setuid tests      |
//! | U-0015| linux.rs `setuid`   | plain integer argument                             | libcap setuid tests      |
//! | U-0016| linux.rs `setgid`   | plain integer argument                             | libcap setuid tests      |
//! | U-0017| linux.rs `setgroups`| live slice; kernel reads len gids                  | libcap setuid tests      |
//! | U-0018| linux.rs `pipe2`    | valid 2-element out-array                          | libcap launcher tests    |
//! | U-0019| linux.rs `fork`     | no arguments; pid handled by sole caller           | libcap launcher tests    |
//! | U-0020| linux.rs `execve`   | NUL-terminated CString arrays; kernel copies       | libcap launcher tests    |
//! | U-0021| linux.rs `waitpid`  | valid status out-parameter                         | libcap launcher tests    |
//! | U-0022| linux.rs `chroot`   | NUL-terminated CString                             | libcap launcher tests    |
//! | U-0023| linux.rs `chdir_root` | NUL-terminated literal                           | libcap launcher tests    |
//! | U-0024| linux.rs `read_fd`  | fd caller-owned; buf live slice bounded by len      | libcap launcher tests    |
//! | U-0025| linux.rs `write_fd` | fd caller-owned; buf live slice of declared length   | libcap launcher tests    |
//!
//! Miri cannot execute the kernel calls themselves (they are FFI); the
//! surrounding pointer/buffer construction is exercised by the unit and
//! court tests.  The linux-raw syscall layer (rustix/libc) is pinned by
//! Cargo.lock and audited at release CI (§62, §63).

pub mod inventory {
    /// The inventory table above, machine-readable for the release unsafe
    /// audit (§63 release tier).
    pub const ENTRIES: &[(&str, &str, &str)] = &[
        (
            "U-0001",
            "linux.rs check",
            "libc -1 failure convention; errno read immediately",
        ),
        (
            "U-0002",
            "linux.rs prctl",
            "caller-supplied ints; kernel copies synchronously",
        ),
        (
            "U-0003",
            "linux.rs capget",
            "valid ABI structs; kernel fills exactly 6 u32s",
        ),
        (
            "U-0004",
            "linux.rs capset",
            "fully initialized ABI structs; kernel reads only",
        ),
        (
            "U-0005",
            "linux.rs getxattr",
            "live slice bounded by len; NUL-terminated names",
        ),
        (
            "U-0006",
            "linux.rs setxattr",
            "live slice; kernel reads exactly len bytes",
        ),
        ("U-0007", "linux.rs removexattr", "NUL-terminated CStrings"),
        (
            "U-0008",
            "linux.rs fgetxattr",
            "fd caller-owned; slice bounded",
        ),
        (
            "U-0009",
            "linux.rs fsetxattr",
            "fd caller-owned; live slice",
        ),
        ("U-0010", "linux.rs fremovexattr", "fd caller-owned"),
        (
            "U-0011",
            "linux.rs open",
            "NUL-terminated path; flags from constants",
        ),
        (
            "U-0012",
            "linux.rs fstat",
            "zeroed ABI struct out-parameter",
        ),
        (
            "U-0013",
            "linux.rs close",
            "caller-owned fd; not used afterwards",
        ),
        ("U-0014", "linux.rs get*id", "no preconditions; cannot fail"),
        ("U-0015", "linux.rs setuid", "plain integer argument"),
        ("U-0016", "linux.rs setgid", "plain integer argument"),
        (
            "U-0017",
            "linux.rs setgroups",
            "live slice; kernel reads len gids",
        ),
        ("U-0018", "linux.rs pipe2", "valid 2-element out-array"),
        (
            "U-0019",
            "linux.rs fork",
            "no arguments; pid handled by sole caller",
        ),
        (
            "U-0020",
            "linux.rs execve",
            "NUL-terminated CString arrays; kernel copies",
        ),
        ("U-0021", "linux.rs waitpid", "valid status out-parameter"),
        ("U-0022", "linux.rs chroot", "NUL-terminated CString"),
        ("U-0023", "linux.rs chdir_root", "NUL-terminated literal"),
        (
            "U-0024",
            "linux.rs read_fd",
            "fd caller-owned; buf live slice bounded by len",
        ),
        (
            "U-0025",
            "linux.rs write_fd",
            "fd caller-owned; buf live slice of declared length",
        ),
    ];
}
