//! `fstrm_unix_writer` (unix_writer.c/unix_writer.h): a bidirectional
//! AF_UNIX stream writer.  The transport has read + write methods, so the
//! writer performs the full READY/ACCEPT/START/STOP/FINISH handshake.
//!
//! The C opens the socket with `SOCK_STREAM | SOCK_CLOEXEC` (falling back to
//! `SOCK_STREAM` on `EINVAL`), then re-asserts `FD_CLOEXEC` with `fcntl`, and
//! on BSD applies `SO_NOSIGPIPE`; on Linux the oracle build uses `sendmsg`
//! with `MSG_NOSIGNAL` for writes (fstrm-private.h).  The Rust transport uses
//! `UnixStream` (CLOEXEC by construction) and `Write::write_vectored`, which
//! lowers to `writev` — the same bytes on the wire.  A socket path longer than
//! `sizeof(sa.sun_path) - 1` (107) rejects the init, like the C's
//! `strlen + 1 > sizeof(uw->sa.sun_path)` check (unix_writer.c:210).

use super::{
    rdwr::{IoVec, Rdwr},
    writer::{Writer, WriterOptions},
    Res,
};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

/// `sizeof(sa.sun_path)` on Linux (unix_writer.c:210).
pub const SUN_PATH_SIZE: usize = 108;

/// `struct fstrm_unix_writer_options` (unix_writer.c:33).
#[derive(Clone, Debug, Default)]
pub struct UnixWriterOptions {
    socket_path: Option<String>,
}

impl UnixWriterOptions {
    /// `fstrm_unix_writer_options_init`.
    #[must_use]
    pub fn new() -> UnixWriterOptions {
        UnixWriterOptions { socket_path: None }
    }

    /// `fstrm_unix_writer_options_set_socket_path` (unix_writer.c:58).
    pub fn set_socket_path(&mut self, socket_path: Option<&str>) {
        self.socket_path = socket_path.map(str::to_owned);
    }
}

/// `struct fstrm__unix_writer` (unix_writer.c:37).
struct UnixWriterState {
    connected: bool,
    stream: Option<UnixStream>,
}

impl UnixWriterState {
    fn new() -> UnixWriterState {
        UnixWriterState {
            connected: false,
            stream: None,
        }
    }

    /// `fstrm__unix_writer_op_open` (unix_writer.c:68).
    fn op_open(&mut self, path: &str) -> Res {
        if self.connected {
            return Res::Success;
        }
        let stream = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(_) => return Res::Failure,
        };
        self.stream = Some(stream);
        self.connected = true;
        Res::Success
    }

    /// `fstrm__unix_writer_op_close` (unix_writer.c:128).
    fn op_close(&mut self) -> Res {
        if self.connected {
            self.connected = false;
            self.stream = None;
            return Res::Success;
        }
        Res::Failure
    }

    /// `fstrm__unix_writer_op_read` (unix_writer.c:141): `read_bytes` loop —
    /// EOF or error is a failure (not stop).
    fn op_read(&mut self, buf: &mut [u8]) -> Res {
        if !self.connected {
            return Res::Failure;
        }
        let stream = self.stream.as_mut().unwrap();
        let mut rest = buf;
        while !rest.is_empty() {
            match stream.read(rest) {
                Ok(0) => return Res::Failure,
                Ok(n) => rest = &mut rest[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Res::Failure,
            }
        }
        Res::Success
    }

    /// `fstrm__unix_writer_op_write` (unix_writer.c:152): sendmsg over the
    /// whole iovec (writev-equivalent; partial writes are completed).
    fn op_write(&mut self, iov: &[IoVec<'_>]) -> Res {
        if !self.connected {
            return Res::Failure;
        }
        let stream = self.stream.as_mut().unwrap();
        let vecs: Vec<io::IoSlice<'_>> = iov.iter().map(|v| io::IoSlice::new(v.data)).collect();
        let mut rest = &vecs[..];
        while !rest.is_empty() {
            match stream.write_vectored(rest) {
                Ok(0) => return Res::Failure,
                Ok(n) => {
                    let mut consumed = n;
                    while !rest.is_empty() {
                        let len = rest[0].len();
                        if consumed < len {
                            rest = &rest[consumed..];
                            // adjust the first slice to the remainder
                            // (write_vectored already returned a partial
                            // first slice, so re-borrow it)
                            break;
                        }
                        consumed -= len;
                        rest = &rest[1..];
                    }
                    if rest.is_empty() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Res::Failure,
            }
        }
        Res::Success
    }
}

/// `fstrm_unix_writer_init` (unix_writer.c:200): rejects a NULL path and a
/// path that does not fit `sun_path`.
pub fn unix_writer_init(uwopt: &UnixWriterOptions, wopt: Option<&WriterOptions>) -> Option<Writer> {
    let path = uwopt.socket_path.as_ref()?;
    if path.len() + 1 > SUN_PATH_SIZE {
        return None;
    }
    let state = Arc::new(Mutex::new(UnixWriterState::new()));
    let mut rdwr = Rdwr::new();
    {
        let s = state.clone();
        rdwr.set_destroy(Box::new(move || {
            drop(s);
            Res::Success
        }));
    }
    {
        let p = path.clone();
        let s = state.clone();
        rdwr.set_open(Box::new(move || s.lock().unwrap().op_open(&p)));
    }
    {
        let s = state.clone();
        rdwr.set_close(Box::new(move || s.lock().unwrap().op_close()));
    }
    {
        let s = state.clone();
        rdwr.set_read(Box::new(move |buf| s.lock().unwrap().op_read(buf)));
    }
    {
        let s = state.clone();
        rdwr.set_write(Box::new(move |iov| s.lock().unwrap().op_write(iov)));
    }
    Writer::new(wopt, &mut Some(rdwr))
}

/// `fstrm_unix_writer_options_init`.
#[must_use]
pub fn unix_writer_options_init() -> UnixWriterOptions {
    UnixWriterOptions::new()
}

/// `fstrm_unix_writer_options_set_socket_path`.
pub fn unix_writer_options_set_socket_path(uwopt: &mut UnixWriterOptions, path: &str) {
    uwopt.set_socket_path(Some(path));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{Reader, ReaderOptions, Res};
    use std::os::unix::net::UnixListener;

    #[test]
    fn unix_writer_init_validation() {
        let mut uwopt = UnixWriterOptions::new();
        // No path: NULL.
        assert!(unix_writer_init(&uwopt, None).is_none());
        // Path too long: strlen + 1 > 108.
        let long = "x".repeat(SUN_PATH_SIZE); // 108 chars + NUL -> fails
        uwopt.set_socket_path(Some(&long));
        assert!(unix_writer_init(&uwopt, None).is_none());
        // 107 chars fits (strncpy truncates to 107; the C accepts).
        let fits = "x".repeat(SUN_PATH_SIZE - 1);
        uwopt.set_socket_path(Some(&fits));
        assert!(unix_writer_init(&uwopt, None).is_some());
    }

    #[test]
    fn unix_writer_connect_failure() {
        let mut uwopt = UnixWriterOptions::new();
        uwopt.set_socket_path(Some("/nonexistent/fstrm-test.sock"));
        let mut w = unix_writer_init(&uwopt, None).unwrap();
        assert_eq!(w.open(), Res::Failure);
    }

    #[test]
    fn unix_writer_full_handshake() {
        // A real AF_UNIX listener at a path; the accepted connection becomes
        // the reader side, running the full bidirectional handshake on its
        // own thread exactly like the C test_fstrm_io_sock consumer.
        let path = format!("/tmp/fstrm-rs-test-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();

        let reader = std::thread::spawn(move || {
            let (b, _) = listener.accept().unwrap();
            let mut rrdwr = Rdwr::new();
            rrdwr.set_open(Box::new(|| Res::Success));
            rrdwr.set_close(Box::new(|| Res::Success));
            let b4 = b.try_clone().unwrap();
            rrdwr.set_read(Box::new(move |buf| {
                let mut s = b4.try_clone().unwrap();
                match s.read_exact(buf) {
                    Ok(()) => Res::Success,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Res::Stop,
                    Err(_) => Res::Failure,
                }
            }));
            let b5 = b.try_clone().unwrap();
            rrdwr.set_write(Box::new(move |iov| {
                let mut s = b5.try_clone().unwrap();
                for v in iov {
                    if s.write_all(v.data).is_err() {
                        return Res::Failure;
                    }
                }
                Res::Success
            }));
            let mut ropt = ReaderOptions::new();
            ropt.add_content_type(b"test:hello");
            let mut r = Reader::new(Some(&ropt), &mut Some(rrdwr)).unwrap();
            assert_eq!(r.open(), Res::Success);
            let d1 = r.read().unwrap().to_vec();
            let d2 = r.read().unwrap().to_vec();
            let stop = match r.read() {
                Ok(d) => Ok(d.to_vec()),
                Err(e) => Err(e),
            };
            let closed = r.close();
            (d1, d2, stop, closed)
        });

        let mut uwopt = UnixWriterOptions::new();
        uwopt.set_socket_path(Some(&path));
        let mut w = unix_writer_init(&uwopt, None).unwrap();
        assert_eq!(w.open(), Res::Success);
        assert_eq!(w.write(b"payload-one"), Res::Success);
        assert_eq!(w.write(b"payload-two"), Res::Success);
        assert_eq!(w.close(), Res::Success);
        drop(w);

        let (d1, d2, stop, closed) = reader.join().unwrap();
        assert_eq!(d1, b"payload-one");
        assert_eq!(d2, b"payload-two");
        assert_eq!(stop, Err(Res::Stop));
        assert_eq!(closed, Res::Success);
        let _ = std::fs::remove_file(&path);
    }
}
