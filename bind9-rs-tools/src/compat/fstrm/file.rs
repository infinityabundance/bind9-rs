//! `fstrm_file` transports (file.c/file.h): reader and writer over a regular
//! file.  `file_path == "-"` maps to stdin (reader) / stdout (writer), exactly
//! like the C (`f->fp = f->file_mode[0] == 'r' ? stdin : stdout`).  The read
//! op mirrors `fread(data, count, 1, fp) == 1` (a partial read at EOF is
//! `fstrm_res_stop`); the write op mirrors `fwrite` per iovec, closing the
//! file on a failed write (file.c `fstrm__file_op_write`).

use super::{
    rdwr::{IoVec, Rdwr},
    reader::{Reader, ReaderOptions},
    writer::{Writer, WriterOptions},
    Res,
};
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// `struct fstrm_file_options` (file.c:27).
#[derive(Clone, Debug, Default)]
pub struct FileOptions {
    file_path: Option<String>,
}

impl FileOptions {
    /// `fstrm_file_options_init`.
    #[must_use]
    pub fn new() -> FileOptions {
        FileOptions { file_path: None }
    }

    /// `fstrm_file_options_set_file_path` (file.c:52): passing `None` clears
    /// the path, like the C's NULL.
    pub fn set_file_path(&mut self, file_path: Option<&str>) {
        self.file_path = file_path.map(str::to_owned);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileMode {
    Read,
    Write,
}

/// The opened stream: the C's `FILE *fp` (file.c `struct fstrm__file`).
enum FileIo {
    Stdin,
    Stdout,
    File(File),
}

/// `struct fstrm__file` (file.c:31): the transport state, shared with the
/// rdwr op closures (they run on one thread at a time, but the iothr moves
/// the writer across threads, so the state is `Arc<Mutex<..>>`).
struct FileTransport {
    file_path: String,
    mode: FileMode,
    fp: Option<FileIo>,
}

impl FileTransport {
    fn new(file_path: String, mode: FileMode) -> FileTransport {
        FileTransport {
            file_path,
            mode,
            fp: None,
        }
    }

    /// `fstrm__file_op_open` (file.c:61): only opens when not already open and
    /// a path is set; `"-"` selects stdio.
    fn op_open(&mut self) -> Res {
        if self.fp.is_none() && !self.file_path.is_empty() {
            self.fp = if self.file_path == "-" {
                match self.mode {
                    FileMode::Read => Some(FileIo::Stdin),
                    FileMode::Write => Some(FileIo::Stdout),
                }
            } else {
                let f = match self.mode {
                    FileMode::Read => File::open(&self.file_path),
                    FileMode::Write => File::create(&self.file_path),
                };
                match f {
                    Ok(f) => Some(FileIo::File(f)),
                    Err(_) => return Res::Failure,
                }
            };
            return Res::Success;
        }
        Res::Failure
    }

    /// `fstrm__file_op_close` (file.c:77).
    fn op_close(&mut self) -> Res {
        if self.fp.take().is_some() {
            return Res::Success;
        }
        Res::Failure
    }

    /// `fstrm__file_op_read` (file.c:91): `fread(data, count, 1, fp) == 1`
    /// semantics — a partial read at EOF is stop, a real error is failure.
    fn op_read(&mut self, buf: &mut [u8]) -> Res {
        match self.fp.as_mut() {
            Some(FileIo::Stdin) => {
                let mut stdin = io::stdin();
                match stdin.read_exact(buf) {
                    Ok(()) => Res::Success,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Res::Stop,
                    Err(_) => Res::Failure,
                }
            }
            Some(FileIo::File(f)) => match f.read_exact(buf) {
                Ok(()) => Res::Success,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Res::Stop,
                Err(_) => Res::Failure,
            },
            _ => Res::Failure,
        }
    }

    /// `fstrm__file_op_write` (file.c:108): `fwrite` per iovec; a failed
    /// write closes the file and fails.
    fn op_write(&mut self, iov: &[IoVec<'_>]) -> Res {
        match self.fp.as_mut() {
            Some(FileIo::Stdout) => {
                let mut stdout = io::stdout();
                for v in iov {
                    if stdout.write_all(v.data).is_err() {
                        self.fp = None;
                        return Res::Failure;
                    }
                }
                Res::Success
            }
            Some(FileIo::File(f)) => {
                for v in iov {
                    if f.write_all(v.data).is_err() {
                        self.fp = None;
                        return Res::Failure;
                    }
                }
                Res::Success
            }
            _ => Res::Failure,
        }
    }
}

/// `fstrm__file_init` (file.c:131): build the rdwr for one file mode; fails
/// without a path.
fn file_init(fopt: &FileOptions, mode: FileMode) -> Option<Rdwr> {
    let path = fopt.file_path.clone()?;
    let state = Arc::new(Mutex::new(FileTransport::new(path, mode)));

    let mut rdwr = Rdwr::new();
    {
        let s = state.clone();
        rdwr.set_destroy(Box::new(move || {
            drop(s);
            Res::Success
        }));
    }
    {
        let s = state.clone();
        rdwr.set_open(Box::new(move || s.lock().unwrap().op_open()));
    }
    {
        let s = state.clone();
        rdwr.set_close(Box::new(move || s.lock().unwrap().op_close()));
    }
    if mode == FileMode::Read {
        let s = state.clone();
        rdwr.set_read(Box::new(move |buf| s.lock().unwrap().op_read(buf)));
    } else {
        let s = state.clone();
        rdwr.set_write(Box::new(move |iov| s.lock().unwrap().op_write(iov)));
    }
    Some(rdwr)
}

/// `fstrm_file_reader_init` (file.c:152): the rdwr gets a read method only,
/// so the reader treats it as a unidirectional stream.
pub fn file_reader_init(fopt: &FileOptions, ropt: Option<&ReaderOptions>) -> Option<Reader> {
    let rdwr = file_init(fopt, FileMode::Read)?;
    Reader::new(ropt, &mut Some(rdwr))
}

/// `fstrm_file_writer_init` (file.c:163): the rdwr gets a write method only,
/// so the writer treats it as a unidirectional stream.
pub fn file_writer_init(fopt: &FileOptions, wopt: Option<&WriterOptions>) -> Option<Writer> {
    let rdwr = file_init(fopt, FileMode::Write)?;
    Writer::new(wopt, &mut Some(rdwr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{ControlFrame, ControlType as CT, Frame, FrameReader, Res};
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fstrm-rs-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn file_writer_reader_round_trip() {
        let path = tmp_path("file-round-trip.fs");
        let p = path.to_str().unwrap().to_owned();

        let mut fopt = FileOptions::new();
        // No path: init fails.
        assert!(file_writer_init(&fopt, None).is_none());
        fopt.set_file_path(Some(&p));

        let mut wopt = WriterOptions::new();
        assert_eq!(wopt.add_content_type(b"test:hello"), Res::Success);
        let mut w = file_writer_init(&fopt, Some(&wopt)).unwrap();
        assert_eq!(w.open(), Res::Success);
        // Double open is a success for writers.
        assert_eq!(w.open(), Res::Success);
        assert_eq!(w.write(b"one"), Res::Success);
        assert_eq!(w.write(b"two"), Res::Success);
        assert_eq!(w.close(), Res::Success);
        drop(w);

        let mut ropt = ReaderOptions::new();
        ropt.add_content_type(b"test:hello");
        let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
        assert_eq!(r.open(), Res::Success);
        assert_eq!(r.read(), Ok(&b"one"[..]));
        assert_eq!(r.read(), Ok(&b"two"[..]));
        assert_eq!(r.read(), Err(Res::Stop));
        assert_eq!(r.close(), Res::Success);
        drop(r);

        // The file is byte-exact: START(test:hello) + (4|one) + (4|two) + STOP.
        let bytes = std::fs::read(&p).unwrap();
        let mut fr = FrameReader::new(&bytes[..]);
        match fr.next().unwrap().unwrap() {
            Frame::Control(c) => {
                assert_eq!(c.control_type, CT::Start);
                assert_eq!(c.content_types, vec![b"test:hello".to_vec()]);
            }
            _ => panic!("expected START"),
        }
        assert_eq!(fr.next().unwrap().unwrap(), Frame::Data(b"one".to_vec()));
        assert_eq!(fr.next().unwrap().unwrap(), Frame::Data(b"two".to_vec()));
        match fr.next().unwrap().unwrap() {
            Frame::Control(c) => assert_eq!(c.control_type, CT::Stop),
            _ => panic!("expected STOP"),
        }
        assert_eq!(fr.next().unwrap(), None);

        let _ = std::fs::remove_file(&p);
        let _ = ControlFrame::new;
    }

    #[test]
    fn file_open_failure_and_close() {
        // Opening a nonexistent path for reading fails at open.
        let mut fopt = FileOptions::new();
        fopt.set_file_path(Some("/nonexistent/definitely-not-here.fs"));
        let mut r = file_reader_init(&fopt, None).unwrap();
        assert_eq!(r.open(), Res::Failure);
        assert_eq!(r.close(), Res::Failure);
    }

    #[test]
    fn file_set_path_none_clears() {
        let mut fopt = FileOptions::new();
        fopt.set_file_path(Some("/tmp/x.fs"));
        fopt.set_file_path(None);
        assert!(file_writer_init(&fopt, None).is_none());
    }
}
