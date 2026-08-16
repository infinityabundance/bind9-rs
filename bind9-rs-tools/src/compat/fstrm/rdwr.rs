//! `fstrm_rdwr` abstraction (rdwr.c/rdwr.h): a byte-stream with destroy/open/
//! close/read/write methods, plus the `fstrm__rdwr_*` control-frame helpers
//! used by the writer and reader state machines.
//!
//! The C dispatches through function pointers with an opaque `obj`; here the
//! ops are boxed closures capturing the transport state, so the observable
//! contract is identical: `open` fails if no open method is set, `close` is a
//! no-op when not opened, and a failing `read`/`write` implicitly closes the
//! stream (rdwr.c `fstrm_rdwr_read`/`fstrm_rdwr_write`).

use super::{Control, ControlType, Res, CONTROL_FLAG_WITH_HEADER, CONTROL_FRAME_LENGTH_MAX};

/// One scatter/gather element, mirroring `struct iovec` (data + length).
#[derive(Clone, Copy, Debug)]
pub struct IoVec<'a> {
    pub data: &'a [u8],
}

impl<'a> IoVec<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> IoVec<'a> {
        IoVec { data }
    }
}

/// A `fstrm_rdwr` object.  Ops are set with the `set_*` methods after
/// [`Rdwr::new`], exactly like the C's `fstrm_rdwr_init` + `fstrm_rdwr_set_*`
/// sequence.
pub struct Rdwr {
    opened: bool,
    destroy: Option<Box<dyn FnOnce() -> Res + Send>>,
    open: Option<Box<dyn FnMut() -> Res + Send>>,
    close: Option<Box<dyn FnMut() -> Res + Send>>,
    read: Option<Box<dyn FnMut(&mut [u8]) -> Res + Send>>,
    write: Option<Box<dyn for<'a> FnMut(&[IoVec<'a>]) -> Res + Send>>,
}

impl Rdwr {
    /// `fstrm_rdwr_init`: an rdwr with no ops set.
    #[must_use]
    pub fn new() -> Rdwr {
        Rdwr {
            opened: false,
            destroy: None,
            open: None,
            close: None,
            read: None,
            write: None,
        }
    }

    /// `fstrm_rdwr_set_destroy`.
    pub fn set_destroy(&mut self, f: Box<dyn FnOnce() -> Res + Send>) {
        self.destroy = Some(f);
    }

    /// `fstrm_rdwr_set_open`.
    pub fn set_open(&mut self, f: Box<dyn FnMut() -> Res + Send>) {
        self.open = Some(f);
    }

    /// `fstrm_rdwr_set_close`.
    pub fn set_close(&mut self, f: Box<dyn FnMut() -> Res + Send>) {
        self.close = Some(f);
    }

    /// `fstrm_rdwr_set_read`.
    pub fn set_read(&mut self, f: Box<dyn FnMut(&mut [u8]) -> Res + Send>) {
        self.read = Some(f);
    }

    /// `fstrm_rdwr_set_write`.
    pub fn set_write(&mut self, f: Box<dyn for<'a> FnMut(&[IoVec<'a>]) -> Res + Send>) {
        self.write = Some(f);
    }

    /// Whether a read method is set (used by the writer/reader state machines
    /// to decide bidirectional vs unidirectional, writer.c/reader.c).
    #[must_use]
    pub fn has_read(&self) -> bool {
        self.read.is_some()
    }

    /// Whether a write method is set.
    #[must_use]
    pub fn has_write(&self) -> bool {
        self.write.is_some()
    }

    /// `fstrm_rdwr_destroy`: invoke the destroy method (if set), dropping the
    /// transport state.
    pub fn destroy(&mut self) -> Res {
        match self.destroy.take() {
            Some(f) => f(),
            None => Res::Success,
        }
    }

    /// `fstrm_rdwr_open` (rdwr.c): fails if no open method is set; records
    /// `opened` on success.
    pub fn open(&mut self) -> Res {
        let Some(f) = self.open.as_mut() else {
            return Res::Failure;
        };
        let res = f();
        if res == Res::Success {
            self.opened = true;
        }
        res
    }

    /// `fstrm_rdwr_close` (rdwr.c): a no-op (success) when not opened.
    pub fn close(&mut self) -> Res {
        let Some(f) = self.close.as_mut() else {
            return Res::Failure;
        };
        if self.opened {
            self.opened = false;
            f()
        } else {
            Res::Success
        }
    }

    /// `fstrm_rdwr_read` (rdwr.c): fails when not opened or without a read
    /// method; a non-success result implicitly closes the stream.
    pub fn read(&mut self, buf: &mut [u8]) -> Res {
        if !self.opened {
            return Res::Failure;
        }
        let Some(f) = self.read.as_mut() else {
            return Res::Failure;
        };
        let res = f(buf);
        if res != Res::Success {
            let _ = self.close();
        }
        res
    }

    /// `fstrm_rdwr_write` (rdwr.c): fails when not opened or without a write
    /// method; a non-success result implicitly closes the stream.
    pub fn write(&mut self, iov: &[IoVec<'_>]) -> Res {
        if !self.opened {
            return Res::Failure;
        }
        let Some(f) = self.write.as_mut() else {
            return Res::Failure;
        };
        let res = f(iov);
        if res != Res::Success {
            let _ = self.close();
        }
        res
    }
}

impl Default for Rdwr {
    fn default() -> Self {
        Rdwr::new()
    }
}

/// `fstrm__rdwr_read_control_frame` (rdwr.c): read the escape (if
/// `with_escape`), the control-frame length (bounded by
/// `FSTRM_CONTROL_FRAME_LENGTH_MAX`), the payload, decode it, and return the
/// control type.
pub(crate) fn rdwr_read_control_frame(
    rdwr: &mut Rdwr,
    control: &mut Control,
    with_escape: bool,
) -> Result<ControlType, Res> {
    if with_escape {
        let mut tmp = [0u8; 4];
        let res = rdwr.read(&mut tmp);
        if res != Res::Success {
            return Err(res);
        }
        let escape = u32::from_be_bytes(tmp);
        if escape != 0 {
            return Err(Res::Failure);
        }
    }
    let mut tmp = [0u8; 4];
    let res = rdwr.read(&mut tmp);
    if res != Res::Success {
        return Err(res);
    }
    let len_control_frame = u32::from_be_bytes(tmp) as usize;
    if len_control_frame > CONTROL_FRAME_LENGTH_MAX {
        return Err(Res::Failure);
    }
    let mut frame = vec![0u8; len_control_frame];
    let res = rdwr.read(&mut frame);
    if res != Res::Success {
        return Err(res);
    }
    control.decode(&frame, 0)?;
    control.get_type()
}

/// `fstrm__rdwr_read_control` (rdwr.c): read a control frame (with escape)
/// and require it to be of `wanted_type`.
pub(crate) fn rdwr_read_control(rdwr: &mut Rdwr, wanted_type: ControlType) -> Result<Control, Res> {
    let mut control = Control::init();
    let actual_type = rdwr_read_control_frame(rdwr, &mut control, true)?;
    if actual_type != wanted_type {
        return Err(Res::Failure);
    }
    Ok(control)
}

/// `fstrm__rdwr_write_control_frame` (rdwr.c): serialize with the header and
/// write the whole frame as a single iovec.
pub(crate) fn rdwr_write_control_frame(rdwr: &mut Rdwr, control: &Control) -> Res {
    let len_control_frame = match control.encoded_size(CONTROL_FLAG_WITH_HEADER) {
        Ok(len) => len,
        Err(res) => return res,
    };
    let mut control_frame = vec![0u8; len_control_frame];
    let mut len = len_control_frame;
    if let Err(res) = control.encode(&mut control_frame, &mut len, CONTROL_FLAG_WITH_HEADER) {
        return res;
    }
    let iov = [IoVec::new(&control_frame)];
    rdwr.write(&iov)
}

/// `fstrm__rdwr_write_control` (rdwr.c): build a one-shot control frame with
/// an optional content-type field, write it, and drop it.
pub(crate) fn rdwr_write_control(
    rdwr: &mut Rdwr,
    ty: ControlType,
    content_type: Option<&[u8]>,
) -> Res {
    let mut control = Control::init();
    if let Err(res) = control.set_type(ty) {
        return res;
    }
    if let Some(ct) = content_type {
        control.add_field_content_type(ct);
    }
    rdwr_write_control_frame(rdwr, &control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdwr_dispatch_semantics() {
        let mut rdwr = Rdwr::new();
        // No ops: everything fails.
        assert_eq!(rdwr.open(), Res::Failure);
        assert_eq!(rdwr.close(), Res::Failure);
        assert_eq!(rdwr.read(&mut [0u8; 4]), Res::Failure);
        assert_eq!(rdwr.write(&[IoVec::new(b"x")]), Res::Failure);
        // Set open/close/read/write/destroy.
        let opened = std::cell::Cell::new(false);
        rdwr.set_open(Box::new(move || {
            opened.set(true);
            Res::Success
        }));
        let mut closed = false;
        rdwr.set_close(Box::new(move || {
            closed = true;
            Res::Success
        }));
        let mut got: Vec<u8> = Vec::new();
        rdwr.set_read(Box::new(move |buf| {
            got.extend_from_slice(&[9; 4]);
            buf.copy_from_slice(&[7; 4]);
            Res::Success
        }));
        let mut written: Vec<u8> = Vec::new();
        rdwr.set_write(Box::new(move |iov| {
            for v in iov {
                written.extend_from_slice(v.data);
            }
            Res::Success
        }));
        assert_eq!(rdwr.open(), Res::Success);
        let mut buf = [0u8; 4];
        assert_eq!(rdwr.read(&mut buf), Res::Success);
        assert_eq!(buf, [7; 4]);
        assert_eq!(
            rdwr.write(&[IoVec::new(b"ab"), IoVec::new(b"cd")]),
            Res::Success
        );
        assert_eq!(rdwr.close(), Res::Success);
        // read on a closed rdwr fails
        assert_eq!(rdwr.read(&mut buf), Res::Failure);
    }
}
