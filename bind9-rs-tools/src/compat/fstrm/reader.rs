//! `fstrm_reader` (reader.c/reader.h): the reader options object and the
//! reader state machine.  Unidirectional transports (no write method) read
//! START (matching the configured content types; an empty option set accepts
//! anything, reader.c `fstrm__reader_open_unidirectional`), then data frames
//! until STOP.  Bidirectional transports read READY, answer ACCEPT with every
//! configured content type that the offer matches, then continue with the
//! START read; at close they write FINISH.  Data frames larger than
//! `max_frame_size` (default 1048576, minimum 512) fail the read and move the
//! reader to the failed state.

use super::{
    rdwr, rdwr::Rdwr, Control, ControlType, Res, CONTENT_TYPE_LENGTH_MAX, CONTROL_FRAME_LENGTH_MAX,
    READER_MAX_FRAME_SIZE_DEFAULT,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReaderState {
    Opening,
    Opened,
    Closing,
    Closed,
    Failed,
}

/// `struct fstrm_reader_options` (reader.c:49).
#[derive(Clone, Debug)]
pub struct ReaderOptions {
    content_types: Vec<Vec<u8>>,
    max_frame_size: usize,
}

impl ReaderOptions {
    /// `fstrm_reader_options_init`: `max_frame_size` defaults to
    /// `FSTRM_READER_MAX_FRAME_SIZE_DEFAULT` (1048576).
    #[must_use]
    pub fn new() -> ReaderOptions {
        ReaderOptions {
            content_types: Vec::new(),
            max_frame_size: READER_MAX_FRAME_SIZE_DEFAULT,
        }
    }

    /// `fstrm_reader_options_add_content_type` (reader.c:82).
    pub fn add_content_type(&mut self, content_type: &[u8]) -> Res {
        if content_type.len() > CONTENT_TYPE_LENGTH_MAX {
            return Res::Failure;
        }
        self.content_types.push(content_type.to_vec());
        Res::Success
    }

    /// `fstrm_reader_options_set_max_frame_size` (reader.c:101): fails below
    /// `FSTRM_CONTROL_FRAME_LENGTH_MAX` (512) or above `UINT32_MAX - 1`.
    pub fn set_max_frame_size(&mut self, max_frame_size: usize) -> Res {
        if max_frame_size < CONTROL_FRAME_LENGTH_MAX || max_frame_size > u32::MAX as usize - 1 {
            return Res::Failure;
        }
        self.max_frame_size = max_frame_size;
        Res::Success
    }
}

impl Default for ReaderOptions {
    fn default() -> Self {
        ReaderOptions::new()
    }
}

/// `struct fstrm_reader` (reader.c:36).
pub struct Reader {
    state: ReaderState,
    content_types: Vec<Vec<u8>>,
    max_frame_size: usize,
    rdwr: Rdwr,
    control_start: Option<Control>,
    control_stop: Option<Control>,
    control_ready: Option<Control>,
    control_accept: Option<Control>,
    /// `ubuf` (reader.c): the data-frame buffer, overwritten per read.
    buf: Vec<u8>,
}

impl Reader {
    /// `fstrm_reader_init` (reader.c:115): takes ownership of the rdwr (the
    /// caller's slot becomes `None`), copies the options, and requires a read
    /// method.  Fails (returns `None`) without one.
    pub fn new(ropt: Option<&ReaderOptions>, rdwr: &mut Option<Rdwr>) -> Option<Reader> {
        let rdwr = rdwr.take()?;
        if !rdwr.has_read() {
            return None;
        }
        let (content_types, max_frame_size) = match ropt {
            Some(o) => (o.content_types.clone(), o.max_frame_size),
            None => (Vec::new(), READER_MAX_FRAME_SIZE_DEFAULT),
        };
        Some(Reader {
            state: ReaderState::Opening,
            content_types,
            max_frame_size,
            rdwr,
            control_start: None,
            control_stop: None,
            control_ready: None,
            control_accept: None,
            buf: Vec::new(),
        })
    }

    /// `fstrm_reader_destroy` (reader.c:150): close if opened or closing,
    /// then release the controls and the rdwr.  Returns the close result when
    /// a close happened, else failure (matching the C).
    pub fn destroy(&mut self) -> Res {
        let res = if self.state == ReaderState::Opened || self.state == ReaderState::Closing {
            self.close()
        } else {
            Res::Failure
        };
        self.control_tmp_free();
        self.control_accept = None;
        self.control_ready = None;
        self.control_stop = None;
        self.control_start = None;
        self.rdwr.destroy();
        self.rdwr = Rdwr::new();
        self.buf.clear();
        res
    }

    fn control_tmp_free(&mut self) {
        // The C keeps a scratch control (control_tmp); we allocate per call.
        let _ = &mut self.control_accept;
    }

    fn open_unidirectional(&mut self) -> Res {
        // Read the START frame.
        let start = match rdwr::rdwr_read_control(&mut self.rdwr, ControlType::Start) {
            Ok(c) => c,
            Err(res) => return res,
        };

        // Match the START content type (reader.c fstrm__reader_open_unidirectional).
        let mut matched = false;
        for ct in &self.content_types {
            if start.match_field_content_type(Some(ct)).is_ok() {
                matched = true;
                break;
            }
        }
        if !self.content_types.is_empty() && !matched {
            // Unwanted content type.
            return Res::Failure;
        }
        self.control_start = Some(start);
        Res::Success
    }

    fn open_bidirectional(&mut self) -> Res {
        // Read the READY frame.
        let ready = match rdwr::rdwr_read_control(&mut self.rdwr, ControlType::Ready) {
            Ok(c) => c,
            Err(res) => return res,
        };

        // Initialize the ACCEPT frame.
        let mut accept = self.control_accept.take().unwrap_or_else(Control::init);
        if let Err(res) = accept.set_type(ControlType::Accept) {
            self.control_accept = Some(accept);
            return res;
        }
        // Add every configured content type that matches the offer.
        for ct in &self.content_types {
            if ready.match_field_content_type(Some(ct)).is_ok() {
                accept.add_field_content_type(ct);
            }
        }
        // Write the ACCEPT frame.
        let res = rdwr::rdwr_write_control_frame(&mut self.rdwr, &accept);
        self.control_accept = Some(accept);
        self.control_ready = Some(ready);
        if res != Res::Success {
            return res;
        }

        // Do the rest of the open.
        self.open_unidirectional()
    }

    /// `fstrm_reader_open` (reader.c:253): a double open FAILS (unlike the
    /// writer, which treats it as a success).
    pub fn open(&mut self) -> Res {
        if self.state == ReaderState::Opened {
            return Res::Failure;
        }
        let res = self.rdwr.open();
        if res != Res::Success {
            return res;
        }
        let res = if self.rdwr.has_write() {
            // Bi-directional transport.
            self.open_bidirectional()
        } else {
            // Uni-directional transport.
            self.open_unidirectional()
        };
        if res != Res::Success {
            return res;
        }
        self.state = ReaderState::Opened;
        Res::Success
    }

    fn maybe_open(&mut self) -> Res {
        if self.state == ReaderState::Opening {
            return self.open();
        }
        Res::Success
    }

    fn read_be32(&mut self) -> Result<u32, Res> {
        let mut tmp = [0u8; 4];
        let res = self.rdwr.read(&mut tmp);
        if res != Res::Success {
            return Err(res);
        }
        Ok(u32::from_be_bytes(tmp))
    }

    /// `fstrm__reader_next_data` (reader.c:294): returns `Err(Res::Stop)` on
    /// STOP (moving to `closing`); a frame longer than `max_frame_size` or
    /// any read/decode failure moves the reader to `failed`.
    fn next_data(&mut self) -> Result<&[u8], Res> {
        loop {
            let len = self.read_be32()?;

            if len != 0 {
                // This is a data frame.
                if len as usize > self.max_frame_size {
                    // reader.c fstrm__reader_next_data: the frame-size check
                    // does `goto fail` with `res` still `success` (stale from
                    // the length read), so fstrm_reader_read reports success
                    // with unspecified output while the state becomes
                    // `failed` (a subsequent close fails).  Mirrored here
                    // with an empty slice for the unspecified data.
                    self.state = ReaderState::Failed;
                    return Ok(&[]);
                }
                self.buf.clear();
                self.buf.resize(len as usize, 0);
                let res = self.rdwr.read(&mut self.buf);
                if res != Res::Success {
                    self.state = ReaderState::Failed;
                    return Err(res);
                }
                return Ok(&self.buf);
            }

            // len == 0: this is a control frame.
            let mut tmp = Control::init();
            let ty = match rdwr::rdwr_read_control_frame(&mut self.rdwr, &mut tmp, false) {
                Ok(t) => t,
                Err(res) => {
                    self.state = ReaderState::Failed;
                    return Err(res);
                }
            };
            if ty == ControlType::Stop {
                self.state = ReaderState::Closing;
                self.control_stop = Some(tmp);
                return Err(Res::Stop);
            }
        }
    }

    /// `fstrm_reader_close` (reader.c:370): fails unless opened or closing;
    /// writes FINISH for bidirectional transports, then closes the rdwr.
    pub fn close(&mut self) -> Res {
        if self.state != ReaderState::Opened && self.state != ReaderState::Closing {
            return Res::Failure;
        }
        self.state = ReaderState::Closed;

        if self.rdwr.has_write() {
            let res = rdwr::rdwr_write_control(&mut self.rdwr, ControlType::Finish, None);
            if res != Res::Success {
                let _ = self.rdwr.close();
                return res;
            }
        }
        self.rdwr.close()
    }

    /// `fstrm_reader_read` (reader.c:395): implicitly opens; returns the next
    /// data frame, `Err(Res::Stop)` after STOP, and `Err(Res::Failure)` in
    /// the failed state.
    pub fn read(&mut self) -> Result<&[u8], Res> {
        let res = self.maybe_open();
        if res != Res::Success {
            return Err(res);
        }
        if self.state == ReaderState::Opened {
            return self.next_data();
        }
        if self.state == ReaderState::Closed {
            return Err(Res::Stop);
        }
        Err(Res::Failure)
    }

    /// `fstrm_reader_get_control` (reader.c:414): implicitly opens.  Returns
    /// `Ok(None)` for a control not yet exchanged; `Err(Res::Failure)` for
    /// FINISH and unknown types.
    pub fn get_control(&mut self, ty: ControlType) -> Result<Option<&Control>, Res> {
        let res = self.maybe_open();
        if res != Res::Success {
            return Err(res);
        }
        let c = match ty {
            ControlType::Start => self.control_start.as_ref(),
            ControlType::Stop => self.control_stop.as_ref(),
            ControlType::Ready => self.control_ready.as_ref(),
            ControlType::Accept => self.control_accept.as_ref(),
            ControlType::Finish => return Err(Res::Failure),
        };
        Ok(c)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

/// `fstrm_reader_options_init`.
#[must_use]
pub fn reader_options_init() -> ReaderOptions {
    ReaderOptions::new()
}

/// `fstrm_reader_init`.
pub fn reader_init(ropt: Option<&ReaderOptions>, rdwr: &mut Option<Rdwr>) -> Option<Reader> {
    Reader::new(ropt, rdwr)
}

/// `fstrm_reader_open`.
pub fn reader_open(r: &mut Reader) -> Res {
    r.open()
}

/// `fstrm_reader_close`.
pub fn reader_close(r: &mut Reader) -> Res {
    r.close()
}

/// `fstrm_reader_destroy`.
pub fn reader_destroy(r: &mut Option<Reader>) -> Res {
    match r.take() {
        Some(mut reader) => reader.destroy(),
        None => Res::Failure,
    }
}

/// `fstrm_reader_read`: returns the frame bytes (borrowed from the reader)
/// and the result code.
pub fn reader_read<'a>(r: &'a mut Reader) -> (Res, &'a [u8]) {
    match r.read() {
        Ok(data) => (Res::Success, data),
        Err(res) => (res, &[]),
    }
}

/// `fstrm_reader_get_control`.
pub fn reader_get_control(r: &mut Reader, ty: ControlType) -> Result<Option<&Control>, Res> {
    r.get_control(ty)
}

/// `fstrm_reader_options_add_content_type`.
pub fn reader_options_add_content_type(ropt: &mut ReaderOptions, ct: &[u8]) -> Res {
    ropt.add_content_type(ct)
}

/// `fstrm_reader_options_set_max_frame_size`.
pub fn reader_options_set_max_frame_size(ropt: &mut ReaderOptions, v: usize) -> Res {
    ropt.set_max_frame_size(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{ControlFrame, ControlType as CT, Frame, FrameWriter, Res};

    /// A reader over an in-memory unidirectional byte stream.
    fn reader_over_bytes(bytes: Vec<u8>) -> Reader {
        let mut rdwr = Rdwr::new();
        let data = std::sync::Arc::new(std::sync::Mutex::new(bytes));
        let d = data.clone();
        rdwr.set_open(Box::new(|| Res::Success));
        let d2 = data.clone();
        rdwr.set_close(Box::new(move || {
            drop(&d2);
            Res::Success
        }));
        rdwr.set_read(Box::new(move |buf| {
            let mut v = d.lock().unwrap();
            if v.len() < buf.len() {
                return Res::Stop;
            }
            buf.copy_from_slice(&v[..buf.len()]);
            v.drain(..buf.len());
            Res::Success
        }));
        let mut ropt = ReaderOptions::new();
        ropt.add_content_type(b"test:hello");
        Reader::new(Some(&ropt), &mut Some(rdwr)).unwrap()
    }

    #[test]
    fn reader_requires_read_method() {
        let rdwr = Rdwr::new();
        assert!(Reader::new(None, &mut Some(rdwr)).is_none());
    }

    #[test]
    fn reader_options_bounds() {
        let mut o = ReaderOptions::new();
        assert_eq!(o.max_frame_size, READER_MAX_FRAME_SIZE_DEFAULT);
        assert_eq!(o.set_max_frame_size(511), Res::Failure);
        assert_eq!(o.set_max_frame_size(512), Res::Success);
        assert_eq!(o.set_max_frame_size(u32::MAX as usize - 1), Res::Success);
        assert_eq!(o.set_max_frame_size(u32::MAX as usize), Res::Failure);
        // content type over 256 fails
        assert_eq!(
            o.add_content_type(&[b'x'; CONTENT_TYPE_LENGTH_MAX + 1]),
            Res::Failure
        );
        assert_eq!(o.add_content_type(b"ok"), Res::Success);
    }

    #[test]
    fn reader_reads_file_stream() {
        // Build a stream with the writer's file semantics.
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut fw = FrameWriter::new(&mut bytes);
            fw.write_control(&ControlFrame::with_content_type(
                CT::Start,
                b"test:hello".to_vec(),
            ))
            .unwrap();
            fw.write_data(b"alpha").unwrap();
            fw.write_data(b"beta").unwrap();
            fw.write_control(&ControlFrame::new(CT::Stop)).unwrap();
        }
        let mut r = reader_over_bytes(bytes);
        assert_eq!(r.open(), Res::Success);
        // Double open fails for readers (reader.c).
        assert_eq!(r.open(), Res::Failure);
        assert_eq!(r.read(), Ok(&b"alpha"[..]));
        assert_eq!(r.read(), Ok(&b"beta"[..]));
        assert_eq!(r.read(), Err(Res::Stop));
        // After stop the reader is in the closing state; the C returns
        // failure for further reads until close (reader.c fstrm_reader_read:
        // only the closed state returns stop).
        assert_eq!(r.read(), Err(Res::Failure));
        assert_eq!(r.close(), Res::Success);
        // Close on a closed reader fails.
        assert_eq!(r.close(), Res::Failure);
    }

    #[test]
    fn reader_get_control_start() {
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut fw = FrameWriter::new(&mut bytes);
            fw.write_control(&ControlFrame::with_content_type(
                CT::Start,
                b"test:hello".to_vec(),
            ))
            .unwrap();
            fw.write_data(b"x").unwrap();
            fw.write_control(&ControlFrame::new(CT::Stop)).unwrap();
        }
        let mut r = reader_over_bytes(bytes);
        assert_eq!(r.read(), Ok(&b"x"[..]));
        let start = r.get_control(CT::Start).unwrap().unwrap();
        assert_eq!(start.get_type(), Ok(CT::Start));
        assert_eq!(start.get_num_field_content_type(), 1);
        assert_eq!(start.get_field_content_type(0), Ok(&b"test:hello"[..]));
        // FINISH is not retrievable.
        assert_eq!(r.get_control(CT::Finish), Err(Res::Failure));
        let _ = Frame::Data(Vec::new());
    }

    #[test]
    fn reader_rejects_wrong_content_type() {
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut fw = FrameWriter::new(&mut bytes);
            fw.write_control(&ControlFrame::with_content_type(
                CT::Start,
                b"test:other".to_vec(),
            ))
            .unwrap();
        }
        let mut r = reader_over_bytes(bytes);
        assert_eq!(r.read(), Err(Res::Failure));
        // The failed state also fails subsequent reads and closes.
        assert_eq!(r.close(), Res::Failure);
    }

    #[test]
    fn reader_enforces_max_frame_size() {
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut fw = FrameWriter::new(&mut bytes);
            fw.write_control(&ControlFrame::with_content_type(
                CT::Start,
                b"test:hello".to_vec(),
            ))
            .unwrap();
            fw.write_data(&vec![b'z'; 600]).unwrap();
            fw.write_control(&ControlFrame::new(CT::Stop)).unwrap();
        }
        let mut rdwr = Rdwr::new();
        let data = std::sync::Arc::new(std::sync::Mutex::new(bytes));
        let d = data.clone();
        rdwr.set_open(Box::new(|| Res::Success));
        let d2 = data.clone();
        rdwr.set_close(Box::new(move || {
            drop(&d2);
            Res::Success
        }));
        rdwr.set_read(Box::new(move |buf| {
            let mut v = d.lock().unwrap();
            if v.len() < buf.len() {
                return Res::Stop;
            }
            buf.copy_from_slice(&v[..buf.len()]);
            v.drain(..buf.len());
            Res::Success
        }));
        let mut ropt = ReaderOptions::new();
        ropt.add_content_type(b"test:hello");
        assert_eq!(ropt.set_max_frame_size(512), Res::Success);
        let mut r = Reader::new(Some(&ropt), &mut Some(rdwr)).unwrap();
        // reader.c: the max-frame-size violation returns success (stale `res`
        // from the length read) with unspecified output; the reader enters
        // the failed state, so the subsequent close fails.
        assert_eq!(r.read().map(|d| d.len()), Ok(0));
        assert_eq!(r.close(), Res::Failure);
    }
}
