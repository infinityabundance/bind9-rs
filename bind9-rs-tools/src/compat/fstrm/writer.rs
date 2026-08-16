//! `fstrm_writer` (writer.c/writer.h): the writer options object and the
//! writer state machine.  Unidirectional transports (no read method) write
//! START (with the first content type), data frames, then STOP.  Bidirectional
//! transports write READY (all content types), wait for ACCEPT, match the
//! offered types against the ACCEPT fields (writer.c
//! `fstrm__writer_open_bidirectional`), write START with the matched type,
//! then data, then STOP and wait for FINISH at close.  Data frames are framed
//! with `u32 BE length | payload` and written via the rdwr's scatter/gather
//! write (one length+data pair per frame, `FSTRM__WRITER_IOVEC_SIZE` = 256
//! batching, chunked at 128 frames per call).

use super::{
    rdwr,
    rdwr::{IoVec, Rdwr},
    Control, ControlType, Res, WRITER_IOVEC_SIZE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// The `Failed` variant exists in the C enum (writer.c:33) but, exactly like
// the C, is never assigned by the writer state machine — it is kept for
// structural fidelity.
#[allow(dead_code)]
pub(crate) enum WriterState {
    Opening,
    Opened,
    Closed,
    Failed,
}

/// `struct fstrm_writer_options` (writer.c:36): the content types the writer
/// can negotiate.
#[derive(Clone, Debug, Default)]
pub struct WriterOptions {
    content_types: Vec<Vec<u8>>,
}

impl WriterOptions {
    /// `fstrm_writer_options_init`.
    #[must_use]
    pub fn new() -> WriterOptions {
        WriterOptions {
            content_types: Vec::new(),
        }
    }

    /// `fstrm_writer_options_add_content_type` (writer.c:74): copies the
    /// content type; fails when it exceeds
    /// `FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX` (256).
    pub fn add_content_type(&mut self, content_type: &[u8]) -> Res {
        if content_type.len() > super::CONTENT_TYPE_LENGTH_MAX {
            return Res::Failure;
        }
        self.content_types.push(content_type.to_vec());
        Res::Success
    }

    /// The content types accumulated so far (a copy; the C exposes no getter,
    /// this exists for tests and transports).
    #[must_use]
    pub fn content_types(&self) -> &[Vec<u8>] {
        &self.content_types
    }
}

/// `struct fstrm_writer` (writer.c:40).
pub struct Writer {
    pub(crate) state: WriterState,
    content_types: Vec<Vec<u8>>,
    pub(crate) rdwr: Rdwr,
    control_ready: Option<Control>,
    control_accept: Option<Control>,
    control_start: Option<Control>,
    control_finish: Option<Control>,
}

impl Writer {
    /// `fstrm_writer_init` (writer.c:93): takes ownership of the rdwr (the
    /// caller's slot becomes `None`), copies the content types, and requires
    /// a write method.  Fails (returns `None`) without one.
    pub fn new(wopt: Option<&WriterOptions>, rdwr: &mut Option<Rdwr>) -> Option<Writer> {
        let rdwr = rdwr.take()?;
        if !rdwr.has_write() {
            return None;
        }
        let content_types = wopt.map(|w| w.content_types.clone()).unwrap_or_default();
        Some(Writer {
            state: WriterState::Opening,
            content_types,
            rdwr,
            control_ready: None,
            control_accept: None,
            control_start: None,
            control_finish: None,
        })
    }

    /// `fstrm_writer_destroy` (writer.c:126): close if opened, then release
    /// the controls and the rdwr (dropping the transport).  Returns the close
    /// result when a close happened, else failure (matching the C).
    pub fn destroy(&mut self) -> Res {
        let res = if self.state == WriterState::Opened {
            self.close()
        } else {
            Res::Failure
        };
        self.control_finish = None;
        self.control_start = None;
        self.control_accept = None;
        self.control_ready = None;
        self.rdwr.destroy();
        self.rdwr = Rdwr::new();
        res
    }

    fn open_bidirectional(&mut self) -> Res {
        // Initialize the READY frame (writer.c fstrm__writer_open_bidirectional).
        let mut ready = self.control_ready.take().unwrap_or_else(Control::init);
        if let Err(res) = ready.set_type(ControlType::Ready) {
            self.control_ready = Some(ready);
            return res;
        }
        for ct in &self.content_types {
            ready.add_field_content_type(ct);
        }
        let res = rdwr::rdwr_write_control_frame(&mut self.rdwr, &ready);
        self.control_ready = Some(ready);
        if res != Res::Success {
            return res;
        }

        // Wait for the ACCEPT frame.
        let accept = match rdwr::rdwr_read_control(&mut self.rdwr, ControlType::Accept) {
            Ok(c) => c,
            Err(res) => return res,
        };

        // Match the ACCEPT content type.  An empty ACCEPT matches the first
        // offered type; an empty offer is accepted; an offer that matches
        // nothing fails the negotiation.
        let mut matched: Option<&[u8]> = None;
        for ct in &self.content_types {
            if accept.match_field_content_type(Some(ct)).is_ok() {
                matched = Some(ct);
                break;
            }
        }
        if !self.content_types.is_empty() && matched.is_none() {
            return Res::Failure;
        }

        // Initialize the START frame with the matched content type.
        let mut start = self.control_start.take().unwrap_or_else(Control::init);
        if let Err(res) = start.set_type(ControlType::Start) {
            self.control_start = Some(start);
            return res;
        }
        if let Some(ct) = matched {
            start.add_field_content_type(ct);
        }
        let res = rdwr::rdwr_write_control_frame(&mut self.rdwr, &start);
        self.control_start = Some(start);
        self.control_accept = Some(accept);
        res
    }

    fn open_unidirectional(&mut self) -> Res {
        // Initialize the START frame (writer.c fstrm__writer_open_unidirectional).
        let mut start = self.control_start.take().unwrap_or_else(Control::init);
        if let Err(res) = start.set_type(ControlType::Start) {
            self.control_start = Some(start);
            return res;
        }
        if let Some(ct) = self.content_types.first() {
            start.add_field_content_type(ct);
        }
        let res = rdwr::rdwr_write_control_frame(&mut self.rdwr, &start);
        self.control_start = Some(start);
        res
    }

    /// `fstrm_writer_open` (writer.c:263): a double open is a success.
    pub fn open(&mut self) -> Res {
        if self.state == WriterState::Opened {
            return Res::Success;
        }
        let res = self.rdwr.open();
        if res != Res::Success {
            return res;
        }
        let res = if self.rdwr.has_read() {
            // Bi-directional transport.
            self.open_bidirectional()
        } else {
            // Uni-directional transport.
            self.open_unidirectional()
        };
        if res != Res::Success {
            return res;
        }
        self.state = WriterState::Opened;
        Res::Success
    }

    fn maybe_open(&mut self) -> Res {
        if self.state == WriterState::Opening {
            return self.open();
        }
        Res::Success
    }

    /// `fstrm_writer_close` (writer.c:305): fails unless opened; writes STOP,
    /// then for bidirectional transports waits for FINISH, then closes the
    /// rdwr.
    pub fn close(&mut self) -> Res {
        if self.state != WriterState::Opened {
            return Res::Failure;
        }
        self.state = WriterState::Closed;

        let res = rdwr::rdwr_write_control(&mut self.rdwr, ControlType::Stop, None);
        if res != Res::Success {
            let _ = self.rdwr.close();
            return res;
        }
        if self.rdwr.has_read() {
            let finish = rdwr::rdwr_read_control(&mut self.rdwr, ControlType::Finish);
            match finish {
                Ok(c) => self.control_finish = Some(c),
                Err(res) => {
                    let _ = self.rdwr.close();
                    return res;
                }
            }
        }
        self.rdwr.close()
    }

    fn write_iov(&mut self, iov: &[&[u8]]) -> Res {
        // Frame each payload with its u32 BE length (writer.c
        // fstrm__writer_write_iov), then write length+data pairs.
        let n = iov.len();
        let mut lens = Vec::with_capacity(n * 4);
        for d in iov {
            lens.extend_from_slice(&(d.len() as u32).to_be_bytes());
        }
        let mut vecs: Vec<IoVec<'_>> = Vec::with_capacity(n * 2);
        for i in 0..n {
            let off = i * 4;
            vecs.push(IoVec::new(&lens[off..off + 4]));
            vecs.push(IoVec::new(iov[i]));
        }
        self.rdwr.write(&vecs)
    }

    fn write_iov_stupid(&mut self, iov: &[&[u8]]) -> Res {
        // writer.c fstrm__writer_write_iov_stupid: chunk at iov_max =
        // min(FSTRM__WRITER_IOVEC_SIZE / 2, IOV_MAX) frames per call.
        let mut iov_max = WRITER_IOVEC_SIZE / 2;
        if iov_max > 1024 {
            iov_max = 1024; // IOV_MAX on Linux (fstrm-private.h)
        }
        let mut rest = iov;
        while !rest.is_empty() {
            let n = iov_max.min(rest.len());
            let res = self.write_iov(&rest[..n]);
            if res != Res::Success {
                return res;
            }
            rest = &rest[n..];
        }
        Res::Success
    }

    /// `fstrm_writer_writev` (writer.c:391): implicitly opens; an empty iovec
    /// list is a success; frames beyond the 256-iovec scratch go through the
    /// chunked path.
    pub fn writev(&mut self, iov: &[&[u8]]) -> Res {
        if iov.is_empty() {
            return Res::Success;
        }
        let res = self.maybe_open();
        if res != Res::Success {
            return res;
        }
        if self.state == WriterState::Opened {
            if 2 * iov.len() <= WRITER_IOVEC_SIZE {
                return self.write_iov(iov);
            }
            return self.write_iov_stupid(iov);
        }
        Res::Failure
    }

    /// `fstrm_writer_write` (writer.c:381).
    pub fn write(&mut self, data: &[u8]) -> Res {
        self.writev(&[data])
    }

    /// `fstrm_writer_get_control` (writer.c:413): implicitly opens.  Returns
    /// `Ok(None)` for a control that has not been exchanged yet (e.g. FINISH
    /// before close); `Err(Res::Failure)` for STOP and unknown types.
    pub fn get_control(&mut self, ty: ControlType) -> Result<Option<&Control>, Res> {
        let res = self.maybe_open();
        if res != Res::Success {
            return Err(res);
        }
        let c = match ty {
            ControlType::Accept => self.control_accept.as_ref(),
            ControlType::Finish => self.control_finish.as_ref(),
            ControlType::Ready => self.control_ready.as_ref(),
            ControlType::Start => self.control_start.as_ref(),
            ControlType::Stop => return Err(Res::Failure),
        };
        Ok(c)
    }

    /// Construct a `Reader` sharing this writer's rdwr (used by four-corner
    /// tests); not part of the C surface.
    #[cfg(test)]
    pub(crate) fn rdwr_for_test(&mut self) -> &mut Rdwr {
        &mut self.rdwr
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

/// `fstrm_writer_options_init`.
#[must_use]
pub fn writer_options_init() -> WriterOptions {
    WriterOptions::new()
}

/// `fstrm_writer_init`.
pub fn writer_init(wopt: Option<&WriterOptions>, rdwr: &mut Option<Rdwr>) -> Option<Writer> {
    Writer::new(wopt, rdwr)
}

/// `fstrm_writer_open`.
pub fn writer_open(w: &mut Writer) -> Res {
    w.open()
}

/// `fstrm_writer_close`.
pub fn writer_close(w: &mut Writer) -> Res {
    w.close()
}

/// `fstrm_writer_destroy`.
pub fn writer_destroy(w: &mut Option<Writer>) -> Res {
    match w.take() {
        Some(mut writer) => writer.destroy(),
        None => Res::Failure,
    }
}

/// `fstrm_writer_write`.
pub fn writer_write(w: &mut Writer, data: &[u8]) -> Res {
    w.write(data)
}

/// `fstrm_writer_writev` for a list of payloads (the C's iovec array).
pub fn writer_writev(w: &mut Writer, iov: &[&[u8]]) -> Res {
    w.writev(iov)
}

/// `fstrm_writer_get_control` (writer.c:413): implicitly opens; `Ok(None)`
/// for a control not yet exchanged, `Err(Res::Failure)` for STOP/unknown.
pub fn writer_get_control(w: &mut Writer, ty: ControlType) -> Result<Option<&Control>, Res> {
    w.get_control(ty)
}

/// `fstrm_writer_options_add_content_type`.
pub fn writer_options_add_content_type(wopt: &mut WriterOptions, ct: &[u8]) -> Res {
    wopt.add_content_type(ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{ControlType as CT, Frame, FrameReader, Reader, Res};
    use std::rc::Rc;

    fn writer_over_sink() -> (Writer, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let mut rdwr = Rdwr::new();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        rdwr.set_open(Box::new(|| Res::Success));
        rdwr.set_close(Box::new(|| Res::Success));
        let b2 = buf.clone();
        rdwr.set_write(Box::new(move |iov| {
            let mut v = b2.lock().unwrap();
            for i in iov {
                v.extend_from_slice(i.data);
            }
            Res::Success
        }));
        let mut wopt = WriterOptions::new();
        wopt.add_content_type(b"test:hello");
        let w = Writer::new(Some(&wopt), &mut Some(rdwr)).unwrap();
        (w, buf)
    }

    fn sink_bytes(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> Vec<u8> {
        buf.lock().unwrap().clone()
    }

    #[test]
    fn writer_requires_write_method() {
        let rdwr = Rdwr::new();
        assert!(Writer::new(None, &mut Some(rdwr)).is_none());
    }

    #[test]
    fn writer_unidirectional_start_stop() {
        let (mut w, buf) = writer_over_sink();
        assert_eq!(w.open(), Res::Success);
        // Double open is a success (writer.c).
        assert_eq!(w.open(), Res::Success);
        assert_eq!(w.write(b"frame"), Res::Success);
        assert_eq!(w.close(), Res::Success);
        // Close on a closed writer fails (writer.c).
        assert_eq!(w.close(), Res::Failure);
        drop(w);
        let buf = sink_bytes(&buf);
        // Wire: START(test:hello) + data + STOP.
        let mut r = FrameReader::new(&buf[..]);
        match r.next().unwrap().unwrap() {
            Frame::Control(c) => {
                assert_eq!(c.control_type, CT::Start);
                assert_eq!(c.content_types, vec![b"test:hello".to_vec()]);
            }
            _ => panic!("expected START"),
        }
        assert_eq!(r.next().unwrap().unwrap(), Frame::Data(b"frame".to_vec()));
        match r.next().unwrap().unwrap() {
            Frame::Control(c) => assert_eq!(c.control_type, CT::Stop),
            _ => panic!("expected STOP"),
        }
    }

    #[test]
    fn writer_get_control() {
        let (mut w, _buf) = writer_over_sink();
        assert_eq!(w.open(), Res::Success);
        let start = w.get_control(CT::Start).unwrap().unwrap();
        assert_eq!(start.get_type(), Ok(CT::Start));
        assert_eq!(start.get_num_field_content_type(), 1);
        // FINISH not exchanged yet.
        assert!(w.get_control(CT::Finish).unwrap().is_none());
        // STOP is not retrievable.
        assert_eq!(w.get_control(CT::Stop), Err(Res::Failure));
        drop(w);
    }

    #[test]
    fn writer_writev_chunked_path() {
        let (mut w, buf) = writer_over_sink();
        // 200 frames > 128 per chunk -> the "stupid" chunked path.
        let iov: Vec<Vec<u8>> = (0..200).map(|i| format!("m{i:03}").into_bytes()).collect();
        let refs: Vec<&[u8]> = iov.iter().map(Vec::as_slice).collect();
        assert_eq!(w.writev(&refs), Res::Success);
        assert_eq!(w.close(), Res::Success);
        drop(w);
        let buf = sink_bytes(&buf);
        let mut r = FrameReader::new(&buf[..]);
        assert!(matches!(r.next().unwrap().unwrap(), Frame::Control(_))); // START
        for i in 0..200 {
            match r.next().unwrap().unwrap() {
                Frame::Data(d) => assert_eq!(d, format!("m{i:03}").as_bytes()),
                _ => panic!("expected data frame {i}"),
            }
        }
        assert!(
            matches!(r.next().unwrap().unwrap(), Frame::Control(c) if c.control_type == CT::Stop)
        );
    }

    #[test]
    fn writer_bidirectional_handshake_with_reader() {
        // Full four-corner: Writer over one UnixStream pair end, Reader over
        // the other, using the faithful reader API.  The reader runs on its
        // own thread exactly like the C test_fstrm_io_sock consumer thread
        // (the writer's close() waits for the reader's FINISH).
        #[cfg(unix)]
        {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;

            let (a, b) = UnixStream::pair().unwrap();

            // Reader side: wrap b in an rdwr with read+write (bidirectional).
            let reader_handle = std::thread::spawn(move || {
                let mut rrdwr = Rdwr::new();
                let rb = b.try_clone().unwrap();
                rrdwr.set_open(Box::new(|| Res::Success));
                let rb2 = rb.try_clone().unwrap();
                rrdwr.set_close(Box::new(move || {
                    drop(&rb2);
                    Res::Success
                }));
                let rb3 = rb.try_clone().unwrap();
                rrdwr.set_read(Box::new(move |buf| {
                    let mut s = rb3.try_clone().unwrap();
                    match s.read_exact(buf) {
                        Ok(()) => Res::Success,
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Res::Stop,
                        Err(_) => Res::Failure,
                    }
                }));
                let rb4 = rb.try_clone().unwrap();
                rrdwr.set_write(Box::new(move |iov| {
                    let mut s = rb4.try_clone().unwrap();
                    for i in iov {
                        if s.write_all(i.data).is_err() {
                            return Res::Failure;
                        }
                    }
                    Res::Success
                }));

                let mut ropt = super::super::ReaderOptions::new();
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

            // Writer side (main thread).
            let mut wrdwr = Rdwr::new();
            let wa = a.try_clone().unwrap();
            wrdwr.set_open(Box::new(|| Res::Success));
            let wa2 = wa.try_clone().unwrap();
            wrdwr.set_close(Box::new(move || {
                drop(&wa2);
                Res::Success
            }));
            let wa3 = wa.try_clone().unwrap();
            wrdwr.set_read(Box::new(move |buf| {
                let mut s = wa3.try_clone().unwrap();
                match s.read_exact(buf) {
                    Ok(()) => Res::Success,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Res::Stop,
                    Err(_) => Res::Failure,
                }
            }));
            let wa4 = wa.try_clone().unwrap();
            wrdwr.set_write(Box::new(move |iov| {
                let mut s = wa4.try_clone().unwrap();
                for i in iov {
                    if s.write_all(i.data).is_err() {
                        return Res::Failure;
                    }
                }
                Res::Success
            }));
            let mut wopt = WriterOptions::new();
            wopt.add_content_type(b"test:hello");
            let mut w = Writer::new(Some(&wopt), &mut Some(wrdwr)).unwrap();

            assert_eq!(w.open(), Res::Success);
            assert_eq!(w.write(b"payload-one"), Res::Success);
            assert_eq!(w.write(b"payload-two"), Res::Success);
            assert_eq!(w.close(), Res::Success);
            drop(w);
            drop(a);

            let (d1, d2, stop, closed) = reader_handle.join().unwrap();
            assert_eq!(d1, b"payload-one");
            assert_eq!(d2, b"payload-two");
            assert_eq!(stop, Err(Res::Stop));
            assert_eq!(closed, Res::Success);
        }
    }
}
