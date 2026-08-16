//! Raw frame codec: `FrameWriter`/`FrameReader` (fstrm `control.h:34`
//! framing — data frames are `u32 BE length | payload`, control frames are
//! escaped with a zero length).  These operate on any `Read`/`Write` pair
//! and are the foundation the [`super::stream`] state machines and the
//! DNSTAP-style file readers build on.

use super::{ControlFrame, CONTROL_FRAME_LENGTH_MAX};
use std::io::{self, Read, Write};

/// Frame writer: emits data frames and control frames on the wire.
pub struct FrameWriter<W: Write> {
    inner: W,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        FrameWriter { inner }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Write a data frame: `u32 BE length | payload`.  A zero-length data
    /// frame is impossible on the wire (length 0 is the escape sequence), so
    /// the C writer never emits one; we reject it the same way.
    pub fn write_data(&mut self, payload: &[u8]) -> io::Result<()> {
        debug_assert!(!payload.is_empty(), "fstrm: empty data frame is the escape");
        self.inner
            .write_all(&(payload.len() as u32).to_be_bytes())?;
        self.inner.write_all(payload)
    }

    pub fn write_control(&mut self, frame: &ControlFrame) -> io::Result<()> {
        let encoded = frame.encode_with_header().map_err(|_| {
            super::io_err(io::ErrorKind::InvalidInput, "fstrm: invalid control frame")
        })?;
        self.inner.write_all(&encoded)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A frame read from the stream: either data payload bytes or a control
/// frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Data(Vec<u8>),
    Control(ControlFrame),
}

/// Frame reader: reads raw frames, distinguishing data from control frames
/// by the escape sequence (control.h:34).
pub struct FrameReader<R: Read> {
    inner: R,
    /// Number of payload bytes still to consume for the current frame.
    remaining: usize,
    reading: bool,
}

impl<R: Read> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner,
            remaining: 0,
            reading: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Read the next frame.  `Ok(None)` indicates clean end-of-stream at a
    /// frame boundary; a truncated frame yields `Err`.
    pub fn next(&mut self) -> io::Result<Option<Frame>> {
        if !self.reading {
            // Read the 4-byte frame length.
            let mut lenbuf = [0u8; 4];
            let mut got = 0;
            while got < 4 {
                match self.inner.read(&mut lenbuf[got..]) {
                    Ok(0) => {
                        if got == 0 {
                            return Ok(None); // clean EOF at boundary
                        }
                        return Err(super::io_err(
                            io::ErrorKind::UnexpectedEof,
                            "fstrm: truncated frame length",
                        ));
                    }
                    Ok(n) => got += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            let len = u32::from_be_bytes(lenbuf) as usize;
            if len == 0 {
                // Escape: a control frame follows: u32 BE control length +
                // payload (<= 512).
                let mut cbuf = [0u8; 4];
                self.read_exact_checked(&mut cbuf)?;
                let clen = u32::from_be_bytes(cbuf) as usize;
                if clen > CONTROL_FRAME_LENGTH_MAX {
                    return Err(super::io_err(
                        io::ErrorKind::InvalidData,
                        "fstrm: control frame too long",
                    ));
                }
                let mut payload = vec![0u8; clen];
                self.read_exact_checked(&mut payload)?;
                let frame = ControlFrame::decode_payload(&payload).map_err(|_| {
                    super::io_err(io::ErrorKind::InvalidData, "fstrm: malformed control frame")
                })?;
                return Ok(Some(Frame::Control(frame)));
            }
            self.remaining = len;
            self.reading = true;
            // Fall through to payload reads.
        }

        let mut buf = vec![0u8; self.remaining];
        self.read_exact_checked(&mut buf)?;
        self.reading = false;
        self.remaining = 0;
        Ok(Some(Frame::Data(buf)))
    }

    fn read_exact_checked(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut got = 0;
        while got < buf.len() {
            match self.inner.read(&mut buf[got..]) {
                Ok(0) => {
                    return Err(super::io_err(
                        io::ErrorKind::UnexpectedEof,
                        "fstrm: truncated frame",
                    ));
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_reader_truncation_is_error() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w: super::super::StreamWriter<&mut Vec<u8>> =
                super::super::StreamWriter::open_unidirectional(&mut buf, vec![]).unwrap();
            w.write(b"0123456789").unwrap();
        }
        let cut = &buf[..buf.len() - 3];
        let mut r = FrameReader::new(cut);
        // START control frame is intact.
        assert!(matches!(r.next().unwrap().unwrap(), Frame::Control(_)));
        // The data frame is intact too (the writer also emits a STOP frame at
        // drop, so the truncation lands in the STOP frame).
        assert_eq!(
            r.next().unwrap().unwrap(),
            Frame::Data(b"0123456789".to_vec())
        );
        // The final (truncated STOP) frame must be an error.
        assert!(r.next().is_err());
    }
}
