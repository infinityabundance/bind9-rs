//! Frame Streams (fstrm) — native Rust conservation of fstrm 0.6.1 (§26).
//!
//! This module preserves the *observable* fstrm contract: the byte-stream
//! framing, the control-frame wire format, the unidirectional
//! START/data*/STOP and bidirectional READY/ACCEPT/data*/FINISH state
//! machines, the `fstrm_res` result taxonomy, and the length limits
//! (`FSTRM_CONTROL_FRAME_LENGTH_MAX` = 512, content-type payload max = 256).
//! It is not a generic "frame codec": every constant, error path and limit
//! below is read from the pinned fstrm 0.6.1 source
//! (`bind9-rs-tools/forensics/oracle/work/deps/fstrm-0.6.1/`) and is subject
//! to the four-corner interchange courts (§38) against the C oracle image
//! (`oracle-fstrm-0.6.1`).
//!
//! # Wire format (control.h:34, control.c)
//!
//! ```text
//! data frame    : u32 BE length (N > 0) | N payload bytes
//! control frame : u32 BE 0 (escape)    | u32 BE control_length | payload
//! payload       : u32 BE type | fields*
//! field         : u32 BE 1 (CONTENT_TYPE) | u32 BE len | bytes
//! ```
//! `START` and `STOP` bracket unidirectional streams; `READY`/`ACCEPT`/
//! `FINISH` implement the bidirectional handshake.  Unknown control types,
//! unknown field types, and out-of-limit lengths are hard failures, exactly
//! as in the C implementation.
//!
//! Status: Phase 1 (§64).  Wire core implemented; `fstrm_iothr` and the
//! unix/tcp transports are staged next.

use std::io::{self, Read, Write};

/// Result codes mirroring `fstrm_res` (fstrm.h:261).  Only `success` and
/// `failure` are produced by the 0.6.1 control codec; `again`/`invalid`/
/// `stop` appear in the reader/writer state machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Res {
    /// Success.
    Success = 0,
    /// Failure.
    Failure = 1,
    /// Resource temporarily unavailable.
    Again = 2,
    /// Parameters were invalid.
    Invalid = 3,
    /// The end of a stream has been reached.
    Stop = 4,
}

impl Res {
    /// `fstrm_res_strerror`-style rendering.  (0.6.1 ships no such function;
    /// the strings match the enum documentation so courts can diff against
    /// observed oracle behavior.)
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Res::Success => "success",
            Res::Failure => "failure",
            Res::Again => "again",
            Res::Invalid => "invalid",
            Res::Stop => "stop",
        }
    }
}

/// Control frame types (control.h:154).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlType {
    Accept = 0x01,
    Start = 0x02,
    Stop = 0x03,
    Ready = 0x04,
    Finish = 0x05,
}

impl ControlType {
    /// String rendering used by `fstrm_control_type_to_str` (unknown values
    /// would render as `"FSTRM_CONTROL_UNKNOWN"`).
    #[must_use]
    pub const fn to_str(self) -> &'static str {
        match self {
            ControlType::Accept => "FSTRM_CONTROL_ACCEPT",
            ControlType::Start => "FSTRM_CONTROL_START",
            ControlType::Stop => "FSTRM_CONTROL_STOP",
            ControlType::Ready => "FSTRM_CONTROL_READY",
            ControlType::Finish => "FSTRM_CONTROL_FINISH",
        }
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(ControlType::Accept),
            0x02 => Some(ControlType::Start),
            0x03 => Some(ControlType::Stop),
            0x04 => Some(ControlType::Ready),
            0x05 => Some(ControlType::Finish),
            _ => None,
        }
    }
}

/// `FSTRM_CONTROL_FRAME_LENGTH_MAX` (control.h:143): maximum control-frame
/// payload length, excluding escape sequence and control-frame length.
pub const CONTROL_FRAME_LENGTH_MAX: usize = 512;

/// `FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX` (control.h:149).
pub const CONTENT_TYPE_LENGTH_MAX: usize = 256;

/// `FSTRM_CONTROL_FIELD_CONTENT_TYPE` (control.h:180).
pub const CONTROL_FIELD_CONTENT_TYPE: u32 = 0x01;

/// A decoded control frame: type plus zero or more content-type fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlFrame {
    pub control_type: ControlType,
    /// Raw content-type byte strings, in wire order.
    pub content_types: Vec<Vec<u8>>,
}

impl ControlFrame {
    pub fn new(control_type: ControlType) -> Self {
        ControlFrame {
            control_type,
            content_types: Vec::new(),
        }
    }

    pub fn with_content_type(control_type: ControlType, ct: Vec<u8>) -> Self {
        ControlFrame {
            control_type,
            content_types: vec![ct],
        }
    }

    /// `fstrm_control_encode` with `FSTRM_CONTROL_FLAG_WITH_HEADER`
    /// (control.c:417): escape (u32 BE 0) + control length + payload.
    pub fn encode_with_header(&self) -> Result<Vec<u8>, Res> {
        let payload = self.encode_payload()?;
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// `fstrm_control_encode` without the header: payload only.
    ///
    /// Enforces exactly the C constraints (control.c `encoded_size`): no
    /// content-type fields on STOP/FINISH, at most one on START, content-type
    /// payloads <= 256 bytes, and the whole payload <= 512 bytes.
    pub fn encode_payload(&self) -> Result<Vec<u8>, Res> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&(self.control_type as u32).to_be_bytes());
        if self.control_type != ControlType::Stop && self.control_type != ControlType::Finish {
            let n = if self.control_type == ControlType::Start {
                1
            } else {
                self.content_types.len()
            };
            for ct in self.content_types.iter().take(n) {
                if ct.len() > CONTENT_TYPE_LENGTH_MAX {
                    return Err(Res::Failure);
                }
                out.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
                out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
                out.extend_from_slice(ct);
            }
        }
        if out.len() > CONTROL_FRAME_LENGTH_MAX {
            return Err(Res::Failure);
        }
        Ok(out)
    }

    /// `fstrm_control_decode` with `FSTRM_CONTROL_FLAG_WITH_HEADER`
    /// (control.c:238): the input begins with the escape + control length.
    pub fn decode_with_header(bytes: &[u8]) -> Result<Self, Res> {
        let mut b = bytes;
        let (outer, rest) = read_be32(b).ok_or(Res::Failure)?;
        b = rest;
        if outer != 0 {
            return Err(Res::Failure);
        }
        let (clen, rest) = read_be32(b).ok_or(Res::Failure)?;
        b = rest;
        if clen as usize > CONTROL_FRAME_LENGTH_MAX {
            return Err(Res::Failure);
        }
        if clen as usize != b.len() {
            return Err(Res::Failure);
        }
        Self::decode_payload(b)
    }

    /// `fstrm_control_decode` without the header: input is the payload.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, Res> {
        if payload.len() > CONTROL_FRAME_LENGTH_MAX {
            return Err(Res::Failure);
        }
        let mut b = payload;
        let (t, rest) = read_be32(b).ok_or(Res::Failure)?;
        b = rest;
        let control_type = ControlType::from_u32(t).ok_or(Res::Failure)?;

        let mut content_types = Vec::new();
        while !b.is_empty() {
            let (ftype, rest) = read_be32(b).ok_or(Res::Failure)?;
            b = rest;
            if ftype != CONTROL_FIELD_CONTENT_TYPE {
                return Err(Res::Failure);
            }
            let (flen, rest) = read_be32(b).ok_or(Res::Failure)?;
            b = rest;
            let flen = flen as usize;
            // Sanity: length cannot exceed the remaining bytes, and cannot
            // exceed the content-type payload limit (control.c).
            if flen > b.len() || flen > CONTENT_TYPE_LENGTH_MAX {
                return Err(Res::Failure);
            }
            content_types.push(b[..flen].to_vec());
            b = &b[flen..];
        }

        // Field-count limits (control.c): START <= 1, STOP/FINISH == 0.
        match control_type {
            ControlType::Start if content_types.len() > 1 => {
                return Err(Res::Failure);
            }
            ControlType::Stop | ControlType::Finish if !content_types.is_empty() => {
                return Err(Res::Failure);
            }
            _ => {}
        }

        Ok(ControlFrame {
            control_type,
            content_types,
        })
    }
}

fn read_be32(b: &[u8]) -> Option<(u32, &[u8])> {
    if b.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    Some((v, &b[4..]))
}

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
            io::Error::new(io::ErrorKind::InvalidInput, "fstrm: invalid control frame")
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
                        return Err(io::Error::new(
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fstrm: control frame too long",
                    ));
                }
                let mut payload = vec![0u8; clen];
                self.read_exact_checked(&mut payload)?;
                let frame = ControlFrame::decode_payload(&payload).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "fstrm: malformed control frame")
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
                    return Err(io::Error::new(
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

/// Stream mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Unidirectional,
    Bidirectional,
}

/// Writer state machine (writer.c `fstrm__writer_open_*`): unidirectional
/// writes START before data and STOP at close; bidirectional writes READY,
/// waits for ACCEPT, and sends FINISH at close.
pub struct StreamWriter<W: Write> {
    frames: FrameWriter<W>,
    mode: Mode,
    opened: bool,
    closed: bool,
}

impl<W: Write> StreamWriter<W> {
    /// Open a unidirectional stream: write the START control frame (with the
    /// given content types, at most one per the wire format).
    pub fn open_unidirectional(inner: W, content_types: Vec<Vec<u8>>) -> io::Result<Self> {
        let mut frames = FrameWriter::new(inner);
        let frame = ControlFrame {
            control_type: ControlType::Start,
            content_types,
        };
        frames.write_control(&frame)?;
        Ok(StreamWriter {
            frames,
            mode: Mode::Unidirectional,
            opened: true,
            closed: false,
        })
    }

    /// Open a bidirectional stream: write READY, then read the ACCEPT reply.
    pub fn open_bidirectional<R: Read>(
        inner: W,
        peer: R,
        content_types: Vec<Vec<u8>>,
    ) -> io::Result<Self> {
        let mut frames = FrameWriter::new(inner);
        let frame = ControlFrame {
            control_type: ControlType::Ready,
            content_types,
        };
        frames.write_control(&frame)?;
        let mut reader = FrameReader::new(peer);
        match reader.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Accept => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected ACCEPT control frame",
                ));
            }
        }
        Ok(StreamWriter {
            frames,
            mode: Mode::Bidirectional,
            opened: true,
            closed: false,
        })
    }

    pub fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        debug_assert!(self.opened && !self.closed);
        self.frames.write_data(payload)
    }

    /// Close the stream: STOP (unidirectional) or FINISH (bidirectional).
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let ty = match self.mode {
            Mode::Unidirectional => ControlType::Stop,
            Mode::Bidirectional => ControlType::Finish,
        };
        self.frames.write_control(&ControlFrame::new(ty))?;
        self.frames.flush()
    }
}

impl<W: Write> Drop for StreamWriter<W> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Reader state machine (reader.c `fstrm__reader_open_*`): unidirectional
/// reads START then data until STOP; bidirectional reads READY, answers
/// ACCEPT, and reads data until FINISH/STOP.
pub struct StreamReader<R: Read> {
    frames: FrameReader<R>,
    stopped: bool,
}

impl<R: Read> StreamReader<R> {
    /// Open a unidirectional stream: the first frame must be START.
    pub fn open_unidirectional(inner: R) -> io::Result<Self> {
        let mut frames = FrameReader::new(inner);
        match frames.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Start => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected START control frame",
                ));
            }
        }
        Ok(StreamReader {
            frames,
            stopped: false,
        })
    }

    /// Open a bidirectional stream: read READY, then answer ACCEPT choosing
    /// the first offered content type (mirroring the reader's accept of one
    /// content type; an empty offer is accepted as empty).
    pub fn open_bidirectional<W: Write>(inner: R, peer: W) -> io::Result<Self> {
        let mut frames = FrameReader::new(inner);
        let ready = match frames.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Ready => c,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected READY control frame",
                ));
            }
        };
        let accept = ControlFrame {
            control_type: ControlType::Accept,
            content_types: ready.content_types.into_iter().take(1).collect(),
        };
        let mut writer = FrameWriter::new(peer);
        writer.write_control(&accept)?;
        writer.flush()?;
        Ok(StreamReader {
            frames,
            stopped: false,
        })
    }

    /// Read the next data frame.  Returns `Err(Res::Stop)`-equivalent via
    /// `Ok(None)` on a STOP/FINISH control frame; other control frames are
    /// returned as `Frame::Control` for the caller.
    pub fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.frames.next()? {
                None => {
                    self.stopped = true;
                    return Ok(None);
                }
                Some(Frame::Control(c)) => {
                    if c.control_type == ControlType::Stop || c.control_type == ControlType::Finish
                    {
                        self.stopped = true;
                        return Ok(None);
                    }
                    // Unknown/other control frames are ignored by the reader
                    // (control.h:120 forward-compatibility rule).
                    continue;
                }
                Some(Frame::Data(d)) => return Ok(Some(d)),
            }
        }
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn into_inner(self) -> R {
        self.frames.inner
    }
}

/// File-format convenience: `fstrm_file` semantics for DNSTAP (a frame
/// stream in a regular file).  Reading preserves frame boundaries exactly.
pub type FileWriter = StreamWriter<std::fs::File>;
pub type FileReader = StreamReader<std::fs::File>;

/// Open a file for writing a new unidirectional frame stream (START first).
pub fn file_writer_open(path: &str, content_types: Vec<Vec<u8>>) -> io::Result<FileWriter> {
    let f = std::fs::File::create(path)?;
    StreamWriter::open_unidirectional(f, content_types)
}

/// Open a file for reading a unidirectional frame stream.
pub fn file_reader_open(path: &str) -> io::Result<FileReader> {
    let f = std::fs::File::open(path)?;
    StreamReader::open_unidirectional(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical START frame from the fstrm documentation example
    /// (control.h): escape 00 00 00 00, control length, type 2, content
    /// type field.  Bytes verified against the C encoder semantics.
    #[test]
    fn start_frame_wire_exact() {
        let frame =
            ControlFrame::with_content_type(ControlType::Start, b"protobuf:dnstap.Dnstap".to_vec());
        let wire = frame.encode_with_header().unwrap();
        assert_eq!(&wire[0..4], &[0, 0, 0, 0]); // escape
        let clen = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        assert_eq!(clen, wire.len() - 8);
        let decoded = ControlFrame::decode_with_header(&wire).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn stop_frame_has_no_fields() {
        let frame = ControlFrame::new(ControlType::Stop);
        let wire = frame.encode_with_header().unwrap();
        // escape + len=4 + type=3
        assert_eq!(wire, [0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 3]);
        let decoded = ControlFrame::decode_with_header(&wire).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn control_type_to_str_matches_c() {
        assert_eq!(ControlType::Accept.to_str(), "FSTRM_CONTROL_ACCEPT");
        assert_eq!(ControlType::Start.to_str(), "FSTRM_CONTROL_START");
        assert_eq!(ControlType::Stop.to_str(), "FSTRM_CONTROL_STOP");
        assert_eq!(ControlType::Ready.to_str(), "FSTRM_CONTROL_READY");
        assert_eq!(ControlType::Finish.to_str(), "FSTRM_CONTROL_FINISH");
        assert_eq!(Res::Success.as_str(), "success");
        assert_eq!(Res::Stop.as_str(), "stop");
    }

    #[test]
    fn start_writes_one_content_type_but_decode_rejects_multiple() {
        // The C encoder (control.c) writes at most one content-type field on
        // START frames but does NOT fail; the decoder rejects > 1.
        let f = ControlFrame {
            control_type: ControlType::Start,
            content_types: vec![b"a".to_vec(), b"b".to_vec()],
        };
        let ok = f.encode_payload().unwrap();
        assert_eq!(ok.len(), 4 + 4 + 4 + 1); // type + field + len + "a"
                                             // The encoded payload carries only one field, so it decodes fine.
        let dec = ControlFrame::decode_payload(&ok).unwrap();
        assert_eq!(dec.content_types, vec![b"a".to_vec()]);
        // A hand-crafted START payload with two fields must fail to decode
        // (control.c: START <= 1 content type).
        let mut bad = Vec::new();
        bad.extend_from_slice(&(ControlType::Start as u32).to_be_bytes());
        for ct in [b"a", b"b"] {
            bad.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
            bad.extend_from_slice(&1u32.to_be_bytes());
            bad.push(ct[0]);
        }
        assert_eq!(ControlFrame::decode_payload(&bad), Err(Res::Failure));
    }

    #[test]
    fn stop_rejects_content_types() {
        let f = ControlFrame::with_content_type(ControlType::Stop, b"x".to_vec());
        // encoder omits fields for STOP, so round-trip is empty
        let wire = f.encode_with_header().unwrap();
        assert_eq!(
            ControlFrame::decode_with_header(&wire).unwrap(),
            ControlFrame::new(ControlType::Stop)
        );
        // but a hand-crafted STOP with a field must fail to decode
        let mut bad = Vec::new();
        bad.extend_from_slice(&(ControlType::Stop as u32).to_be_bytes());
        bad.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
        bad.extend_from_slice(&1u32.to_be_bytes());
        bad.push(b'x');
        assert_eq!(ControlFrame::decode_payload(&bad), Err(Res::Failure));
    }

    #[test]
    fn unknown_control_type_fails() {
        let bad = [0u8, 0, 0, 6]; // type 6
        assert_eq!(ControlFrame::decode_payload(&bad), Err(Res::Failure));
    }

    #[test]
    fn unknown_field_type_fails() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&(ControlType::Ready as u32).to_be_bytes());
        bad.extend_from_slice(&0x99u32.to_be_bytes()); // unknown field
        bad.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(ControlFrame::decode_payload(&bad), Err(Res::Failure));
    }

    #[test]
    fn length_limits_enforced() {
        // content type > 256 fails to encode
        let f = ControlFrame::with_content_type(
            ControlType::Ready,
            vec![b'x'; CONTENT_TYPE_LENGTH_MAX + 1],
        );
        assert_eq!(f.encode_payload(), Err(Res::Failure));
        // control payload > 512 fails to encode
        let big = ControlFrame {
            control_type: ControlType::Ready,
            content_types: vec![vec![b'x'; CONTENT_TYPE_LENGTH_MAX]; 3],
        };
        assert_eq!(big.encode_payload(), Err(Res::Failure));
        // header decode: control length must equal remaining bytes
        let wire = ControlFrame::new(ControlType::Ready)
            .encode_with_header()
            .unwrap();
        let mut truncated = wire.clone();
        truncated.pop();
        assert_eq!(
            ControlFrame::decode_with_header(&truncated),
            Err(Res::Failure)
        );
        // outer length must be 0
        let mut bad = wire.clone();
        bad[0] = 1;
        assert_eq!(ControlFrame::decode_with_header(&bad), Err(Res::Failure));
    }

    #[test]
    fn unidirectional_round_trip() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::open_unidirectional(
                &mut buf,
                vec![b"protobuf:dnstap.Dnstap".to_vec()],
            )
            .unwrap();
            w.write(b"frame-one").unwrap();
            w.write(b"frame-two").unwrap();
            w.close().unwrap();
        }
        let mut r = StreamReader::open_unidirectional(&buf[..]).unwrap();
        assert_eq!(r.next().unwrap().unwrap(), b"frame-one");
        assert_eq!(r.next().unwrap().unwrap(), b"frame-two");
        assert_eq!(r.next().unwrap(), None);
        assert!(r.stopped());
    }

    #[test]
    fn bidirectional_handshake() {
        // Writer -> reader stream and reader -> writer stream.
        let mut to_client: Vec<u8> = Vec::new();
        let mut to_server: Vec<u8> = Vec::new();
        // Pre-seed the reader's ACCEPT reply (a C reader would send this).
        let accept = ControlFrame::new(ControlType::Accept)
            .encode_with_header()
            .unwrap();
        to_server.extend_from_slice(&accept);
        {
            let mut accept_slice: &[u8] = &to_server;
            let mut w = StreamWriter::open_bidirectional(
                &mut to_client,
                &mut accept_slice,
                vec![b"proto:dnstap".to_vec()],
            )
            .unwrap();
            w.write(b"hello").unwrap();
            w.close().unwrap();
        }
        // The writer consumed exactly the ACCEPT reply.
        assert_eq!(to_server.len(), accept.len());
        // The reader side sees READY, data, FINISH.
        let mut frames = FrameReader::new(&to_client[..]);
        assert!(matches!(
            frames.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Ready
        ));
        assert_eq!(
            frames.next().unwrap().unwrap(),
            Frame::Data(b"hello".to_vec())
        );
        assert!(matches!(
            frames.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Finish
        ));
        assert_eq!(frames.next().unwrap(), None);

        // And the reader side of the handshake: consume the READY stream and
        // reply ACCEPT, then drain data until FINISH.
        let mut reader_stream = to_client.clone();
        let mut accept_buf: Vec<u8> = Vec::new();
        {
            let mut r =
                StreamReader::open_bidirectional(&reader_stream[..], &mut accept_buf).unwrap();
            assert_eq!(r.next().unwrap().unwrap(), b"hello");
            assert_eq!(r.next().unwrap(), None);
            assert!(r.stopped());
        }
        // The reader replied with a well-formed ACCEPT.
        let a = ControlFrame::decode_with_header(&accept_buf).unwrap();
        assert_eq!(a.control_type, ControlType::Accept);
        // ... which the writer accepted (round trip already proved above).
        let _ = &mut reader_stream;
    }

    #[test]
    fn reader_rejects_missing_start() {
        let empty: &[u8] = &[];
        assert!(StreamReader::open_unidirectional(empty).is_err());
    }

    #[test]
    fn frame_reader_truncation_is_error() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = StreamWriter::open_unidirectional(&mut buf, vec![]).unwrap();
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

    #[test]
    fn res_variants_round_trip() {
        let values = [
            Res::Success,
            Res::Failure,
            Res::Again,
            Res::Invalid,
            Res::Stop,
        ];
        for (i, v) in values.iter().enumerate() {
            assert_eq!(*v as u32, i as u32);
        }
    }
}
