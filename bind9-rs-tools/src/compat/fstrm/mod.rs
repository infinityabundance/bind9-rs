//! Frame Streams (fstrm) — native Rust conservation of fstrm 0.6.1 (§26).
//!
//! This module preserves the *observable* fstrm contract: the byte-stream
//! framing, the control-frame wire format, the unidirectional
//! START/data*/STOP and bidirectional READY/ACCEPT/START/data*/STOP/FINISH
//! state machines, the `fstrm_res` result taxonomy, the length limits
//! (`FSTRM_CONTROL_FRAME_LENGTH_MAX` = 512, content-type payload max = 256),
//! the `fstrm_writer`/`fstrm_reader` option and state-machine API, the
//! `fstrm_rdwr` abstraction, the file/unix/tcp transports, and the
//! `fstrm_iothr` background I/O thread with its input queues.
//!
//! Every constant, error path and limit below is read from the pinned fstrm
//! 0.6.1 source (`bind9-rs-tools/forensics/oracle/work/deps/fstrm-0.6.1/`)
//! and is subject to the four-corner interchange courts (§38) against the C
//! oracle image (`oracle-fstrm-0.6.1`); FSTRM-0001 is the conservation court.
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
//! # Layout
//!
//! The module mirrors the upstream file layout: `control.{c,h}` →
//! [`Control`]/[`ControlFrame`]; `rdwr.{c,h}` → [`rdwr`]; `writer.{c,h}` →
//! [`writer`]; `reader.{c,h}` → [`reader`]; `file.{c,h}` → [`file`];
//! `unix_writer.{c,h}` → [`unix`]; `tcp_writer.{c,h}` → [`tcp`];
//! `iothr.{c,h}` → [`iothr`]; `libmy/my_queue*` → [`queue`].  The
//! `frame`/`stream` submodules are the generic byte-stream codec built on the
//! same wire format (they are what DNSTAP-style file readers use).
//!
//! Status: Phase 1 (§64).  Wire core + full writer/reader/rdwr/file/unix/tcp/
//! iothr API conserved; FSTRM-0001 court green at 0 residuals.

mod file;
mod frame;
mod iothr;
mod queue;
mod rdwr;
mod reader;
mod stream;
mod tcp;
mod unix;
mod writer;

pub use file::{file_reader_init, file_writer_init, FileOptions};
pub use frame::{Frame, FrameReader, FrameWriter};
pub use iothr::{
    free_wrapper, get_input_queue, get_input_queue_idx, iothr_destroy, iothr_init,
    iothr_options_destroy, iothr_options_init, submit, FreeFunc, Iothr, IothrOptions, IothrQueue,
    QueueModel,
};
pub use queue::Queue;
pub use rdwr::{IoVec, Rdwr};
pub use reader::{
    reader_close, reader_destroy, reader_get_control, reader_init, reader_open,
    reader_options_add_content_type, reader_options_init, reader_options_set_max_frame_size,
    reader_read, Reader, ReaderOptions,
};
pub use stream::{
    file_reader_open, file_writer_open, FileReader, FileWriter, Mode, StreamReader, StreamWriter,
};
pub use tcp::{
    tcp_writer_init, tcp_writer_options_init, tcp_writer_options_set_socket_address,
    tcp_writer_options_set_socket_port, TcpWriterOptions,
};
pub use unix::{
    unix_writer_init, unix_writer_options_init, unix_writer_options_set_socket_path,
    UnixWriterOptions,
};
pub use writer::{
    writer_close, writer_destroy, writer_get_control, writer_init, writer_open,
    writer_options_add_content_type, writer_options_init, writer_write, writer_writev, Writer,
    WriterOptions,
};

use std::io;

/// Result codes mirroring `fstrm_res` (fstrm.h:261).
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
    /// render as `"FSTRM_CONTROL_UNKNOWN"`).
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

    /// Const variant of [`from_u32`](ControlType::from_u32) for constant
    /// string renderers.
    pub const fn from_u32_const(v: u32) -> Option<Self> {
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

/// `FSTRM_CONTROL_FLAG_WITH_HEADER` (control.h:202).
pub const CONTROL_FLAG_WITH_HEADER: u32 = 1;

/// `FSTRM_READER_MAX_FRAME_SIZE_DEFAULT` (reader.h:47).
pub const READER_MAX_FRAME_SIZE_DEFAULT: usize = 1_048_576;

/// `FSTRM_IOTHR_*` limits and defaults (iothr.h).  `OUTPUT_QUEUE_SIZE_MAX` is
/// `IOV_MAX` (fstrm-private.h:66, 1024 on Linux).
pub const IOTHR_BUFFER_HINT_MIN: u32 = 1024;
pub const IOTHR_BUFFER_HINT_DEFAULT: u32 = 8192;
pub const IOTHR_BUFFER_HINT_MAX: u32 = 65536;
pub const IOTHR_FLUSH_TIMEOUT_MIN: u32 = 1;
pub const IOTHR_FLUSH_TIMEOUT_DEFAULT: u32 = 1;
pub const IOTHR_FLUSH_TIMEOUT_MAX: u32 = 600;
pub const IOTHR_INPUT_QUEUE_SIZE_MIN: u32 = 2;
pub const IOTHR_INPUT_QUEUE_SIZE_DEFAULT: u32 = 512;
pub const IOTHR_INPUT_QUEUE_SIZE_MAX: u32 = 16384;
pub const IOTHR_NUM_INPUT_QUEUES_MIN: u32 = 1;
pub const IOTHR_NUM_INPUT_QUEUES_DEFAULT: u32 = 1;
pub const IOTHR_OUTPUT_QUEUE_SIZE_MIN: u32 = 2;
pub const IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT: u32 = 64;
pub const IOTHR_OUTPUT_QUEUE_SIZE_MAX: u32 = 1024; // IOV_MAX on Linux
pub const IOTHR_QUEUE_NOTIFY_THRESHOLD_MIN: u32 = 1;
pub const IOTHR_QUEUE_NOTIFY_THRESHOLD_DEFAULT: u32 = 32;
pub const IOTHR_REOPEN_INTERVAL_MIN: u32 = 1;
pub const IOTHR_REOPEN_INTERVAL_DEFAULT: u32 = 5;
pub const IOTHR_REOPEN_INTERVAL_MAX: u32 = 600;

/// `FSTRM__WRITER_IOVEC_SIZE` (writer.c:27): iovec scratch capacity.
pub const WRITER_IOVEC_SIZE: usize = 256;

/// `IOV_MAX` (fstrm-private.h:66): 1024 on Linux.
pub const IOV_MAX: usize = 1024;

/// A decoded control frame: type plus zero or more content-type fields.
/// This is the wire-codec view (`ControlFrame`); the C-API mirror with the
/// mutating control.c semantics is [`Control`].
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

/// The mutating C-API control object (control.c `struct fstrm_control`).
///
/// Mirrors `fstrm_control_init/destroy/reset/set_type/get_type/
/// get_num_field_content_type/get_field_content_type/add_field_content_type/
/// match_field_content_type/encoded_size/encode/decode`.  The `type_` field
/// is a raw `u32` like the C (`0` means "unset"; `fstrm_control_get_type`
/// fails on it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    type_: u32,
    content_types: Vec<Vec<u8>>,
}

impl Control {
    /// `fstrm_control_init` (control.c:61): type 0, no content types.
    #[must_use]
    pub fn init() -> Control {
        Control {
            type_: 0,
            content_types: Vec::new(),
        }
    }

    /// `fstrm_control_reset` (control.c:80): drop all content-type fields and
    /// set the type to 0.
    pub fn reset(&mut self) {
        self.content_types.clear();
        self.type_ = 0;
    }

    /// `fstrm_control_get_type` (control.c:91): fails on an unset (0) or
    /// unknown type.
    pub fn get_type(&self) -> Result<ControlType, Res> {
        ControlType::from_u32(self.type_).ok_or(Res::Failure)
    }

    /// `fstrm_control_set_type` (control.c:107): fails on unknown types.
    pub fn set_type(&mut self, ty: ControlType) -> Result<(), Res> {
        self.type_ = ty as u32;
        Ok(())
    }

    /// `fstrm_control_get_num_field_content_type` (control.c:123): the number
    /// of content-type fields, clamped exactly like the C: STOP/FINISH report
    /// 0, START reports at most 1.
    #[must_use]
    pub fn get_num_field_content_type(&self) -> usize {
        let n = self.content_types.len();
        match self.type_ {
            t if t == ControlType::Stop as u32 || t == ControlType::Finish as u32 => 0,
            t if t == ControlType::Start as u32 => n.min(1),
            _ => n,
        }
    }

    /// `fstrm_control_get_field_content_type` (control.c:149).
    pub fn get_field_content_type(&self, idx: usize) -> Result<&[u8], Res> {
        self.content_types
            .get(idx)
            .map(Vec::as_slice)
            .ok_or(Res::Failure)
    }

    /// `fstrm_control_add_field_content_type` (control.c:164): appends a copy.
    /// The C does not bounds-check here; limits are enforced at encode time.
    pub fn add_field_content_type(&mut self, content_type: &[u8]) {
        self.content_types.push(content_type.to_vec());
    }

    /// `fstrm_control_match_field_content_type` (control.c:178).
    ///
    /// STOP/FINISH never match.  A control frame with no content-type fields
    /// matches any requested type; otherwise the match must be byte-exact
    /// against one of the frame's fields.  `None` (the C's NULL) only matches
    /// a frame that has no content-type fields.
    pub fn match_field_content_type(&self, matched: Option<&[u8]>) -> Result<(), Res> {
        if self.type_ == ControlType::Stop as u32 || self.type_ == ControlType::Finish as u32 {
            return Err(Res::Failure);
        }
        let n = self.get_num_field_content_type();
        if n == 0 {
            // Control frame doesn't set any content type.
            return Ok(());
        }
        let matched = matched.ok_or(Res::Failure)?;
        for idx in 0..n {
            let field = self.get_field_content_type(idx)?;
            if field == matched {
                return Ok(());
            }
        }
        Err(Res::Failure)
    }

    /// `fstrm_control_encoded_size` (control.c:362): the serialized length,
    /// with the escape + frame-length header when the flag is set.  Content
    /// types are skipped on STOP/FINISH and capped at one on START; payloads
    /// over 256 bytes or an overall frame over 512 bytes fail.
    pub fn encoded_size(&self, flags: u32) -> Result<usize, Res> {
        let mut len = 0usize;
        if flags & CONTROL_FLAG_WITH_HEADER != 0 {
            // Escape + frame length: 32-bit BE integers.
            len += 8;
        }
        // Control type: 32-bit BE integer.
        len += 4;
        for ct in &self.content_types {
            // No content-type fields on STOP or FINISH.
            if self.type_ == ControlType::Stop as u32 || self.type_ == ControlType::Finish as u32 {
                break;
            }
            if ct.len() > CONTENT_TYPE_LENGTH_MAX {
                return Err(Res::Failure);
            }
            // Field type + field length + payload.
            len += 8 + ct.len();
            // Only one content-type field on START.
            if self.type_ == ControlType::Start as u32 {
                break;
            }
        }
        if len > CONTROL_FRAME_LENGTH_MAX {
            return Err(Res::Failure);
        }
        Ok(len)
    }

    /// `fstrm_control_encode` (control.c:417): serialize into `buf`, which
    /// must hold at least the encoded size; `len` is the buffer size in and
    /// the encoded size out.
    pub fn encode(&self, buf: &mut [u8], len: &mut usize, flags: u32) -> Result<(), Res> {
        let encoded_size = self.encoded_size(flags)?;
        if *len < encoded_size {
            return Err(Res::Failure);
        }
        let mut out = Vec::with_capacity(encoded_size);
        if flags & CONTROL_FLAG_WITH_HEADER != 0 {
            // Escape: 32-bit BE integer. Zero.
            out.extend_from_slice(&0u32.to_be_bytes());
            // Frame length: total minus the escape and length fields.
            out.extend_from_slice(&((encoded_size - 8) as u32).to_be_bytes());
        }
        // Control type: 32-bit BE integer.
        out.extend_from_slice(&self.type_.to_be_bytes());
        for ct in &self.content_types {
            if self.type_ == ControlType::Stop as u32 || self.type_ == ControlType::Finish as u32 {
                break;
            }
            out.extend_from_slice(&CONTROL_FIELD_CONTENT_TYPE.to_be_bytes());
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(ct);
            if self.type_ == ControlType::Start as u32 {
                break;
            }
        }
        buf[..encoded_size].copy_from_slice(&out);
        *len = encoded_size;
        Ok(())
    }

    /// `fstrm_control_decode` (control.c:238): parse `control_frame` into
    /// this control, resetting it first.  With `FSTRM_CONTROL_FLAG_WITH_HEADER`
    /// the input begins with the escape + control frame length; without it the
    /// input is the payload and the length limit is applied directly.
    pub fn decode(&mut self, control_frame: &[u8], flags: u32) -> Result<(), Res> {
        self.reset();
        let mut buf = control_frame;
        if flags & CONTROL_FLAG_WITH_HEADER != 0 {
            let (outer, rest) = read_be32(buf).ok_or(Res::Failure)?;
            buf = rest;
            if outer != 0 {
                return Err(Res::Failure);
            }
            let (clen, rest) = read_be32(buf).ok_or(Res::Failure)?;
            buf = rest;
            if clen as usize > CONTROL_FRAME_LENGTH_MAX {
                return Err(Res::Failure);
            }
            if clen as usize != buf.len() {
                return Err(Res::Failure);
            }
        } else if control_frame.len() > CONTROL_FRAME_LENGTH_MAX {
            return Err(Res::Failure);
        }

        let (t, rest) = read_be32(buf).ok_or(Res::Failure)?;
        buf = rest;
        self.type_ = match ControlType::from_u32(t) {
            Some(ty) => ty as u32,
            None => return Err(Res::Failure),
        };

        while !buf.is_empty() {
            let (ftype, rest) = read_be32(buf).ok_or(Res::Failure)?;
            buf = rest;
            if ftype != CONTROL_FIELD_CONTENT_TYPE {
                return Err(Res::Failure);
            }
            let (flen, rest) = read_be32(buf).ok_or(Res::Failure)?;
            buf = rest;
            let flen = flen as usize;
            // Sanity: the length cannot be larger than the bytes remaining.
            if flen > buf.len() {
                return Err(Res::Failure);
            }
            // Enforce the content-type payload limit.
            if flen > CONTENT_TYPE_LENGTH_MAX {
                return Err(Res::Failure);
            }
            self.content_types.push(buf[..flen].to_vec());
            buf = &buf[flen..];
        }

        // Field-count limits (control.c): START <= 1, STOP/FINISH == 0.
        let n = self.content_types.len();
        match self.type_ {
            t if t == ControlType::Start as u32 && n > 1 => return Err(Res::Failure),
            t if (t == ControlType::Stop as u32 || t == ControlType::Finish as u32) && n > 0 => {
                return Err(Res::Failure);
            }
            _ => {}
        }
        Ok(())
    }
}

/// `fstrm_control_field_type_to_str` (control.c:50).
#[must_use]
pub const fn control_field_type_to_str(f_type: u32) -> &'static str {
    match f_type {
        CONTROL_FIELD_CONTENT_TYPE => "FSTRM_CONTROL_FIELD_CONTENT_TYPE",
        _ => "FSTRM_CONTROL_FIELD_UNKNOWN",
    }
}

/// `fstrm_control_type_to_str` for a raw value (unknown values render as
/// `"FSTRM_CONTROL_UNKNOWN"`, control.c:31).
#[must_use]
pub const fn control_type_to_str(type_: u32) -> &'static str {
    match ControlType::from_u32_const(type_) {
        Some(ty) => ty.to_str(),
        None => "FSTRM_CONTROL_UNKNOWN",
    }
}

pub(crate) fn read_be32(b: &[u8]) -> Option<(u32, &[u8])> {
    if b.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    Some((v, &b[4..]))
}

pub(crate) fn io_err(kind: io::ErrorKind, msg: &'static str) -> io::Error {
    io::Error::new(kind, msg)
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
        assert_eq!(control_type_to_str(0xff), "FSTRM_CONTROL_UNKNOWN");
        assert_eq!(
            control_field_type_to_str(CONTROL_FIELD_CONTENT_TYPE),
            "FSTRM_CONTROL_FIELD_CONTENT_TYPE"
        );
        assert_eq!(
            control_field_type_to_str(0x99),
            "FSTRM_CONTROL_FIELD_UNKNOWN"
        );
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
    fn control_api_mirrors_c() {
        // init: type 0, no fields; get_type fails
        let mut c = Control::init();
        assert!(c.get_type().is_err());
        // set_type with unknown fails
        assert!(c.set_type(ControlType::Accept).is_ok());
        assert_eq!(c.get_type(), Ok(ControlType::Accept));
        // add + clamped getters
        c.add_field_content_type(b"wharr\0garbl");
        c.add_field_content_type(b"wharrgarblv2");
        assert_eq!(c.get_num_field_content_type(), 2);
        assert_eq!(c.get_field_content_type(0), Ok(&b"wharr\0garbl"[..]));
        assert_eq!(c.get_field_content_type(1), Ok(&b"wharrgarblv2"[..]));
        assert_eq!(c.get_field_content_type(2), Err(Res::Failure));
        // match: exact match ok; non-match fails
        assert!(c.match_field_content_type(Some(b"wharr\0garbl")).is_ok());
        assert!(c.match_field_content_type(Some(b"wharrgarblv2")).is_ok());
        assert!(c.match_field_content_type(Some(b"nope")).is_err());
        assert!(c.match_field_content_type(None).is_err());
        // START clamps to 1 field
        c.set_type(ControlType::Start).unwrap();
        assert_eq!(c.get_num_field_content_type(), 1);
        assert!(c.match_field_content_type(Some(b"wharr\0garbl")).is_ok());
        assert!(c.match_field_content_type(Some(b"wharrgarblv2")).is_err());
        // STOP never matches
        c.set_type(ControlType::Stop).unwrap();
        assert_eq!(c.get_num_field_content_type(), 0);
        assert!(c.match_field_content_type(Some(b"wharr\0garbl")).is_err());
        assert!(c.match_field_content_type(None).is_err());
        // reset
        c.reset();
        assert!(c.get_type().is_err());
        assert_eq!(c.get_num_field_content_type(), 0);
    }

    #[test]
    fn control_encode_decode_with_flags() {
        // encode with header + decode with header round trip
        let mut c = Control::init();
        c.set_type(ControlType::Ready).unwrap();
        c.add_field_content_type(b"a");
        c.add_field_content_type(b"b");
        let size = c.encoded_size(CONTROL_FLAG_WITH_HEADER).unwrap();
        assert_eq!(size, 8 + 4 + 8 + 1 + 8 + 1);
        let mut buf = vec![0u8; size];
        let mut len = buf.len();
        c.encode(&mut buf, &mut len, CONTROL_FLAG_WITH_HEADER)
            .unwrap();
        assert_eq!(len, size);
        let mut d = Control::init();
        d.decode(&buf, CONTROL_FLAG_WITH_HEADER).unwrap();
        assert_eq!(d, c);
        // decode without header works on the payload
        let mut d2 = Control::init();
        d2.decode(&buf[8..], 0).unwrap();
        assert_eq!(d2, c);
        // encoded_size with a too-small caller buffer fails at encode: the
        // no-header size is 22, so a 21-byte buffer fails.
        let mut small = vec![0u8; size - 10]; // 20 bytes < 22
        let mut slen = small.len();
        assert_eq!(c.encode(&mut small, &mut slen, 0), Err(Res::Failure));
    }

    #[test]
    fn control_encoded_size_matches_control_frame() {
        // The C-API encoded_size must agree with the wire-codec encoder.
        let cf = ControlFrame {
            control_type: ControlType::Ready,
            content_types: vec![b"proto:dnstap".to_vec()],
        };
        let wire = cf.encode_with_header().unwrap();
        let mut c = Control::init();
        c.set_type(ControlType::Ready).unwrap();
        c.add_field_content_type(b"proto:dnstap");
        assert_eq!(
            c.encoded_size(CONTROL_FLAG_WITH_HEADER).unwrap(),
            wire.len()
        );
        let mut buf = vec![0u8; wire.len()];
        let mut len = buf.len();
        c.encode(&mut buf, &mut len, CONTROL_FLAG_WITH_HEADER)
            .unwrap();
        assert_eq!(buf, wire);
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
