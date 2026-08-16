//! Stream state machines over generic byte streams, mirroring the C
//! writer.c/reader.c protocols on top of [`super::frame`].
//!
//! Unidirectional streams bracket data with START/STOP; bidirectional
//! streams perform the full handshake: writer sends READY (all its content
//! types), reader replies ACCEPT (its matching content types), writer sends
//! START (the matched content type), then data, then STOP, and the reader
//! answers FINISH (reader.c closes with a FINISH; writer.c closes with STOP
//! then waits for FINISH).

use super::{io_err, ControlFrame, ControlType, Frame, FrameReader, FrameWriter, Res};
use std::io::{self, Empty, Read, Sink, Write};

/// Stream mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Unidirectional,
    Bidirectional,
}

/// Writer state machine (writer.c `fstrm__writer_open_*`): unidirectional
/// writes START before data and STOP at close; bidirectional writes READY,
/// waits for ACCEPT, writes START, and at close writes STOP then waits for
/// FINISH.
pub struct StreamWriter<W: Write, R: Read = Empty> {
    frames: FrameWriter<W>,
    peer: R,
    mode: Mode,
    opened: bool,
    closed: bool,
}

impl<W: Write, R: Read> StreamWriter<W, R> {
    /// Open a unidirectional stream: write the START control frame with the
    /// first content type (writer.c `fstrm__writer_open_unidirectional`:
    /// `fs_bufvec_value(w->content_types, 0)`; empty set → START with no
    /// content type).
    pub fn open_unidirectional(mut inner: W, content_types: Vec<Vec<u8>>) -> io::Result<Self>
    where
        R: Default,
    {
        let ct = content_types.into_iter().take(1).collect();
        let frame = ControlFrame {
            control_type: ControlType::Start,
            content_types: ct,
        };
        FrameWriter::new(&mut inner).write_control(&frame)?;
        Ok(StreamWriter {
            frames: FrameWriter::new(inner),
            peer: R::default(),
            mode: Mode::Unidirectional,
            opened: true,
            closed: false,
        })
    }

    /// Open a bidirectional stream: write READY (all content types), wait for
    /// the ACCEPT reply, and match our content types against it exactly like
    /// `fstrm__writer_open_bidirectional` (writer.c): an ACCEPT with no
    /// content-type fields matches the first offered type; an empty offer is
    /// accepted as empty; an offer that matches nothing fails the open.  The
    /// START frame carries the matched content type.
    pub fn open_bidirectional(
        mut inner: W,
        mut peer: R,
        content_types: Vec<Vec<u8>>,
    ) -> io::Result<Self> {
        let ready = ControlFrame {
            control_type: ControlType::Ready,
            content_types: content_types.clone(),
        };
        FrameWriter::new(&mut inner).write_control(&ready)?;

        let mut reader = FrameReader::new(&mut peer);
        let accept = match reader.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Accept => c,
            _ => {
                return Err(io_err(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected ACCEPT control frame",
                ));
            }
        };

        // fstrm_control_match_field_content_type semantics: an ACCEPT with no
        // fields matches the first offered type (control.c: n_ctype == 0
        // succeeds); otherwise the match must be exact.
        let matched = if content_types.is_empty() {
            None
        } else if accept.content_types.is_empty() {
            content_types.first().cloned()
        } else {
            let m = content_types
                .iter()
                .find(|ct| accept.content_types.iter().any(|a| a == *ct))
                .cloned();
            if m.is_none() {
                return Err(io_err(
                    io::ErrorKind::InvalidData,
                    "fstrm: content type negotiation failed",
                ));
            }
            m
        };

        let start = ControlFrame {
            control_type: ControlType::Start,
            content_types: matched.into_iter().collect(),
        };
        FrameWriter::new(&mut inner).write_control(&start)?;

        Ok(StreamWriter {
            frames: FrameWriter::new(inner),
            peer,
            mode: Mode::Bidirectional,
            opened: true,
            closed: false,
        })
    }

    pub fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        debug_assert!(self.opened && !self.closed);
        self.frames.write_data(payload)
    }

    /// Close the stream (writer.c `fstrm_writer_close`): write STOP, then
    /// for bidirectional streams wait for the FINISH reply, then flush.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.frames
            .write_control(&ControlFrame::new(ControlType::Stop))?;
        if self.mode == Mode::Bidirectional {
            let mut reader = FrameReader::new(&mut self.peer);
            match reader.next()? {
                Some(Frame::Control(c)) if c.control_type == ControlType::Finish => {}
                _ => {
                    return Err(io_err(
                        io::ErrorKind::InvalidData,
                        "fstrm: expected FINISH control frame",
                    ));
                }
            }
        }
        self.frames.flush()
    }
}

impl<W: Write, R: Read> Drop for StreamWriter<W, R> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Reader state machine (reader.c `fstrm__reader_open_*`): unidirectional
/// reads START then data until STOP; bidirectional reads READY, answers
/// ACCEPT (this generic layer has no configured content types, so, exactly
/// like a C reader with an empty option set, it accepts any offer and echoes
/// no content types), reads START, and at close writes FINISH.
pub struct StreamReader<R: Read, W: Write = Sink> {
    frames: FrameReader<R>,
    peer: W,
    stopped: bool,
}

impl<R: Read, W: Write> StreamReader<R, W> {
    /// Open a unidirectional stream: the first frame must be START.
    pub fn open_unidirectional(mut inner: R) -> io::Result<Self>
    where
        W: Default,
    {
        let mut frames = FrameReader::new(&mut inner);
        match frames.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Start => {}
            _ => {
                return Err(io_err(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected START control frame",
                ));
            }
        }
        Ok(StreamReader {
            frames: FrameReader::new(inner),
            peer: W::default(),
            stopped: false,
        })
    }

    /// Open a bidirectional stream: read READY, then answer ACCEPT with no
    /// content-type fields (the reader has no configured types, so every
    /// offer is accepted — reader.c `fstrm__reader_open_bidirectional` with
    /// an empty `content_types` set), then require START.
    pub fn open_bidirectional(mut inner: R, mut peer: W) -> io::Result<Self> {
        let mut frames = FrameReader::new(&mut inner);
        let ready = match frames.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Ready => c,
            _ => {
                return Err(io_err(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected READY control frame",
                ));
            }
        };
        let _ = &ready;
        let accept = ControlFrame::new(ControlType::Accept);
        let mut writer = FrameWriter::new(&mut peer);
        writer.write_control(&accept)?;
        writer.flush()?;

        match frames.next()? {
            Some(Frame::Control(c)) if c.control_type == ControlType::Start => {}
            _ => {
                return Err(io_err(
                    io::ErrorKind::InvalidData,
                    "fstrm: expected START control frame",
                ));
            }
        }
        Ok(StreamReader {
            frames: FrameReader::new(inner),
            peer,
            stopped: false,
        })
    }

    /// Read the next data frame.  Returns `Ok(None)` on a STOP/FINISH
    /// control frame (reader.c `fstrm__reader_next_data` returns
    /// `fstrm_res_stop` on STOP); other control frames are skipped per the
    /// forward-compatibility rule (control.h:120).
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
                    continue;
                }
                Some(Frame::Data(d)) => return Ok(Some(d)),
            }
        }
    }

    /// Close the stream (reader.c `fstrm_reader_close`): for bidirectional
    /// streams write the FINISH control frame.
    pub fn close(&mut self) -> io::Result<()> {
        let mut writer = FrameWriter::new(&mut self.peer);
        writer.write_control(&ControlFrame::new(ControlType::Finish))?;
        writer.flush()
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }
}

impl<R: Read, W: Write> Drop for StreamReader<R, W> {
    fn drop(&mut self) {
        let _ = self.close();
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

/// Map a `Res`-style failure into an `io::Error` for the state machine
/// helpers above.
fn _res_err(_: Res) -> io::Error {
    io_err(io::ErrorKind::Other, "fstrm: protocol failure")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unidirectional_round_trip() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w: StreamWriter<&mut Vec<u8>> = StreamWriter::open_unidirectional(
                &mut buf,
                vec![b"protobuf:dnstap.Dnstap".to_vec()],
            )
            .unwrap();
            w.write(b"frame-one").unwrap();
            w.write(b"frame-two").unwrap();
            w.close().unwrap();
        }
        let mut r: StreamReader<&[u8]> = StreamReader::open_unidirectional(&buf[..]).unwrap();
        assert_eq!(r.next().unwrap().unwrap(), b"frame-one");
        assert_eq!(r.next().unwrap().unwrap(), b"frame-two");
        assert_eq!(r.next().unwrap(), None);
        assert!(r.stopped());
    }

    #[test]
    fn bidirectional_handshake() {
        // Writer -> reader stream and reader -> writer stream.  The writer
        // side consumes the ACCEPT reply at open and the FINISH reply at
        // close, so the peer stream must be pre-seeded with both.
        let mut to_client: Vec<u8> = Vec::new();
        let mut seed: Vec<u8> = Vec::new();
        seed.extend_from_slice(
            &ControlFrame::new(ControlType::Accept)
                .encode_with_header()
                .unwrap(),
        );
        seed.extend_from_slice(
            &ControlFrame::new(ControlType::Finish)
                .encode_with_header()
                .unwrap(),
        );
        {
            let mut seed_slice: &[u8] = &seed;
            let mut w = StreamWriter::open_bidirectional(
                &mut to_client,
                &mut seed_slice,
                vec![b"proto:dnstap".to_vec()],
            )
            .unwrap();
            w.write(b"hello").unwrap();
            w.close().unwrap();
            drop(w);
            // The writer consumed exactly the ACCEPT and FINISH replies.
            assert!(seed_slice.is_empty());
        }
        // The writer's wire: READY, START, data, STOP.
        let mut frames = FrameReader::new(&to_client[..]);
        assert!(matches!(
            frames.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Ready
        ));
        assert!(matches!(
            frames.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Start
        ));
        assert_eq!(
            frames.next().unwrap().unwrap(),
            Frame::Data(b"hello".to_vec())
        );
        assert!(matches!(
            frames.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Stop
        ));
        assert_eq!(frames.next().unwrap(), None);

        // The reader side of the handshake: consume the writer's stream and
        // reply ACCEPT + FINISH.
        let mut reader_stream = to_client.clone();
        let mut accept_buf: Vec<u8> = Vec::new();
        {
            let mut r =
                StreamReader::open_bidirectional(&reader_stream[..], &mut accept_buf).unwrap();
            assert_eq!(r.next().unwrap().unwrap(), b"hello");
            assert_eq!(r.next().unwrap(), None);
            assert!(r.stopped());
        }
        // The reader replied ACCEPT (empty — no configured content types)
        // and FINISH.
        let mut frames2 = FrameReader::new(&accept_buf[..]);
        assert!(matches!(
            frames2.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Accept
        ));
        assert!(matches!(
            frames2.next().unwrap().unwrap(),
            Frame::Control(c) if c.control_type == ControlType::Finish
        ));
        assert_eq!(frames2.next().unwrap(), None);
        let _ = &mut reader_stream;
    }

    #[test]
    fn bidirectional_accept_with_content_types_matches() {
        // A peer that echoes a content type must match the offered set; a
        // peer that echoes a non-offered type must fail the open.
        let mut to_client: Vec<u8> = Vec::new();
        let mut seed: Vec<u8> = Vec::new();
        seed.extend_from_slice(
            &ControlFrame::with_content_type(ControlType::Accept, b"proto:dnstap".to_vec())
                .encode_with_header()
                .unwrap(),
        );
        seed.extend_from_slice(
            &ControlFrame::new(ControlType::Finish)
                .encode_with_header()
                .unwrap(),
        );
        let mut seed_slice: &[u8] = &seed;
        let mut w = StreamWriter::open_bidirectional(
            &mut to_client,
            &mut seed_slice,
            vec![b"proto:dnstap".to_vec()],
        )
        .unwrap();
        w.close().unwrap();

        // Non-matching offer: ACCEPT carries "proto:other".
        let mut to_client2: Vec<u8> = Vec::new();
        let mut seed2: Vec<u8> = Vec::new();
        seed2.extend_from_slice(
            &ControlFrame::with_content_type(ControlType::Accept, b"proto:other".to_vec())
                .encode_with_header()
                .unwrap(),
        );
        let mut seed2_slice: &[u8] = &seed2;
        assert!(StreamWriter::open_bidirectional(
            &mut to_client2,
            &mut seed2_slice,
            vec![b"proto:dnstap".to_vec()]
        )
        .is_err());
    }

    #[test]
    fn reader_rejects_missing_start() {
        let empty: &[u8] = &[];
        let r: Result<StreamReader<&[u8]>, _> = StreamReader::open_unidirectional(empty);
        assert!(r.is_err());
    }
}
