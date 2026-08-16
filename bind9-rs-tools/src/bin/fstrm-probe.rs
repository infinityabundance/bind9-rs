//! fstrm-probe — Rust mirror of `forensics/oracle/probes/probe-fstrm.c` for
//! the FSTRM-0001 court (§26, §37).  Runs in the same oracle-fstrm-0.6.1
//! container; stdout must be byte-identical to the C probe.
//!
//! Usage: fstrm-probe

use bind9_rs_tools::compat::fstrm::*;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const WORK: &str = "/tmp/fstrm_work";

/* ------------------------------------------------------------------ utils */

fn print_string(data: &[u8]) {
    print!("\"");
    for &c in data {
        if (0x20..=0x7e).contains(&c) {
            if c == b'"' {
                print!("\\\"");
            } else {
                print!("{}", c as char);
            }
        } else {
            print!("\\x{c:02x}");
        }
    }
    print!("\"");
}

fn dump(p: &[u8]) {
    for b in p {
        print!("{b:02x}");
    }
}

fn res_str(res: Res) -> &'static str {
    res.as_str()
}

fn print_res(what: &str, res: Res) {
    println!("  {what} -> {} ({})", res as u32, res_str(res));
}

fn mkwork() {
    let _ = std::fs::create_dir_all(WORK);
}

/* ------------------------------------------- control corpus (test_control.c) */

const WHARRGARBL: &[u8] = b"wharr\x00garbl";
const WHARRGARBLV2: &[u8] = b"wharrgarblv2";

const ACCEPT_1: &[u8] = &[0x00, 0x00, 0x00, 0x01];
const ACCEPT_1_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
];
const ACCEPT_2: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r',
    b'r', 0x00, b'g', b'a', b'r', b'b', b'l',
];
const ACCEPT_2_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r', b'r', 0x00, b'g', b'a', b'r', b'b', b'l',
];
const ACCEPT_3: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r',
    b'r', 0x00, b'g', b'a', b'r', b'b', b'l', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, b'w',
    b'h', b'a', b'r', b'r', b'g', b'a', b'r', b'b', b'l', b'v', b'2',
];
const ACCEPT_3_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r', b'r', 0x00, b'g', b'a', b'r', b'b', b'l', 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, b'w', b'h', b'a', b'r', b'r', b'g', b'a', b'r', b'b',
    b'l', b'v', b'2',
];
const READY_1: &[u8] = &[
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r',
    b'r', 0x00, b'g', b'a', b'r', b'b', b'l', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, b'w',
    b'h', b'a', b'r', b'r', b'g', b'a', b'r', b'b', b'l', b'v', b'2',
];
const START_1: &[u8] = &[0x00, 0x00, 0x00, 0x02];
const START_1_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
];
const START_2: &[u8] = &[
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r',
    b'r', 0x00, b'g', b'a', b'r', b'b', b'l',
];
const START_2_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a', b'r', b'r', 0x00, b'g', b'a', b'r', b'b', b'l',
];
const STOP_1: &[u8] = &[0x00, 0x00, 0x00, 0x03];
const STOP_1_WH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
];

struct ControlTest {
    frame: &'static [u8],
    ty: u32,
    flags: u32,
    ct: Option<&'static [u8]>,
    match_res: Res,
}

const CONTROL_TESTS: &[ControlTest] = &[
    ControlTest {
        frame: ACCEPT_1,
        ty: 0x01,
        flags: 0,
        ct: None,
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_1_WH,
        ty: 0x01,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: None,
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_2,
        ty: 0x01,
        flags: 0,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_2_WH,
        ty: 0x01,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_3,
        ty: 0x01,
        flags: 0,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_3_WH,
        ty: 0x01,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_3,
        ty: 0x01,
        flags: 0,
        ct: Some(WHARRGARBLV2),
        match_res: Res::Success,
    },
    ControlTest {
        frame: ACCEPT_3_WH,
        ty: 0x01,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: Some(WHARRGARBLV2),
        match_res: Res::Success,
    },
    ControlTest {
        frame: READY_1,
        ty: 0x04,
        flags: 0,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: READY_1,
        ty: 0x04,
        flags: 0,
        ct: Some(WHARRGARBLV2),
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_1,
        ty: 0x02,
        flags: 0,
        ct: None,
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_1_WH,
        ty: 0x02,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: None,
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_1,
        ty: 0x02,
        flags: 0,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_1_WH,
        ty: 0x02,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_2,
        ty: 0x02,
        flags: 0,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: START_2,
        ty: 0x02,
        flags: 0,
        ct: Some(WHARRGARBLV2),
        match_res: Res::Failure,
    },
    ControlTest {
        frame: START_2_WH,
        ty: 0x02,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: Some(WHARRGARBL),
        match_res: Res::Success,
    },
    ControlTest {
        frame: STOP_1,
        ty: 0x03,
        flags: 0,
        ct: None,
        match_res: Res::Failure,
    },
    ControlTest {
        frame: STOP_1_WH,
        ty: 0x03,
        flags: CONTROL_FLAG_WITH_HEADER,
        ct: None,
        match_res: Res::Failure,
    },
];

const INVALID: &[&[u8]] = &[
    &[0xff],
    &[0xff, 0xff],
    &[0xff, 0xff, 0xff],
    &[0xff, 0xff, 0xff],
    &[0xff, 0xff, 0xff, 0xff],
    &[0xff, 0xff, 0xff, 0xff, 0xff],
    &[0xab, 0xad, 0x1d, 0xea],
    &[
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a',
        b'r', b'r', 0x00, b'g', b'a', b'r', b'b',
    ],
    &[
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, b'w', b'h', b'a',
        b'r', b'r', 0x00, b'g', b'a', b'r', b'b', b'l', b'z',
    ],
    &[0x00, 0x00, 0x00, 0x02, 0x00],
    &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
    &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01],
];

fn match_content_type(c: &Control, ct: Option<&[u8]>, len: usize) -> Res {
    let ok = c.match_field_content_type(ct).is_ok();
    print!(
        "  Control frame is {}compatible with CONTENT_TYPE ({len} bytes): ",
        if ok { "" } else { "NOT " }
    );
    print_string(ct.unwrap_or(&[]));
    println!();
    if ok {
        Res::Success
    } else {
        Res::Failure
    }
}

fn decode_control_frame(c: &mut Control, control_frame: &[u8], flags: u32) -> Res {
    match c.decode(control_frame, flags) {
        Ok(()) => {
            print!(
                "Successfully decoded frame ({} bytes):\n  ",
                control_frame.len()
            );
            print_string(control_frame);
            println!();
        }
        Err(res) => {
            print!(
                "Failed to decode frame ({} bytes):\n  ",
                control_frame.len()
            );
            print_string(control_frame);
            println!();
            return res;
        }
    }
    let ty = match c.get_type() {
        Ok(t) => t,
        Err(_) => {
            println!("  fstrm_control_get_type() failed.");
            return Res::Failure;
        }
    };
    println!(
        "  The control frame is of type {} (0x{:08x}).",
        control_type_to_str(ty as u32),
        ty as u32
    );
    let n = c.get_num_field_content_type();
    for idx in 0..n {
        match c.get_field_content_type(idx) {
            Ok(ct) => {
                print!(
                    "  The control frame has a CONTENT_TYPE field ({} bytes): ",
                    ct.len()
                );
                print_string(ct);
                println!();
            }
            Err(_) => {
                println!("  The control frame does not have any CONTENT_TYPE fields.");
            }
        }
    }
    Res::Success
}

fn test_reencode_frame(c: &mut Control, control_frame: &[u8], flags: u32) {
    println!("Running test_reencode_frame().");
    let len_new_frame = c.encoded_size(flags).unwrap();
    println!("Need {len_new_frame} bytes for new frame.");
    let mut buf = vec![0u8; len_new_frame];
    let mut len = len_new_frame;
    c.encode(&mut buf, &mut len, flags).unwrap();
    print!("Successfully encoded a new frame ({len} bytes):\n  ");
    print_string(&buf[..len]);
    println!();
    assert_eq!(len, len_new_frame);
    assert_eq!(len, control_frame.len());
    assert_eq!(&buf[..len], control_frame);
    println!("New frame is identical to original frame.");
}

fn test_reencode_frame_static(c: &mut Control, control_frame: &[u8], flags: u32) {
    println!("Running test_reencode_frame_static().");
    let mut buf = vec![0u8; CONTROL_FRAME_LENGTH_MAX];
    let mut len = buf.len();
    c.encode(&mut buf, &mut len, flags).unwrap();
    assert!(len <= CONTROL_FRAME_LENGTH_MAX);
    print!("Successfully encoded a new frame ({len} bytes):\n  ");
    print_string(&buf[..len]);
    println!();
    assert_eq!(&buf[..len], control_frame);
    println!("New frame is identical to original frame.");
}

fn test_control_test(c: &mut Control, test: &ControlTest) {
    println!("Running test_control_test().");
    if test.flags & CONTROL_FLAG_WITH_HEADER != 0 {
        println!(
            "Control frames include escape sequence and control frame length.\n  (FSTRM_CONTROL_FLAG_WITH_HEADER enabled.)"
        );
    }
    let res = decode_control_frame(c, test.frame, test.flags);
    assert_eq!(res, Res::Success);
    let ty = c.get_type().unwrap();
    assert_eq!(ty as u32, test.ty);
    let res = match_content_type(c, test.ct, test.ct.map_or(0, |ct| ct.len()));
    assert_eq!(res, test.match_res);
    test_reencode_frame(c, test.frame, test.flags);
    test_reencode_frame_static(c, test.frame, test.flags);
}

fn run_control_corpus() {
    let mut c = Control::init();
    println!("====> The following tests must succeed. <====");
    println!("Running test_control_tests().\n");
    for test in CONTROL_TESTS {
        test_control_test(&mut c, test);
        println!();
    }
    println!("====> The following tests must fail. <====");
    println!("Running test_invalid().");
    for frame in INVALID {
        let res = decode_control_frame(&mut c, frame, 0);
        assert_ne!(res, Res::Success);
    }
}

/* ---------------------------------------------------- file round trip */

fn run_file_round_trip() {
    let path = format!("{WORK}/hello.fs");
    println!("== file writer/reader round trip ==");

    let mut fopt = FileOptions::new();
    fopt.set_file_path(Some(&path));

    let mut wopt = WriterOptions::new();
    let res = wopt.add_content_type(b"test:hello");
    print_res("writer_options_add_content_type(test:hello)", res);
    let res = wopt.add_content_type(&[b'x'; 257]);
    print_res("writer_options_add_content_type(257 bytes)", res);

    let mut w = file_writer_init(&fopt, Some(&wopt));
    println!(
        "  file_writer_init -> {}",
        if w.is_some() { "non-NULL" } else { "NULL" }
    );
    let mut w = w.unwrap();
    let res = w.open();
    print_res("writer_open", res);
    let res = w.open();
    print_res("writer_open (double)", res);
    for i in 0..32 {
        let mut msg = format!("Hello world #{i}").into_bytes();
        msg.push(0); // strlen + 1, like the C test_file_hello
        let res = w.write(&msg);
        assert_eq!(res, Res::Success);
    }
    let res = w.close();
    print_res("writer_close", res);
    let res = w.close();
    print_res("writer_close (again)", res);
    let mut wslot = Some(w);
    let res = writer_destroy(&mut wslot);
    print_res("writer_destroy", res);

    /* Byte-exact dump of the file. */
    let bytes = std::fs::read(&path).unwrap();
    println!("  file size {}", bytes.len());
    print!("  file bytes ");
    dump(&bytes);
    println!();

    /* Read it back. */
    let mut fopt = FileOptions::new();
    fopt.set_file_path(Some(&path));
    let mut ropt = ReaderOptions::new();
    let res = ropt.add_content_type(b"test:hello");
    print_res("reader_options_add_content_type(test:hello)", res);
    let mut r = file_reader_init(&fopt, Some(&ropt));
    println!(
        "  file_reader_init -> {}",
        if r.is_some() { "non-NULL" } else { "NULL" }
    );
    let mut r = r.unwrap();
    let res = r.open();
    print_res("reader_open", res);
    let res = r.open();
    print_res("reader_open (double)", res);
    for i in 0..32 {
        let mut expect = format!("Hello world #{i}").into_bytes();
        expect.push(0);
        let res = r.read();
        match res {
            Ok(data) => {
                print!(
                    "  read #{i} -> {} ({}), {} bytes: ",
                    Res::Success as u32,
                    res_str(Res::Success),
                    data.len()
                );
                print_string(data);
                println!();
                assert_eq!(data, expect);
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let res = r.read().unwrap_err();
    print_res("reader_read past end", res);
    let res = r.read().unwrap_err();
    print_res("reader_read (closing state)", res);
    let res = r.close();
    print_res("reader_close", res);
    let res = r.close();
    print_res("reader_close (again)", res);

    let c = r.get_control(ControlType::Start).unwrap();
    println!(
        "  reader_get_control(START) -> {} ({}), control {}",
        Res::Success as u32,
        res_str(Res::Success),
        if c.is_some() { "non-NULL" } else { "NULL" }
    );
    if let Some(c) = c {
        let ty = c.get_type().unwrap();
        let n = c.get_num_field_content_type();
        println!("    type {} n_ctype {n}", control_type_to_str(ty as u32));
        for idx in 0..n {
            let ct = c.get_field_content_type(idx).unwrap();
            print!("    ct[{idx}] ");
            print_string(ct);
            println!();
        }
    }
    let res = r.get_control(ControlType::Finish).unwrap_err();
    print_res("reader_get_control(FINISH)", res);
    let mut rslot = Some(r);
    let res = reader_destroy(&mut rslot);
    print_res("reader_destroy", res);
}

/* --------------------------------------------------- reader limits */

fn run_reader_limits() {
    let path = format!("{WORK}/big.fs");
    println!("== reader limits ==");

    let mut ropt = ReaderOptions::new();
    let res = ropt.set_max_frame_size(511);
    print_res("set_max_frame_size(511)", res);
    let res = ropt.set_max_frame_size(512);
    print_res("set_max_frame_size(512)", res);
    let res = ropt.set_max_frame_size(u32::MAX as usize - 1);
    print_res("set_max_frame_size(UINT32_MAX-1)", res);
    let res = ropt.set_max_frame_size(u32::MAX as usize);
    print_res("set_max_frame_size(UINT32_MAX)", res);
    drop(ropt);

    /* Write a file containing a 600-byte frame. */
    let mut fopt = FileOptions::new();
    fopt.set_file_path(Some(&path));
    let mut wopt = WriterOptions::new();
    wopt.add_content_type(b"test:hello");
    let mut w = file_writer_init(&fopt, Some(&wopt)).unwrap();
    assert_eq!(w.open(), Res::Success);
    let big = vec![b'z'; 600];
    assert_eq!(w.write(&big), Res::Success);
    assert_eq!(w.close(), Res::Success);
    let mut wslot = Some(w);
    writer_destroy(&mut wslot);

    /* A 512-byte max rejects the 600-byte frame. */
    let mut ropt = ReaderOptions::new();
    ropt.add_content_type(b"test:hello");
    ropt.set_max_frame_size(512);
    let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
    let res = r.open();
    print_res("reader open (max 512)", res);
    let res = r.read();
    // reader.c: the max-frame-size violation returns success with unspecified
    // output (a stale `res` from the length read); the reader then fails the
    // close.  Mirror: print the return code only.
    let code = match res {
        Ok(_) => Res::Success,
        Err(e) => e,
    };
    print_res("reader read 600-byte frame (max 512)", code);
    let res = r.close();
    print_res("reader close after failure", res);
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);

    /* The default (1048576) accepts it. */
    let mut ropt = ReaderOptions::new();
    ropt.add_content_type(b"test:hello");
    let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
    let res = r.open();
    print_res("reader open (default max)", res);
    match r.read() {
        Ok(data) => {
            println!(
                "  reader read 600-byte frame (default max) -> {} ({}), {} bytes",
                Res::Success as u32,
                res_str(Res::Success),
                data.len()
            );
            assert_eq!(data.len(), 600);
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);

    /* Content-type mismatch: the file says test:hello. */
    let mut ropt = ReaderOptions::new();
    ropt.add_content_type(b"test:other");
    let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
    let res = r.open();
    print_res("reader open (content-type mismatch)", res);
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);

    /* No configured content types: accept anything. */
    let ropt = ReaderOptions::new();
    let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
    let res = r.open();
    print_res("reader open (no content types configured)", res);
    match r.read() {
        Ok(data) => {
            println!(
                "  reader read (no content types) -> {} ({}), {} bytes",
                Res::Success as u32,
                res_str(Res::Success),
                data.len()
            );
            assert_eq!(data.len(), 600);
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);
}

/* --------------------------------------------------- writer errors */

fn run_writer_errors() {
    let path = format!("{WORK}/err.fs");
    println!("== writer errors ==");

    /* A writer over an rdwr with no write method is NULL. */
    {
        let mut rdwr = Rdwr::new();
        let w = Writer::new(None, &mut Some(rdwr));
        println!(
            "  writer_init (no write method) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_none());
    }

    let mut fopt = FileOptions::new();
    fopt.set_file_path(Some(&path));
    let mut w = file_writer_init(&fopt, None).unwrap();
    let res = w.close();
    print_res("writer_close before open", res);
    let res = w.writev(&[]);
    print_res("writer_writev(iovcnt=0)", res);
    let res = w.open();
    print_res("writer_open", res);
    let res = w.write(b"data");
    print_res("writer_write", res);
    let res = w.close();
    print_res("writer_close", res);
    let res = w.write(b"late");
    print_res("writer_write after close", res);
    let res = w.get_control(ControlType::Stop).unwrap_err();
    print_res("writer_get_control(STOP)", res);
    let c = w.get_control(ControlType::Ready).unwrap();
    println!(
        "  writer_get_control(READY) -> {} ({}), control {}",
        Res::Success as u32,
        res_str(Res::Success),
        if c.is_some() { "non-NULL" } else { "NULL" }
    );
    let mut wslot = Some(w);
    writer_destroy(&mut wslot);
}

/* --------------------------------------------------- writev chunked */

fn run_writev_chunked() {
    let path = format!("{WORK}/chunked.fs");
    println!("== writev chunked ==");

    let mut fopt = FileOptions::new();
    fopt.set_file_path(Some(&path));
    let mut wopt = WriterOptions::new();
    wopt.add_content_type(b"test:hello");
    let mut w = file_writer_init(&fopt, Some(&wopt)).unwrap();
    assert_eq!(w.open(), Res::Success);
    let frames: Vec<Vec<u8>> = (0..200).map(|i| format!("m{i:03}").into_bytes()).collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let res = w.writev(&refs);
    print_res("writer_writev(200 frames)", res);
    assert_eq!(w.close(), Res::Success);
    let mut wslot = Some(w);
    writer_destroy(&mut wslot);

    let mut ropt = ReaderOptions::new();
    ropt.add_content_type(b"test:hello");
    let mut r = file_reader_init(&fopt, Some(&ropt)).unwrap();
    assert_eq!(r.open(), Res::Success);
    for i in 0..200 {
        match r.read() {
            Ok(data) => {
                print!(
                    "  read #{i} -> {} ({}), {} bytes: ",
                    Res::Success as u32,
                    res_str(Res::Success),
                    data.len()
                );
                print_string(data);
                println!();
                assert_eq!(data, frames[i]);
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let res = r.read().unwrap_err();
    print_res("reader_read past end", res);
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);
}

/* --------------------------------------------------- unix/tcp init validation */

fn run_transport_init_validation() {
    println!("== unix writer init validation ==");
    {
        let mut uwopt = UnixWriterOptions::new();
        let w = unix_writer_init(&uwopt, None);
        println!(
            "  unix_writer_init(NULL path) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_none());

        let longpath = "x".repeat(108);
        uwopt.set_socket_path(Some(&longpath));
        let w = unix_writer_init(&uwopt, None);
        println!(
            "  unix_writer_init(108-char path) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_none());

        let fitpath = "x".repeat(107);
        uwopt.set_socket_path(Some(&fitpath));
        let w = unix_writer_init(&uwopt, None);
        println!(
            "  unix_writer_init(107-char path) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_some());
        let mut wslot = w;
        writer_destroy(&mut wslot);
    }

    println!("== tcp writer init validation ==");
    {
        let mut twopt = TcpWriterOptions::new();
        let w = tcp_writer_init(&twopt, None);
        println!(
            "  tcp_writer_init(no addr/port) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_none());

        twopt.set_socket_address(Some("127.0.0.1"));
        let w = tcp_writer_init(&twopt, None);
        println!(
            "  tcp_writer_init(addr, no port) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_none());

        twopt.set_socket_port(Some("8080"));
        let w = tcp_writer_init(&twopt, None);
        println!(
            "  tcp_writer_init(127.0.0.1, 8080) -> {}",
            if w.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(w.is_some());
        let mut wslot = w;
        writer_destroy(&mut wslot);

        let cases: &[(&str, &str)] = &[
            ("127.0.0.1", "8080"),
            ("::1", "8080"),
            ("1.2.3.999", "8080"),
            ("notanaddress", "8080"),
            ("010.0.0.1", "8080"),
            ("127.0.0.1:8080", "8080"),
            ("127.0.0.1", "65535"),
            ("127.0.0.1", "65536"),
            ("127.0.0.1", "8080junk"),
            ("127.0.0.1", "-1"),
            ("127.0.0.1", ""),
            ("127.0.0.1", "0x1F90"),
            ("127.0.0.1", " 8080"),
            ("127.0.0.1", "010"),
            ("127.0.0.1", "+8080"),
        ];
        for (addr, port) in cases {
            twopt.set_socket_address(Some(addr));
            twopt.set_socket_port(Some(port));
            let w = tcp_writer_init(&twopt, None);
            println!(
                "  tcp_writer_init(\"{addr}\", \"{port}\") -> {}",
                if w.is_some() { "non-NULL" } else { "NULL" }
            );
            if w.is_some() {
                let mut wslot = w;
                writer_destroy(&mut wslot);
            }
        }
    }
}

/* --------------------------------------------------- socket interop */

/// The fd-rdwr over an accepted stream (the C probe's `sock_open`/`sock_close`/
/// `sock_read`/`sock_write`): read/write are exact-read/exact-write loops,
/// EOF is a failure (not stop), like the C's `read_bytes`-style ops.
trait StreamDup: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> std::io::Result<Self>;
}

impl StreamDup for UnixStream {
    fn dup(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
}

impl StreamDup for std::net::TcpStream {
    fn dup(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
}

fn socket_rdwr<S: StreamDup>(stream: S) -> Rdwr {
    let mut rdwr = Rdwr::new();
    rdwr.set_open(Box::new(|| Res::Success));
    let s_close = stream.dup().unwrap();
    rdwr.set_close(Box::new(move || {
        drop(&s_close);
        Res::Success
    }));
    let mut s_read = stream.dup().unwrap();
    rdwr.set_read(Box::new(move |buf| {
        let mut rest = buf;
        while !rest.is_empty() {
            match s_read.read(rest) {
                Ok(0) => return Res::Failure,
                Ok(n) => rest = &mut rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Res::Failure,
            }
        }
        Res::Success
    }));
    let mut s_write = stream;
    rdwr.set_write(Box::new(move |iov| {
        for v in iov {
            let mut rest = v.data;
            while !rest.is_empty() {
                match s_write.write(rest) {
                    Ok(0) => return Res::Failure,
                    Ok(n) => rest = &rest[n..],
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Res::Failure,
                }
            }
        }
        Res::Success
    }));
    rdwr
}

fn fprint_string(out: &mut String, data: &[u8]) {
    out.push('"');
    for &c in data {
        if (0x20..=0x7e).contains(&c) {
            if c == b'"' {
                out.push_str("\\\"");
            } else {
                out.push(c as char);
            }
        } else {
            out.push_str(&format!("\\x{c:02x}"));
        }
    }
    out.push('"');
}

/// The consumer: `fstrm_reader` over the accepted stream; the transcript is
/// written to a file (mirroring the C probe) and printed by the caller after
/// join so the output is deterministic.
fn consumer_main<S: StreamDup>(stream: S, transcript: &str) {
    let mut out = String::new();
    out.push_str("accepted a connection\n");

    let mut rrdwr = socket_rdwr(stream);
    let mut ropt = ReaderOptions::new();
    ropt.add_content_type(b"test:hello");
    let mut r = Reader::new(Some(&ropt), &mut Some(rrdwr)).unwrap();
    let res = r.open();
    out.push_str(&format!(
        "reader open -> {} ({})\n",
        res as u32,
        res_str(res)
    ));
    assert_eq!(res, Res::Success);

    let c = r.get_control(ControlType::Ready).unwrap().unwrap();
    let ty = c.get_type().unwrap();
    let n = c.get_num_field_content_type();
    out.push_str(&format!(
        "ready: type {} n_ctype {n}\n",
        control_type_to_str(ty as u32)
    ));
    for idx in 0..n {
        let ct = c.get_field_content_type(idx).unwrap();
        out.push_str(&format!("  ready ct[{idx}] "));
        fprint_string(&mut out, ct);
        out.push('\n');
    }

    let c = r.get_control(ControlType::Start).unwrap().unwrap();
    let ty = c.get_type().unwrap();
    let n = c.get_num_field_content_type();
    out.push_str(&format!(
        "start: type {} n_ctype {n}\n",
        control_type_to_str(ty as u32)
    ));
    for idx in 0..n {
        let ct = c.get_field_content_type(idx).unwrap();
        out.push_str(&format!("  start ct[{idx}] "));
        fprint_string(&mut out, ct);
        out.push('\n');
    }

    let mut idx = 0;
    loop {
        match r.read() {
            Ok(data) => {
                out.push_str(&format!("frame {idx}: {} bytes ", data.len()));
                fprint_string(&mut out, data);
                out.push('\n');
                idx += 1;
            }
            Err(Res::Stop) => {
                out.push_str("read -> stop\n");
                break;
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let res = r.close();
    out.push_str(&format!(
        "reader close -> {} ({})\n",
        res as u32,
        res_str(res)
    ));
    let mut rslot = Some(r);
    reader_destroy(&mut rslot);
    std::fs::write(transcript, out).unwrap();
}

fn run_socket_interop(
    kind: &str,
    socket_path: Option<&str>,
    tcp_address: Option<&str>,
    transcript: &str,
) {
    let (writer, consumer) = if kind == "unix" {
        let path = socket_path.unwrap();
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let mut uwopt = UnixWriterOptions::new();
        uwopt.set_socket_path(Some(path));
        let mut wopt = WriterOptions::new();
        wopt.add_content_type(b"test:hello");
        let w = unix_writer_init(&uwopt, Some(&wopt)).unwrap();
        let t = transcript.to_owned();
        let consumer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            consumer_main(stream, &t);
        });
        (w, consumer)
    } else {
        let listener = std::net::TcpListener::bind((tcp_address.unwrap(), 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut twopt = TcpWriterOptions::new();
        twopt.set_socket_address(Some(tcp_address.unwrap()));
        twopt.set_socket_port(Some(&port.to_string()));
        let mut wopt = WriterOptions::new();
        wopt.add_content_type(b"test:hello");
        let w = tcp_writer_init(&twopt, Some(&wopt)).unwrap();
        let t = transcript.to_owned();
        let consumer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            consumer_main(stream, &t);
        });
        (w, consumer)
    };

    let mut iopt = IothrOptions::new();
    let mut wslot = Some(writer);
    let iothr = iothr_init(Some(&iopt), &mut wslot).unwrap();
    assert!(wslot.is_none());

    let ioq = get_input_queue(&iothr).unwrap();
    for i in 0..8 {
        let msg = format!("msg-{i:04}");
        loop {
            let res = submit(
                &iothr,
                &ioq,
                msg.as_bytes().to_vec(),
                Some(Box::new(free_wrapper)),
            );
            if res == Res::Success {
                break;
            }
            assert_eq!(res, Res::Again);
            std::thread::yield_now();
        }
    }
    let mut islot = Some(iothr);
    iothr_destroy(&mut islot);
    consumer.join().unwrap();

    /* Print the consumer's transcript. */
    let text = std::fs::read_to_string(transcript).unwrap();
    print!("{text}");
}

/* --------------------------------------------------- iothr surface */

fn run_iothr_surface() {
    println!("== iothr options ==");
    let mut opt = IothrOptions::new();
    print_res("set_buffer_hint(1023)", opt.set_buffer_hint(1023));
    print_res("set_buffer_hint(1024)", opt.set_buffer_hint(1024));
    print_res("set_buffer_hint(8192)", opt.set_buffer_hint(8192));
    print_res("set_buffer_hint(65536)", opt.set_buffer_hint(65536));
    print_res("set_buffer_hint(65537)", opt.set_buffer_hint(65537));
    print_res("set_flush_timeout(0)", opt.set_flush_timeout(0));
    print_res("set_flush_timeout(1)", opt.set_flush_timeout(1));
    print_res("set_flush_timeout(600)", opt.set_flush_timeout(600));
    print_res("set_flush_timeout(601)", opt.set_flush_timeout(601));
    print_res("set_input_queue_size(1)", opt.set_input_queue_size(1));
    print_res("set_input_queue_size(2)", opt.set_input_queue_size(2));
    print_res("set_input_queue_size(3)", opt.set_input_queue_size(3));
    print_res("set_input_queue_size(4)", opt.set_input_queue_size(4));
    print_res("set_input_queue_size(6)", opt.set_input_queue_size(6));
    print_res(
        "set_input_queue_size(16384)",
        opt.set_input_queue_size(16384),
    );
    print_res(
        "set_input_queue_size(16385)",
        opt.set_input_queue_size(16385),
    );
    print_res("set_num_input_queues(0)", opt.set_num_input_queues(0));
    print_res("set_num_input_queues(1)", opt.set_num_input_queues(1));
    print_res("set_num_input_queues(4)", opt.set_num_input_queues(4));
    print_res("set_output_queue_size(1)", opt.set_output_queue_size(1));
    print_res("set_output_queue_size(2)", opt.set_output_queue_size(2));
    print_res(
        "set_output_queue_size(1024)",
        opt.set_output_queue_size(1024),
    );
    print_res(
        "set_output_queue_size(1025)",
        opt.set_output_queue_size(1025),
    );
    print_res(
        "set_queue_model(SPSC)",
        opt.set_queue_model(QueueModel::Spsc),
    );
    print_res(
        "set_queue_model(MPSC)",
        opt.set_queue_model(QueueModel::Mpsc),
    );
    print_res("set_queue_model(2)", opt.set_queue_model_raw(2));
    print_res(
        "set_queue_notify_threshold(0)",
        opt.set_queue_notify_threshold(0),
    );
    print_res(
        "set_queue_notify_threshold(1)",
        opt.set_queue_notify_threshold(1),
    );
    print_res("set_reopen_interval(0)", opt.set_reopen_interval(0));
    print_res("set_reopen_interval(1)", opt.set_reopen_interval(1));
    print_res("set_reopen_interval(600)", opt.set_reopen_interval(600));
    print_res("set_reopen_interval(601)", opt.set_reopen_interval(601));
    let mut oslot = Some(opt);
    iothr_options_destroy(&mut oslot);

    println!("== iothr init + submit ==");
    {
        let path = format!("{WORK}/iothr.fs");
        let mut fopt = FileOptions::new();
        fopt.set_file_path(Some(&path));
        let mut w = Some(file_writer_init(&fopt, None).unwrap());

        /* A power-of-2 input queue size inits cleanly.  (The non-power-of-2
         * path is excluded from the corpus: fstrm 0.6.1's iothr_init
         * goto-fail path joins an uninitialized thread/condvar and
         * segfaults — see FSTRM-LORE.) */
        let mut o2 = IothrOptions::new();
        o2.set_input_queue_size(8);
        let iothr = Iothr::new(Some(&o2), &mut w);
        println!(
            "  iothr_init(input_queue_size=8) -> {}",
            if iothr.is_some() { "non-NULL" } else { "NULL" }
        );
        let iothr = iothr.unwrap();

        let ioq = iothr.get_input_queue();
        println!(
            "  get_input_queue #1 -> {}",
            if ioq.is_some() { "non-NULL" } else { "NULL" }
        );
        let ioq2 = iothr.get_input_queue();
        println!(
            "  get_input_queue #2 (beyond num_input_queues) -> {}",
            if ioq2.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(ioq2.is_none());
        let ioq3 = iothr.get_input_queue_idx(0);
        println!(
            "  get_input_queue_idx(0) -> {}",
            if ioq3.is_some() { "non-NULL" } else { "NULL" }
        );
        let ioq4 = iothr.get_input_queue_idx(1);
        println!(
            "  get_input_queue_idx(1) -> {}",
            if ioq4.is_some() { "non-NULL" } else { "NULL" }
        );
        assert!(ioq4.is_none());
        /* The handles from get_input_queue are one-shot (one per
         * num_input_queues); index the array directly for the submits. */
        let ioq = iothr.get_input_queue_idx(0).unwrap();

        let res = iothr.submit(&ioq, Vec::new(), None);
        print_res("submit(len=0)", res);
        let res = iothr.submit(&ioq, Vec::new(), None);
        print_res("submit(empty, len=0)", res);

        for i in 0..16 {
            let msg = format!("hello world #{i}");
            loop {
                let res = iothr.submit(&ioq, msg.as_bytes().to_vec(), Some(Box::new(free_wrapper)));
                if res == Res::Success {
                    break;
                }
                assert_eq!(res, Res::Again);
                std::thread::yield_now();
            }
            println!("  submit #{i} -> 0 (success)");
        }

        let mut islot = Some(iothr);
        iothr_destroy(&mut islot);

        let bytes = std::fs::read(&path).unwrap();
        println!("  iothr file size {}", bytes.len());
        print!("  iothr file bytes ");
        dump(&bytes);
        println!();
    }

    println!("== iothr discard on unopenable writer ==");
    {
        let mut uwopt = UnixWriterOptions::new();
        uwopt.set_socket_path(Some(&format!("{WORK}/none.sock")));
        let mut w = Some(unix_writer_init(&uwopt, None).unwrap());
        let iothr = Iothr::new(None, &mut w).unwrap();
        let ioq = iothr.get_input_queue().unwrap();
        let freed = Arc::new(AtomicUsize::new(0));
        for i in 0..4 {
            let msg = format!("drop-{i}");
            let counter = freed.clone();
            let res = iothr.submit(
                &ioq,
                msg.into_bytes(),
                Some(Box::new(move |d| {
                    drop(d);
                    counter.fetch_add(1, Ordering::Relaxed);
                })),
            );
            assert_eq!(res, Res::Success);
        }
        let mut islot = Some(iothr);
        iothr_destroy(&mut islot);
        let n = freed.load(Ordering::Relaxed);
        println!("  freed {n} frames (discarded on shutdown)");
        assert_eq!(n, 4);
    }
}

/* ------------------------------------------------------------------ main */

fn main() {
    mkwork();

    println!("== control types ==");
    println!("  type 0x{0:08x} {1}", 0x01, control_type_to_str(0x01));
    println!("  type 0x{0:08x} {1}", 0x02, control_type_to_str(0x02));
    println!("  type 0x{0:08x} {1}", 0x03, control_type_to_str(0x03));
    println!("  type 0x{0:08x} {1}", 0x04, control_type_to_str(0x04));
    println!("  type 0x{0:08x} {1}", 0x05, control_type_to_str(0x05));
    println!("  type 0x{0:08x} {1}", 0xff, control_type_to_str(0xff));
    println!(
        "  field 0x{0:08x} {1}",
        0x01,
        control_field_type_to_str(0x01)
    );
    println!(
        "  field 0x{0:08x} {1}",
        0xff,
        control_field_type_to_str(0xff)
    );

    println!("== control corpus ==");
    run_control_corpus();

    run_file_round_trip();
    run_reader_limits();
    run_writer_errors();
    run_writev_chunked();
    run_transport_init_validation();

    println!("== unix socket interop ==");
    run_socket_interop(
        "unix",
        Some(&format!("{WORK}/test.sock")),
        None,
        &format!("{WORK}/consumer.unix.txt"),
    );
    println!("== tcp socket interop ==");
    run_socket_interop(
        "tcp",
        None,
        Some("127.0.0.1"),
        &format!("{WORK}/consumer.tcp.txt"),
    );

    run_iothr_surface();
}
