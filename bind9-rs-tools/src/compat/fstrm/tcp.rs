//! `fstrm_tcp_writer` (tcp_writer.c/tcp_writer.h): a bidirectional TCP stream
//! writer (AF_INET or AF_INET6).  Init parses the socket address with
//! `inet_pton` (AF_INET first, then AF_INET6 — tcp_writer.c
//! `fstrm__tcp_writer_fill_socket_address`) and the port with `strtoul` base 0
//! (rejecting trailing garbage and values > `UINT16_MAX` — tcp_writer.c
//! `fstrm__tcp_writer_fill_socket_port`).
//!
//! `inet_pton` is strict: IPv4 requires exactly four decimal octets (no
//! leading zeros, each 0..255); IPv6 is the RFC 4291 text form with `::`
//! compression, an optional embedded IPv4 tail, and no zone ids.  `strtoul`
//! base 0 accepts leading whitespace and an optional sign, then hex (`0x`),
//! octal (`0`), or decimal digits with C unsigned wrap-around; an empty
//! subject is valid with value 0 (the C's `*endptr != '\0'` check passes on
//! the empty string), and `"-1"` wraps to ULONG_MAX, failing the
//! `> UINT16_MAX` check.  Both are transcribed here so the init error surface
//! matches the oracle byte-for-byte.

use super::{
    rdwr::{IoVec, Rdwr},
    writer::{Writer, WriterOptions},
    Res,
};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

/// `struct fstrm_tcp_writer_options` (tcp_writer.c:34).
#[derive(Clone, Debug, Default)]
pub struct TcpWriterOptions {
    socket_address: Option<String>,
    socket_port: Option<String>,
}

impl TcpWriterOptions {
    /// `fstrm_tcp_writer_options_init`.
    #[must_use]
    pub fn new() -> TcpWriterOptions {
        TcpWriterOptions {
            socket_address: None,
            socket_port: None,
        }
    }

    /// `fstrm_tcp_writer_options_set_socket_address` (tcp_writer.c:62).
    pub fn set_socket_address(&mut self, socket_address: Option<&str>) {
        self.socket_address = socket_address.map(str::to_owned);
    }

    /// `fstrm_tcp_writer_options_set_socket_port` (tcp_writer.c:72).
    pub fn set_socket_port(&mut self, socket_port: Option<&str>) {
        self.socket_port = socket_port.map(str::to_owned);
    }
}

/// `struct fstrm__tcp_writer` (tcp_writer.c:39).
struct TcpWriterState {
    connected: bool,
    stream: Option<TcpStream>,
}

impl TcpWriterState {
    fn new() -> TcpWriterState {
        TcpWriterState {
            connected: false,
            stream: None,
        }
    }

    /// `fstrm__tcp_writer_op_open` (tcp_writer.c:82).
    fn op_open(&mut self, addr: SocketAddr) -> Res {
        if self.connected {
            return Res::Success;
        }
        let stream = match TcpStream::connect(addr) {
            Ok(s) => s,
            Err(_) => return Res::Failure,
        };
        self.stream = Some(stream);
        self.connected = true;
        Res::Success
    }

    /// `fstrm__tcp_writer_op_close` (tcp_writer.c:142).
    fn op_close(&mut self) -> Res {
        if self.connected {
            self.connected = false;
            self.stream = None;
            return Res::Success;
        }
        Res::Failure
    }

    /// `fstrm__tcp_writer_op_read` (tcp_writer.c:155): `read_bytes` loop.
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

    /// `fstrm__tcp_writer_op_write` (tcp_writer.c:166): sendmsg over the whole
    /// iovec.
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

/// glibc `strtoul(s, &endptr, 0)`: returns `(value, consumed)` — the number
/// of bytes consumed by the subject sequence.  Mirrors glibc for the cases
/// the oracle exercises: leading whitespace, optional sign, `0x` hex, `0`
/// octal, decimal, saturation to ULONG_MAX (errno = ERANGE) on overflow, and
/// the unsigned negation of a leading `-` (e.g. `"-1"` → ULONG_MAX).
fn strtoul_base0(s: &str) -> (u64, usize) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let mut negative = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        negative = b[i] == b'-';
        i += 1;
    }
    let mut acc: u64 = 0;
    let mut overflowed = false;

    let digit = |c: u8, radix: u64| -> Option<u64> {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (c - b'a' + 10) as u64,
            b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => return None,
        };
        (d < radix).then_some(d)
    };

    // glibc saturates to ULONG_MAX (errno = ERANGE) on overflow but keeps
    // consuming the remaining digits.
    let add_digit = |acc: &mut u64, d: u64, radix: u64, overflowed: &mut bool| {
        if *overflowed {
            return;
        }
        match acc.checked_mul(radix).and_then(|v| v.checked_add(d)) {
            Some(v) => *acc = v,
            None => {
                *acc = u64::MAX;
                *overflowed = true;
            }
        }
    };

    // Base 0: hex after "0x"/"0X" (only when a hex digit follows, else the
    // "0" is octal and the 'x' is trailing garbage), octal after a leading
    // "0", decimal otherwise.
    if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        if i + 2 < b.len() && digit(b[i + 2], 16).is_some() {
            i += 2;
            while i < b.len() {
                match digit(b[i], 16) {
                    Some(d) => {
                        add_digit(&mut acc, d, 16, &mut overflowed);
                        i += 1;
                    }
                    None => break,
                }
            }
        } else {
            i += 1; // consume the '0' as octal; the 'x' stays unconsumed
            while i < b.len() {
                match digit(b[i], 8) {
                    Some(d) => {
                        add_digit(&mut acc, d, 8, &mut overflowed);
                        i += 1;
                    }
                    None => break,
                }
            }
        }
    } else if i < b.len() && b[i] == b'0' {
        i += 1;
        while i < b.len() {
            match digit(b[i], 8) {
                Some(d) => {
                    add_digit(&mut acc, d, 8, &mut overflowed);
                    i += 1;
                }
                None => break,
            }
        }
    } else {
        while i < b.len() {
            match digit(b[i], 10) {
                Some(d) => {
                    add_digit(&mut acc, d, 10, &mut overflowed);
                    i += 1;
                }
                None => break,
            }
        }
    }

    let value = if negative { acc.wrapping_neg() } else { acc };
    (value, i)
}

/// `inet_pton(AF_INET, ...)`: exactly four decimal octets, each 0..255, no
/// leading zeros (glibc semantics).
fn inet_pton4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let bytes = part.as_bytes();
        if bytes.is_empty() || bytes.len() > 3 {
            return None;
        }
        // No leading zeros unless the octet is exactly "0".
        if bytes.len() > 1 && bytes[0] == b'0' {
            return None;
        }
        let mut v: u32 = 0;
        for &c in bytes {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as u32;
        }
        if v > 255 {
            return None;
        }
        out[i] = v as u8;
    }
    Some(out)
}

/// One IPv6 text group: 1-4 hex digits.
fn parse_ipv6_group(part: &str) -> Option<u16> {
    if part.is_empty() || part.len() > 4 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in part.as_bytes() {
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => return None,
        };
        v = v * 16 + d;
    }
    Some(v as u16)
}

/// `inet_pton(AF_INET6, ...)`: RFC 4291 text form — up to 8 groups of 1-4
/// hex digits, `::` compression (at most one), optional embedded IPv4 tail
/// (occupying the last two groups), no zone ids.
fn inet_pton6(s: &str) -> Option<[u16; 8]> {
    if s.as_bytes().contains(&b'%') {
        return None; // zone ids are rejected by inet_pton
    }
    match s.find("::") {
        None => {
            // No compression: exactly 8 groups (the last may be embedded v4).
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 8 {
                return None;
            }
            let mut out = [0u16; 8];
            for (i, p) in parts.iter().enumerate() {
                if i == 7 && p.contains('.') {
                    let v4 = inet_pton4(p)?;
                    out[6] = ((v4[0] as u16) << 8) | v4[1] as u16;
                    out[7] = ((v4[2] as u16) << 8) | v4[3] as u16;
                } else {
                    out[i] = parse_ipv6_group(p)?;
                }
            }
            Some(out)
        }
        Some(idx) => {
            let head = &s[..idx];
            let tail = &s[idx + 2..];
            let head_parts: Vec<&str> = if head.is_empty() {
                Vec::new()
            } else {
                head.split(':').collect()
            };
            let tail_parts: Vec<&str> = if tail.is_empty() {
                Vec::new()
            } else {
                tail.split(':').collect()
            };
            let mut values: Vec<u16> = Vec::new();
            for p in &head_parts {
                if p.is_empty() {
                    return None; // only one "::" may appear
                }
                values.push(parse_ipv6_group(p)?);
            }
            let n_head = values.len();
            let n_tail = tail_parts.len();
            for (i, p) in tail_parts.iter().enumerate() {
                if p.is_empty() {
                    return None;
                }
                if i == n_tail - 1 && p.contains('.') {
                    let v4 = inet_pton4(p)?;
                    values.push(((v4[0] as u16) << 8) | v4[1] as u16);
                    values.push(((v4[2] as u16) << 8) | v4[3] as u16);
                } else {
                    values.push(parse_ipv6_group(p)?);
                }
            }
            let n = values.len();
            if n >= 8 {
                return None; // "::" must compress at least one group
            }
            let fill = 8 - n;
            let mut out = [0u16; 8];
            for (i, v) in values.iter().enumerate() {
                if i < n_head {
                    out[i] = *v;
                } else {
                    out[i + fill] = *v;
                }
            }
            Some(out)
        }
    }
}

/// `fstrm__tcp_writer_fill_socket_address` (tcp_writer.c:239): `inet_pton`
/// AF_INET first, then AF_INET6.
fn fill_socket_address(address: &str) -> Option<SocketAddr> {
    if let Some(v4) = inet_pton4(address) {
        return Some(SocketAddr::from((v4, 0)));
    }
    inet_pton6(address).map(|v6| SocketAddr::from((v6, 0)))
}

/// `fstrm__tcp_writer_fill_socket_port` (tcp_writer.c:214).
fn fill_socket_port(port_str: &str) -> Option<u16> {
    let (port, endptr) = strtoul_base0(port_str);
    if endptr != port_str.len() || port > u16::MAX as u64 {
        return None;
    }
    Some(port as u16)
}

/// `fstrm_tcp_writer_init` (tcp_writer.c:259): rejects a NULL address or
/// port, or a parse failure.
pub fn tcp_writer_init(twopt: &TcpWriterOptions, wopt: Option<&WriterOptions>) -> Option<Writer> {
    let address = twopt.socket_address.as_ref()?;
    let port = twopt.socket_port.as_ref()?;
    let mut addr = fill_socket_address(address)?;
    let port = fill_socket_port(port)?;
    addr.set_port(port);

    let state = Arc::new(Mutex::new(TcpWriterState::new()));
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
        rdwr.set_open(Box::new(move || s.lock().unwrap().op_open(addr)));
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

/// `fstrm_tcp_writer_options_init`.
#[must_use]
pub fn tcp_writer_options_init() -> TcpWriterOptions {
    TcpWriterOptions::new()
}

/// `fstrm_tcp_writer_options_set_socket_address`.
pub fn tcp_writer_options_set_socket_address(twopt: &mut TcpWriterOptions, address: &str) {
    twopt.set_socket_address(Some(address));
}

/// `fstrm_tcp_writer_options_set_socket_port`.
pub fn tcp_writer_options_set_socket_port(twopt: &mut TcpWriterOptions, port: &str) {
    twopt.set_socket_port(Some(port));
}

/// The IPv6 test helper.
#[allow(dead_code)]
pub(crate) fn _inet_pton6_for_test(s: &str) -> Option<[u16; 8]> {
    inet_pton6(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{Reader, ReaderOptions, Res};

    fn opt(address: &str, port: &str) -> TcpWriterOptions {
        let mut o = TcpWriterOptions::new();
        o.set_socket_address(Some(address));
        o.set_socket_port(Some(port));
        o
    }

    #[test]
    fn tcp_writer_init_validation() {
        let mut o = TcpWriterOptions::new();
        assert!(tcp_writer_init(&o, None).is_none()); // no address/port
        o.set_socket_address(Some("127.0.0.1"));
        assert!(tcp_writer_init(&o, None).is_none()); // no port
        o.set_socket_port(Some("8080"));
        assert!(tcp_writer_init(&o, None).is_some());
        // Address parsing.
        assert!(tcp_writer_init(&opt("127.0.0.1", "8080"), None).is_some());
        assert!(tcp_writer_init(&opt("::1", "8080"), None).is_some());
        assert!(tcp_writer_init(&opt("1.2.3.999", "8080"), None).is_none());
        assert!(tcp_writer_init(&opt("notanaddress", "8080"), None).is_none());
        assert!(tcp_writer_init(&opt("010.0.0.1", "8080"), None).is_none()); // leading zero
        assert!(tcp_writer_init(&opt("127.0.0.1:8080", "8080"), None).is_none());
        // Port parsing (strtoul base 0 semantics).
        assert!(tcp_writer_init(&opt("127.0.0.1", "65535"), None).is_some());
        assert!(tcp_writer_init(&opt("127.0.0.1", "65536"), None).is_none());
        assert!(tcp_writer_init(&opt("127.0.0.1", "8080junk"), None).is_none());
        assert!(tcp_writer_init(&opt("127.0.0.1", "-1"), None).is_none());
        assert!(tcp_writer_init(&opt("127.0.0.1", ""), None).is_some()); // port 0
        assert!(tcp_writer_init(&opt("127.0.0.1", "0x1F90"), None).is_some()); // hex 8080
        assert!(tcp_writer_init(&opt("127.0.0.1", " 8080"), None).is_some());
        assert!(tcp_writer_init(&opt("127.0.0.1", "0"), None).is_some());
    }

    #[test]
    fn strtoul_semantics() {
        assert_eq!(strtoul_base0("8080"), (8080, 4));
        assert_eq!(strtoul_base0("0x1F90"), (8080, 6));
        assert_eq!(strtoul_base0("0x"), (0, 1)); // 'x' not consumed
        assert_eq!(strtoul_base0("010"), (8, 3)); // octal
        assert_eq!(strtoul_base0(" 8080"), (8080, 5)); // whitespace skipped
        assert_eq!(strtoul_base0(""), (0, 0)); // empty: endptr == start
        assert_eq!(strtoul_base0("-1"), (u64::MAX, 2)); // wraps
        assert_eq!(strtoul_base0("8080junk"), (8080, 4)); // trailing garbage
        assert_eq!(strtoul_base0("+12"), (12, 3));
        assert_eq!(strtoul_base0("99999999999999999999999"), (u64::MAX, 23)); // wraps
    }

    #[test]
    fn inet_pton_semantics() {
        assert_eq!(inet_pton4("127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(inet_pton4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(inet_pton4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(inet_pton4("1.2.3.256"), None);
        assert_eq!(inet_pton4("01.2.3.4"), None);
        assert_eq!(inet_pton4("1.2.3"), None);
        assert_eq!(inet_pton4("1.2.3.4.5"), None);
        assert_eq!(inet_pton4("a.b.c.d"), None);
        assert_eq!(inet_pton6("::1"), Some([0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(
            inet_pton6("2001:db8::1"),
            Some([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            inet_pton6("::ffff:192.0.2.128"),
            Some([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0280])
        );
        assert_eq!(
            inet_pton6("1:2:3:4:5:6:7:8"),
            Some([1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(inet_pton6("1::2::3"), None); // two compressions
        assert_eq!(inet_pton6("::"), Some([0; 8]));
        assert_eq!(inet_pton6("fe80::1%eth0"), None); // zone id rejected
        assert_eq!(inet_pton6("12345::"), None); // group too long
    }

    #[test]
    fn tcp_writer_connect_failure() {
        // Port 1 on a loopback address with no listener: open fails.
        let mut w = tcp_writer_init(&opt("127.0.0.1", "1"), None).unwrap();
        assert_eq!(w.open(), Res::Failure);
    }

    #[test]
    fn tcp_writer_full_handshake() {
        // A real loopback listener; the accepted connection becomes the
        // reader side on its own thread.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

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

        let mut w = tcp_writer_init(&opt("127.0.0.1", &port.to_string()), None).unwrap();
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
    }
}
