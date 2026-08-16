#!/usr/bin/env python3
"""dns-responder.py — deterministic scripted DNS server for the CLI-DIG courts.

Serves UDP and TCP on 127.0.0.1:<port> with a fixed response table keyed by
(qname, qtype).  Deterministic by construction: the response echoes the
query's transaction ID, always sets QR|RA (and RD when the query set it),
and uses fixed TTLs, records and ordering.  Every received query is logged
to <logfile> (one line per query) for outbound-query parity courts.

The wire messages are built by hand (no external DNS library) so the
responder itself is part of the pinned court fixture.
"""

import socket
import struct
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
LOG = sys.argv[2] if len(sys.argv) > 2 else "/tmp/dns-responder.log"

log_lock = threading.Lock()


def log_query(qname, qtype, qclass, proto):
    with log_lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{proto} {qname} {qtype} {qclass}\n")


# --------------------------------------------------------------------------
# wire helpers
# --------------------------------------------------------------------------

def enc_name(name):
    """Encode a dot-name; an empty name is the root."""
    out = b""
    if name in ("", "."):
        return b"\x00"
    for label in name.rstrip(".").split("."):
        if len(label) > 63:
            raise ValueError("label too long")
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dec_name(buf, off):
    """Decode a (uncompressed) name; returns (name, new_off)."""
    labels = []
    while True:
        n = buf[off]
        off += 1
        if n == 0:
            break
        if n & 0xC0:
            raise ValueError("compression pointer in query (not expected)")
        labels.append(buf[off:off + n].decode())
        off += n
    return ".".join(labels) if labels else ".", off


def rr(name, rtype, rclass, ttl, rdata):
    return enc_name(name) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def soa_rdata(mname="ns1.example.com.", rname="hostmaster.example.com."):
    return (
        enc_name(mname) + enc_name(rname)
        + struct.pack(">IIIII", 2024010101, 7200, 3600, 1209600, 3600)
    )


def build_response(query, rcode, answers, authority, additional, tc=False):
    """Wrap sections into a message echoing the query's ID and question."""
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    # echo RD, force QR and RA
    flags = (flags & 0x0100) | 0x8000 | 0x0080
    if tc:
        flags |= 0x0200
    # Re-encode only the question (the query's trailing records, e.g. an
    # OPT, must NOT be echoed into the question section).
    _, qname, qtype, qclass = parse_query(query)
    question = enc_name(qname) + struct.pack(">HH", qtype, qclass)
    resp = struct.pack(
        ">HHHHHH", ident, flags, 1, len(answers), len(authority), len(additional)
    )
    resp += question
    for sec in (answers, authority, additional):
        for r in sec:
            resp += r
    return resp


def parse_query(data):
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if qd != 1:
        raise ValueError(f"qd={qd}")
    off = 12
    qname, off = dec_name(data, off)
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    return ident, qname, qtype, qclass


# --------------------------------------------------------------------------
# response table
# --------------------------------------------------------------------------

def answers_for(qname, qtype):
    """Return (rcode, answers, authority, additional, tc_udp)."""
    a = []
    au = []
    ad = []
    tc = False
    rcode = 0

    def A(name, ip):
        return rr(name, 1, 1, 3600, socket.inet_aton(ip))

    def AAAA(name, ip):
        return rr(name, 28, 1, 3600, socket.inet_pton(socket.AF_INET6, ip))

    def NS(name, target):
        return rr(name, 2, 1, 3600, enc_name(target))

    def MX(name, pref, target):
        return rr(name, 15, 1, 3600, struct.pack(">H", pref) + enc_name(target))

    def TXT(name, text):
        b = text.encode()
        return rr(name, 16, 1, 3600, bytes([len(b)]) + b)

    def SOA(name):
        return rr(name, 6, 1, 3600, soa_rdata())

    if qname == "example.com" and qtype in (1, 255):
        a.append(A("example.com.", "192.0.2.1"))
    if qname == "example.com" and qtype == 28:
        a.append(AAAA("example.com.", "2001:db8::1"))
    if qname == "example.com" and qtype == 15:
        a.append(MX("example.com.", 10, "mail.example.com."))
        ad.append(A("mail.example.com.", "192.0.2.10"))
    if qname == "example.com" and qtype == 16:
        a.append(TXT("example.com.", "hello world"))
    if qname == "example.com" and qtype == 2:
        a.append(NS("example.com.", "ns1.example.com."))
        ad.append(A("ns1.example.com.", "192.0.2.53"))
    if qname == "example.com" and qtype == 6:
        a.append(SOA("example.com."))
    if qname == "idn.example.com" and qtype == 2:
        # NS target is an A-label: +idnout renders it as Unicode.
        a.append(NS("idn.example.com.", "ns.xn--mnchen-3ya.de."))
        ad.append(A("ns.xn--mnchen-3ya.de.", "192.0.2.77"))
    if qname == "www.xn--mnchen-3ya.de" and qtype == 1:
        a.append(A("www.xn--mnchen-3ya.de.", "192.0.2.2"))
    if qname == "nonexistent.example.com":
        rcode = 3  # NXDOMAIN
        au.append(SOA("example.com."))
    if qname == "nodata.example.com":
        au.append(SOA("example.com."))
    if qname == "servfail.example.com":
        rcode = 2  # SERVFAIL
    if qname == "refused.example.com":
        rcode = 5  # REFUSED
    if qname == "formerr.example.com":
        rcode = 1  # FORMERR
    if qname == "big.example.com" and qtype == 16:
        # Large response: TC on UDP, full answer on TCP.
        tc = True
        for i in range(5):
            a.append(TXT("big.example.com.", f"record number {i}"))
    return rcode, a, au, ad, tc


def handle(data, proto):
    try:
        ident, qname, qtype, qclass = parse_query(data)
    except (ValueError, IndexError, UnicodeDecodeError):
        # Malformed query: FORMERR echoing the ID if we can read it.
        ident = struct.unpack(">H", data[:2])[0]
        resp = struct.pack(">HHHHHH", ident, 0x8000 | 0x0001, 0, 0, 0, 0)
        return resp
    log_query(qname, qtype, qclass, proto)
    rcode, answers, authority, additional, tc = answers_for(qname, qtype)
    return build_response(data, rcode, answers, authority, additional, tc)


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        resp = handle(data, "udp")
        s.sendto(resp, addr)


def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        try:
            hdr = conn.recv(2)
            if len(hdr) != 2:
                conn.close()
                continue
            (n,) = struct.unpack(">H", hdr)
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
            resp = handle(data, "tcp")
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    threading.Thread(target=tcp_server, daemon=True).start()
    udp_server()
