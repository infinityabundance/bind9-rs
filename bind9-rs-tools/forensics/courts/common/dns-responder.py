#!/usr/bin/env python3
"""dns-responder.py — deterministic scripted DNS server for the CLI-DIG courts.

Serves UDP and TCP on 127.0.0.1:<port> with a fixed response table keyed by
(qname, qtype, qclass).  Deterministic by construction: the response echoes
the query's transaction ID, always sets QR|RA (and RD when the query set
it), and uses fixed TTLs, records and ordering.  Every received query is
logged to <logfile> (one line per query) for outbound-query parity courts.

EDNS surface: the query's OPT (if any) is parsed and echoed back — udp size,
version, DO flag and every option (COOKIE gets a fixed 16-byte server cookie
appended; NSID a fixed value; ECS/EXPIRE/KEEPALIVE/PADDING/custom options
are echoed).  Queries with an OPT version > 0 get BADVERS (ext-rcode 16).

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
        b = label.encode()
        if len(b) > 63:
            raise ValueError("label too long")
        out += bytes([len(b)]) + b
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


def opt_rr(udp_size, ext_rcode, version, do_flag, z, options):
    ttl = ((ext_rcode & 0xFF) << 24) | ((version & 0xFF) << 16) | ((do_flag & 1) << 15) | (z & 0x7FFF)
    return rr("", 41, udp_size, ttl, options)


def edns_opt(code, data):
    return struct.pack(">HH", code, len(data)) + data


# Fixed server-side values (pinned court fixtures).
SERVER_COOKIE = bytes.fromhex("0123456789abcdef1122334455667788")
NSID_VALUE = bytes.fromhex("726573706f6e646572")  # "responder"


def parse_query(data):
    """Parse the query header + question + OPT; returns a dict."""
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if qd != 1:
        raise ValueError(f"qd={qd}")
    off = 12
    qname, off = dec_name(data, off)
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    off += 4
    # Additional records: only an OPT is expected; parse it if present.
    opt = None  # dict(udp, ver, do, z, opts=[(code, data)])
    for _ in range(ar):
        name, off = dec_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 41:
            opt = {
                "udp": rclass,
                "ver": (ttl >> 16) & 0xFF,
                "do": (ttl >> 15) & 1,
                "z": ttl & 0x7FFF,
                "ext": (ttl >> 24) & 0xFF,
                "opts": [],
            }
            ooff = 0
            while ooff + 4 <= rdlen:
                code, olen = struct.unpack(">HH", rdata[ooff:ooff + 4])
                ooff += 4
                opt["opts"].append((code, rdata[ooff:ooff + olen]))
                ooff += olen
    return {
        "ident": ident,
        "flags": flags,
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
        "opt": opt,
    }


def build_response(query, rcode, answers, authority, additional, tc=False,
                   opt=None, flags_extra=0):
    """Wrap sections into a message echoing the query's ID, opcode, RD and
    the given rcode; QR and RA are forced."""
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    flags = (flags & 0x7900) | 0x8000 | 0x0080 | (rcode & 0xF) | flags_extra
    if tc:
        flags |= 0x0200
    q = parse_query(query)
    question = enc_name(q["qname"]) + struct.pack(">HH", q["qtype"], q["qclass"])
    additional = list(additional)
    if opt is not None:
        additional.append(opt)
    resp = struct.pack(
        ">HHHHHH", ident, flags, 1, len(answers), len(authority), len(additional)
    )
    resp += question
    for sec in (answers, authority, additional):
        for r in sec:
            resp += r
    return resp


# --------------------------------------------------------------------------
# response table
# --------------------------------------------------------------------------

def response_opt(query_opt):
    """Build the response OPT: echo udp size, version, DO, options.

    COOKIE: echo the client cookie + SERVER_COOKIE; NSID: fixed value;
    ECS/EXPIRE/KEEPALIVE/PADDING/custom: echoed verbatim.  A BADVERS reply
    (version > 0) carries ext-rcode 16 and no options.
    """
    if query_opt is None:
        return None
    if query_opt["ver"] > 0:
        return opt_rr(query_opt["udp"], 16, 0, 0, 0, b"")
    out_opts = []
    for code, data in query_opt["opts"]:
        if code == 10:  # COOKIE
            if data:
                out_opts.append(edns_opt(10, data + SERVER_COOKIE))
        elif code == 3:  # NSID
            out_opts.append(edns_opt(3, NSID_VALUE))
        else:
            out_opts.append(edns_opt(code, data))
    return opt_rr(query_opt["udp"], 0, 0, query_opt["do"], 0, b"".join(out_opts))


def answers_for(qname, qtype, qclass, query_opt):
    """Return (rcode, answers, authority, additional, tc_udp, opt, flags)."""
    a = []
    au = []
    ad = []
    tc = False
    rcode = 0
    extra_flags = 0

    def A(name, ip, ttl=3600):
        return rr(name, 1, 1, ttl, socket.inet_aton(ip))

    def AAAA(name, ip, ttl=3600):
        return rr(name, 28, 1, ttl, socket.inet_pton(socket.AF_INET6, ip))

    def NS(name, target):
        return rr(name, 2, 1, 3600, enc_name(target))

    def MX(name, pref, target):
        return rr(name, 15, 1, 3600, struct.pack(">H", pref) + enc_name(target))

    def TXT(name, strings, cls=1):
        rd = b"".join(bytes([len(s.encode())]) + s.encode() for s in strings)
        return rr(name, 16, cls, 3600, rd)

    def SOA(name):
        return rr(name, 6, 1, 3600, soa_rdata())

    def RRSIG(name, covered):
        # RRSIG(covered=A): alg 8, labels 2, origttl 3600, times fixed.
        sig = bytes.fromhex("ab") * 16
        rd = (
            struct.pack(">HBBIIIH", covered, 8, 2, 3600,
                        0x66B5D2E0, 0x661C6AE0, 0x3039)
            + enc_name("example.com.") + sig
        )
        return rr(name, 46, 1, 3600, rd)

    opt = response_opt(query_opt)

    if qclass == 3 and qname == "version.bind" and qtype in (16, 255):
        a.append(TXT("version.bind.", ["9.20.26"], cls=3))
    elif qname == "example.com" and qtype in (1, 255):
        a.append(A("example.com.", "192.0.2.1"))
    elif qname == "example.com" and qtype == 28:
        a.append(AAAA("example.com.", "2001:db8::1"))
    elif qname == "example.com" and qtype == 15:
        a.append(MX("example.com.", 10, "mail.example.com."))
        ad.append(A("mail.example.com.", "192.0.2.10"))
    elif qname == "example.com" and qtype == 16:
        a.append(TXT("example.com.", ["hello world"]))
    elif qname == "example.com" and qtype == 2:
        a.append(NS("example.com.", "ns1.example.com."))
        ad.append(A("ns1.example.com.", "192.0.2.53"))
    elif qname == "example.com" and qtype == 6:
        a.append(SOA("example.com."))
    elif qname == "a.example.com" and qtype in (1, 255):
        a.append(A("a.example.com.", "192.0.2.2"))
    elif qname == "long.example.com" and qtype in (1, 255):
        # Owner name longer than the 24-column style stop: exercises the
        # indent() "at least one space" edge.
        a.append(A("a-very-long-owner-name.example.com.", "192.0.2.3"))
    elif qname == "multi.example.com" and qtype in (16, 255):
        a.append(TXT("multi.example.com.", ["first", "second", "third"]))
    elif qname == "any.example.com" and qtype == 255:
        a.append(A("any.example.com.", "192.0.2.4"))
        a.append(AAAA("any.example.com.", "2001:db8::2"))
        a.append(MX("any.example.com.", 20, "mail.any.example.com."))
        a.append(TXT("any.example.com.", ["any text"]))
        ad.append(A("mail.any.example.com.", "192.0.2.20"))
    elif qname == "dnssec.example.com" and qtype in (1, 255):
        a.append(A("dnssec.example.com.", "192.0.2.5"))
        a.append(RRSIG("dnssec.example.com.", 1))
    elif qname == "idn.example.com" and qtype == 2:
        # NS target is an A-label: +idnout renders it as Unicode.
        a.append(NS("idn.example.com.", "ns.xn--mnchen-3ya.de."))
        ad.append(A("ns.xn--mnchen-3ya.de.", "192.0.2.77"))
    elif qname == "www.xn--mnchen-3ya.de" and qtype == 1:
        a.append(A("www.xn--mnchen-3ya.de.", "192.0.2.2"))
    elif qname == "badcookie.example.com" and qtype in (1, 255):
        # Echo a *different* client cookie + server cookie -> mismatch.
        a.append(A("badcookie.example.com.", "192.0.2.6"))
        if query_opt is not None:
            bad = bytes.fromhex("deadbeefdeadbeef") + SERVER_COOKIE
            opt = opt_rr(query_opt["udp"], 0, 0, 0, 0,
                         edns_opt(10, bad))
    elif qname == "nonexistent.example.com":
        rcode = 3  # NXDOMAIN
        au.append(SOA("example.com."))
    elif qname == "nodata.example.com":
        au.append(SOA("example.com."))
    elif qname == "servfail.example.com":
        rcode = 2  # SERVFAIL
    elif qname == "refused.example.com":
        rcode = 5  # REFUSED
    elif qname == "formerr.example.com":
        rcode = 1  # FORMERR
    elif qname == "opcodemismatch.example.com":
        # A response whose opcode differs from the query: courts dig's
        # opcode-mismatch warning and retry path.
        a.append(A("opcodemismatch.example.com.", "192.0.2.8"))
        extra_flags = 2 << 11  # opcode STATUS
    elif qname == "badvers.example.com":
        # BADVERS (ext-rcode 1 -> full rcode 16) with a version-0 OPT when
        # the query asks for EDNS version > 0: courts dig's EDNS-version
        # negotiation retry (dighost.c ednsneg path).
        if query_opt is not None and query_opt["ver"] > 0:
            opt = opt_rr(query_opt["udp"], 1, 0, 0, 0, b"")
        else:
            a.append(A("badvers.example.com.", "192.0.2.9"))
    elif qname == "ednsneg.example.com":
        # FORMERR when the query carries EDNS; NOERROR without.
        if query_opt is not None:
            rcode = 1
            opt = None
        else:
            a.append(A("ednsneg.example.com.", "192.0.2.7"))
    elif qname == "big.example.com" and qtype == 16:
        # Large response: TC on UDP, full answer on TCP.
        tc = True
        for i in range(5):
            a.append(TXT("big.example.com.", [f"record number {i}"]))
    elif qname == "malformed.example.com":
        # A record whose rdata is 3 bytes instead of 4: unparseable.  The
        # response OPT is suppressed so the bad-packet hex dump carries no
        # nondeterministic client-cookie bytes (the dump's ID bytes are
        # normalized by the comparator).
        a.append(rr("malformed.example.com.", 1, 1, 3600, b"\xc0\x00\x02"))
        opt = None
    return rcode, a, au, ad, tc, opt, extra_flags


def handle(data, proto):
    try:
        q = parse_query(data)
    except (ValueError, IndexError, UnicodeDecodeError):
        # Malformed query: FORMERR echoing the ID if we can read it.
        ident = struct.unpack(">H", data[:2])[0]
        resp = struct.pack(">HHHHHH", ident, 0x8000 | 0x0001, 0, 0, 0, 0)
        return resp
    log_query(q["qname"], q["qtype"], q["qclass"], proto)
    rcode, answers, authority, additional, tc, opt, extra_flags = answers_for(
        q["qname"], q["qtype"], q["qclass"], q["opt"]
    )
    return build_response(data, rcode, answers, authority, additional, tc, opt,
                          extra_flags)


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
