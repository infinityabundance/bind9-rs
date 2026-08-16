#!/usr/bin/env python3
"""One-off archaeology probe: log raw UDP query bytes BIND dig sends."""
import socket, sys, struct

port = int(sys.argv[1]) if len(sys.argv) > 1 else 5334
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
while True:
    data, addr = s.recvfrom(65535)
    print(f"LEN={len(data)} HEX={data.hex()}")
    sys.stdout.flush()
    ident = struct.unpack(">H", data[:2])[0]
    resp = struct.pack(">HHHHHH", ident, 0x8000, 0, 0, 0, 0)
    s.sendto(resp, addr)
