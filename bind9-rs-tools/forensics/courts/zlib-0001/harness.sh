#!/bin/sh
# harness.sh — court ZLIB-0001
#
# Both probes run in the SAME oracle-zlib-1.3.1 container against the same
# /tmp/zwork files (each probe starts from a clean directory).
#
#   oracle: gcc probe-zlib.c -lz  -> captures/oracle/
#   rust:   /zlib-probe           -> captures/rust/

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

"$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh --user "$(id -u):$(id -g)" \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/zlib-probe:/zlib-probe:ro" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-zlib-1.3.1 sh -c '
        set -eu
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-zlib.c \
            -L/opt/dep/lib -lz
        rm -rf /tmp/zwork && mkdir -p /tmp/zwork
        /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
        printf "%s\n" "$?" > /captures/oracle/exit.txt
        rm -rf /tmp/zwork && mkdir -p /tmp/zwork
        /zlib-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
        printf "%s\n" "$?" > /captures/rust/exit.txt
    '
