#!/bin/sh
# harness.sh — court LMDB-0001 (§24, §25, §38).
#
# Both probes run in the SAME oracle-lmdb-0.9.35 container.  Each probe
# recreates its own /tmp/lmdb_work tree (fresh per side), runs the same
# deterministic op sequence, and writes the same structured page dumps, so
# the transcripts compare line-by-line.
#
#   oracle: gcc probe-lmdb.c -llmdb -> captures/oracle/
#   rust:   /lmdb-probe             -> captures/rust/
#
# With no arguments both sides run (writing the capture files, the manual
# repro flow).  With `oracle` or `rust` only that side runs and its transcript
# streams to stdout/stderr so the bind9-court runner captures it per side.

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

side="${1:-both}"

if [ "$side" = both ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$repo/target/debug/lmdb-probe:/lmdb-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-lmdb-0.9.35 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-lmdb.c \
                -L/opt/dep/lib -llmdb
            rm -rf /tmp/lmdb_work && mkdir -p /tmp/lmdb_work
            /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            rm -rf /tmp/lmdb_work && mkdir -p /tmp/lmdb_work
            /lmdb-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-lmdb-0.9.35 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-lmdb.c \
                -L/opt/dep/lib -llmdb
            rm -rf /tmp/lmdb_work && mkdir -p /tmp/lmdb_work
            exec /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/lmdb-probe:/lmdb-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-lmdb-0.9.35 sh -c '
            set -eu
            rm -rf /tmp/lmdb_work && mkdir -p /tmp/lmdb_work
            exec /lmdb-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
