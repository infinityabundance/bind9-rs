#!/bin/sh
# harness.sh — court LIBUV-0001 (§30, §38).
#
# Both probes run in the SAME oracle-libuv-1.52.1 container, each running
# the same deterministic op sequence, so the transcripts compare
# line-by-line.
#
#   oracle: gcc probe-libuv.c -luv -lpthread -> captures/oracle/
#   rust:   /libuv-probe                        -> captures/rust/
#
# With no arguments both sides run (writing the capture files, the manual
# repro flow).  With `oracle` or `rust` only that side runs and its
# transcript streams to stdout/stderr so the bind9-court runner captures
# it per side.

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

side="${1:-both}"

if [ "$side" = both ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$repo/target/debug/libuv-probe:/libuv-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libuv-1.52.1 sh -c '
            set -eu
            gcc -Wall -Wextra -I/opt/dep/include -o /tmp/cprobe \
                /probes/probe-libuv.c -L/opt/dep/lib -luv -lpthread
            /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            /libuv-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libuv-1.52.1 sh -c '
            set -eu
            gcc -Wall -Wextra -I/opt/dep/include -o /tmp/cprobe \
                /probes/probe-libuv.c -L/opt/dep/lib -luv -lpthread
            exec /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/libuv-probe:/libuv-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libuv-1.52.1 sh -c '
            set -eu
            exec /libuv-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
