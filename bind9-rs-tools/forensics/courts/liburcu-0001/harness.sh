#!/bin/sh
# harness.sh — court LIBURCU-0001 (§30, §38).
#
# Both probes run in the SAME oracle-liburcu-0.15.6 container, each running
# the same deterministic op sequence, so the transcripts compare
# line-by-line.
#
#   oracle: gcc probe-liburcu.c -lurcu -lpthread -> captures/oracle/
#   rust:   /liburcu-probe                         -> captures/rust/
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
        -v "$repo/target/debug/liburcu-probe:/liburcu-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-liburcu-0.15.6 sh -c '
            set -eu
            gcc -Wall -Wextra -I/opt/dep/include -o /tmp/cprobe \
                /probes/probe-liburcu.c -L/opt/dep/lib -lurcu -pthread
            /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            /liburcu-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-liburcu-0.15.6 sh -c '
            set -eu
            gcc -Wall -Wextra -I/opt/dep/include -o /tmp/cprobe \
                /probes/probe-liburcu.c -L/opt/dep/lib -lurcu -pthread
            exec /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/liburcu-probe:/liburcu-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-liburcu-0.15.6 sh -c '
            set -eu
            exec /liburcu-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
