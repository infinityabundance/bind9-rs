#!/bin/sh
# harness.sh — court JSON-0001
#
# Both probes run in the SAME oracle-json-c-0.19 container.
#
#   oracle: gcc probe-jsonc.c      -> captures/oracle/
#   rust:   /jsonc-probe           -> captures/rust/

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

docker run --rm \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/jsonc-probe:/jsonc-probe:ro" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-json-c-0.19 sh -c '
        set -eu
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-jsonc.c \
            -L/opt/dep/lib -ljson-c
        /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
        printf "%s\n" "$?" > /captures/oracle/exit.txt
        /jsonc-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
        printf "%s\n" "$?" > /captures/rust/exit.txt
    '
