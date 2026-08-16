#!/bin/sh
# harness.sh — court FSTRM-0001
#
# Both probes run in the SAME oracle-fstrm-0.6.1 container against the same
# /tmp/fstrm_work files (each probe starts from a clean directory).
#
#   oracle: gcc probe-fstrm.c -lfstrm -> captures/oracle/
#   rust:   /fstrm-probe              -> captures/rust/

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

docker run --rm --user "$(id -u):$(id -g)" \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/fstrm-probe:/fstrm-probe:ro" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-fstrm-0.6.1 sh -c '
        set -eu
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-fstrm.c \
            -L/opt/dep/lib -lfstrm
        rm -rf /tmp/fstrm_work && mkdir -p /tmp/fstrm_work
        /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
        printf "%s\n" "$?" > /captures/oracle/exit.txt
        rm -rf /tmp/fstrm_work && mkdir -p /tmp/fstrm_work
        /fstrm-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
        printf "%s\n" "$?" > /captures/rust/exit.txt
    '
