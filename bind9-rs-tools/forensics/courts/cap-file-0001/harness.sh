#!/bin/sh
# harness.sh — court CAP-FILE-0001
#
# Four-corner file-capability court (§38): the C probe and the Rust mirror
# run in the SAME oracle-libcap-2.78 container sharing one /tmp directory
# (mounted from ./work), so both sides observe identical kernel capability
# context, filesystem and security.capability xattr state.
#
# Sequence (each full probe run leaves its own file in the v3 rootid=1000
# state, so both cross-reads observe the same deterministic state):
#
#   1. warm-up: C probe   writes /tmp/cap-c   (leaves cap-c = v3)
#   2. warm-up: Rust probe writes /tmp/cap-r  (leaves cap-r = v3)
#   3. capture: C probe   re-writes cap-c, cross-reads cap-r  -> oracle/
#   4. capture: Rust probe re-writes cap-r, cross-reads cap-c -> rust/
#
# Steps 3 and 4 are byte-identical because every section of the probe is
# deterministic and the cross-read target is the other side's identical v3
# file in both cases.
#
# The container runs with CAP_SETFCAP so the real kernel xattr path is
# exercised; if the host daemon cannot grant it, both sides still observe the
# identical failure and the court remains valid.

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

docker run --rm \
    --cap-add CAP_SETFCAP \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/cap-file-probe:/cap-file-probe:ro" \
    -v "$court_dir/work:/tmp:rw" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-libcap-2.78 sh -c '
        set -eu
        rm -f /tmp/cap-c /tmp/cap-r /tmp/fcap-link
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-libcap-file.c \
            -L/opt/dep/lib64 -lcap
        # warm-up: each side writes its own file
        /tmp/cprobe /tmp/cap-c /tmp/cap-r > /dev/null 2>&1
        /cap-file-probe /tmp/cap-r /tmp/cap-c > /dev/null 2>&1
        # captures: oracle first (C writes cap-c, cross-reads cap-r)
        /tmp/cprobe /tmp/cap-c /tmp/cap-r > /captures/oracle/stdout.txt \
            2> /captures/oracle/stderr.txt
        printf "%s\n" "$?" > /captures/oracle/exit.txt
        # then rust (Rust writes cap-r, cross-reads cap-c)
        /cap-file-probe /tmp/cap-r /tmp/cap-c > /captures/rust/stdout.txt \
            2> /captures/rust/stderr.txt
        printf "%s\n" "$?" > /captures/rust/exit.txt
    '
