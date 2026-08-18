#!/bin/sh
# harness.sh — court LE-0001 (§29, §38, §64 Phase 9).
#
# Both probes run in the SAME oracle-libedit-20260512-3.1 container.  The
# oracle probe is compiled against the pinned /opt/dep install; the Rust
# probe is statically self-contained (it models the pty line discipline in
# its out/err sinks), so both sides observe the same TERM/terminfo and
# locale environment and the transcripts compare byte-exactly.
#
#   oracle: gcc probe-libedit.c -ledit -> captures/oracle/
#   rust:   /libedit-probe             -> captures/rust/
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
        -v "$repo/target/debug/libedit-probe:/libedit-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libedit-20260512-3.1 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-libedit.c \
                -L/opt/dep/lib -ledit
            /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            /libedit-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libedit-20260512-3.1 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-libedit.c \
                -L/opt/dep/lib -ledit
            exec /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/libedit-probe:/libedit-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-libedit-20260512-3.1 sh -c '
            set -eu
            exec /libedit-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
