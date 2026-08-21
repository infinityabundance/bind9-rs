#!/bin/sh
# harness.sh — court LZ-0001 (libidn2 locale layer + NO_TR46; §28, §37).
#
# Both probes run in the SAME oracle-libidn2-2.3.8 container.  The probe has
# two sections: `locale` (run once per pinned locale: C.UTF-8, C and
# en_US.ISO-8859-1) and `algo` (locale-independent).  Every run appends to
# the same capture files so the transcripts compare line-by-line; the exit
# status is recorded per run.
#
#   oracle: gcc probe-libidn2-lz.c -lidn2 -> captures/oracle/
#   rust:   /libidn2-lz-probe             -> captures/rust/

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

"$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh --user "$(id -u):$(id -g)" \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/libidn2-lz-probe:/libidn2-lz-probe:ro" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-libidn2-2.3.8 sh -c '
        set -eu
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-libidn2-lz.c \
            -L/opt/dep/lib -lidn2
        run_side() {
            side=$1
            probe=$2
            rm -f /captures/$side/stdout.txt /captures/$side/stderr.txt \
                /captures/$side/exit.txt
            LANG=C.UTF-8 "$probe" locale >> /captures/$side/stdout.txt \
                2>> /captures/$side/stderr.txt
            printf "%s\n" "$?" >> /captures/$side/exit.txt
            LANG=C "$probe" locale >> /captures/$side/stdout.txt \
                2>> /captures/$side/stderr.txt
            printf "%s\n" "$?" >> /captures/$side/exit.txt
            LANG=en_US.ISO-8859-1 "$probe" locale >> /captures/$side/stdout.txt \
                2>> /captures/$side/stderr.txt
            printf "%s\n" "$?" >> /captures/$side/exit.txt
            LANG=C.UTF-8 "$probe" algo >> /captures/$side/stdout.txt \
                2>> /captures/$side/stderr.txt
            printf "%s\n" "$?" >> /captures/$side/exit.txt
        }
        run_side oracle /tmp/cprobe
        run_side rust /libidn2-lz-probe
    '
