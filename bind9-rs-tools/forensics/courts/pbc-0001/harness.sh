#!/bin/sh
# harness.sh — court PBC-0001 (§26, §38).
#
# Both probes run in the SAME oracle-protobuf-c-1.5.2 container.
#
#   oracle: gcc probe-protobuf-c.c + protobuf-c-gen/*.pb-c.c -lprotobuf-c
#   rust:   /protobuf-c-probe
#
# The oracle probe compiles the checked-in protoc-gen-c 1.5.2 fixtures
# (generated from the pinned tarball's own t/test-full.proto and
# t/test-proto3.proto) against the runtime library built from the pinned
# tarball — the exact pipeline BIND uses for dns_message.pb-c.h.
#
# With no arguments both sides run (writing the capture files, the manual
# repro flow).  With `oracle` or `rust` only that side runs and its
# transcript streams to stdout/stderr so the bind9-court runner captures it
# per side.

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

side="${1:-both}"

if [ "$side" = both ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$repo/target/debug/protobuf-c-probe:/protobuf-c-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-protobuf-c-1.5.2 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-protobuf-c.c \
                /probes/protobuf-c-gen/test-full.pb-c.c \
                /probes/protobuf-c-gen/test-proto3.pb-c.c \
                -L/opt/dep/lib -lprotobuf-c
            /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            /protobuf-c-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-protobuf-c-1.5.2 sh -c '
            set -eu
            gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-protobuf-c.c \
                /probes/protobuf-c-gen/test-full.pb-c.c \
                /probes/protobuf-c-gen/test-proto3.pb-c.c \
                -L/opt/dep/lib -lprotobuf-c
            exec /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/protobuf-c-probe:/protobuf-c-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-protobuf-c-1.5.2 sh -c '
            set -eu
            exec /protobuf-c-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
