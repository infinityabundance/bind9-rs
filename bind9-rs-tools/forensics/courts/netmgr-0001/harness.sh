#!/bin/sh
# harness.sh — court NETMGR-0001 (§30, §38).
#
# Both probes run in the SAME oracle-bind-9.20.26 container, each running
# the same deterministic op sequence over the public isc_nm_* surface plus
# the netmgr-int.h internal-state observations, so the transcripts compare
# line-by-line.
#
#   oracle: gcc probe-netmgr.c -lisc (the container's pinned BIND 9.20.26
#           libisc) -> captures/oracle/
#   rust:   /netmgr-probe                  -> captures/rust/
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
    "$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$repo/target/debug/netmgr-probe:/netmgr-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-bind-9.20.26 sh -c '
            set -eu
            gcc -w -DHAVE_LIBNGHTTP2=1 -DRCU_MEMBARRIER \
                -I/opt/bind/include -I/probes/netmgr-include \
                -I/usr/include/x86_64-linux-gnu -o /tmp/cprobe \
                /probes/probe-netmgr.c -L/opt/bind/lib -lisc -lpthread
            LD_LIBRARY_PATH=/opt/bind/lib /tmp/cprobe > /captures/oracle/stdout.txt 2> /captures/oracle/stderr.txt
            printf "%s\n" "$?" > /captures/oracle/exit.txt
            /netmgr-probe > /captures/rust/stdout.txt 2> /captures/rust/stderr.txt
            printf "%s\n" "$?" > /captures/rust/exit.txt
        '
elif [ "$side" = oracle ]; then
    "$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh --user "$(id -u):$(id -g)" \
        -v "$repo/forensics/oracle/probes:/probes:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-bind-9.20.26 sh -c '
            set -eu
            gcc -w -DHAVE_LIBNGHTTP2=1 -DRCU_MEMBARRIER \
                -I/opt/bind/include -I/probes/netmgr-include \
                -I/usr/include/x86_64-linux-gnu -o /tmp/cprobe \
                /probes/probe-netmgr.c -L/opt/bind/lib -lisc -lpthread
            exec env LD_LIBRARY_PATH=/opt/bind/lib /tmp/cprobe
        '
elif [ "$side" = rust ]; then
    "$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh --user "$(id -u):$(id -g)" \
        -v "$repo/target/debug/netmgr-probe:/netmgr-probe:ro" \
        -v "$court_dir/captures:/captures:rw" \
        oracle-bind-9.20.26 sh -c '
            set -eu
            exec /netmgr-probe
        '
else
    echo "usage: $0 [oracle|rust]" >&2
    exit 2
fi
