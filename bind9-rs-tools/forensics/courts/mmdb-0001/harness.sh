#!/bin/sh
# harness.sh — court MMDB-0001
#
# Both probes run in the SAME oracle-libmaxminddb-1.13.3 container against
# the same pinned upstream test databases (test-data/ + bad-data/ mounted
# read-only), so filesystem, library and toolchain state are identical.
#
#   oracle: gcc probe-maxminddb.c  -> captures/oracle/
#   rust:   /maxminddb-probe       -> captures/rust/

set -eu

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(cd "$(dirname "$0")" && pwd)
mmdb_src="$repo/bind9-rs-tools/forensics/oracle/work/deps/libmaxminddb-1.13.3"
test_data="$mmdb_src/t/maxmind-db/test-data"
bad_data="$mmdb_src/t/maxmind-db/bad-data"

mkdir -p "$court_dir/captures/oracle" "$court_dir/captures/rust"

if [ ! -d "$test_data" ]; then
    echo "missing pinned test corpus: $test_data" >&2
    exit 1
fi

# Stage the corpus into work/db (hardlinks; same filesystem) so the
# container mounts one read-only tree containing both test-data/ and
# bad-data/ (nested read-only mounts are rejected by the runtime).
stage="$court_dir/work/db"
rm -rf "$stage"
mkdir -p "$stage/bad-data"
cp -al "$test_data"/. "$stage/"
cp -al "$bad_data"/. "$stage/bad-data/"

docker run --rm \
    -v "$stage:/opt/test-data:ro" \
    -v "$repo/forensics/oracle/probes:/probes:ro" \
    -v "$repo/target/debug/maxminddb-probe:/maxminddb-probe:ro" \
    -v "$court_dir/captures:/captures:rw" \
    oracle-libmaxminddb-1.13.3 sh -c '
        set -eu
        gcc -I/opt/dep/include -o /tmp/cprobe /probes/probe-maxminddb.c \
            -L/opt/dep/lib -lmaxminddb
        /tmp/cprobe /opt/test-data > /captures/oracle/stdout.txt \
            2> /captures/oracle/stderr.txt
        printf "%s\n" "$?" > /captures/oracle/exit.txt
        /maxminddb-probe /opt/test-data > /captures/rust/stdout.txt \
            2> /captures/rust/stderr.txt
        printf "%s\n" "$?" > /captures/rust/exit.txt
    '
