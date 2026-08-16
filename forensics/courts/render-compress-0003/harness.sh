#!/bin/sh
# harness.sh — court RENDER-COMPRESS-0003 (DNS_COMPRESS_CASE: case-sensitive
# suffix matching; named's default for query responses unless the peer
# matches the view's nocasecompress ACL — lib/ns/client.c).

set -eu

side=$1
court_dir=$(dirname "$0")
repo=$(cd "$court_dir" && while [ ! -f Cargo.toml ] && [ "$PWD" != "/" ]; do cd ..; done; pwd)

case "$side" in
    oracle)
        probe="$repo/forensics/oracle/build/probe_compress"
        [ -x "$probe" ] || { echo "oracle probe missing; run scripts/oracle/build-oracle-probes.sh" >&2; exit 1; }
        mode="case"
        ;;
    rust)
        probe="$repo/target/debug/probe-compress"
        [ -x "$probe" ] || { echo "rust probe missing; run cargo build -p bind9-rs-forensics --bins" >&2; exit 1; }
        mode="case"
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac

mkdir -p "$court_dir/captures/$side"
"$probe" $mode < "$court_dir/inputs/names.txt"
