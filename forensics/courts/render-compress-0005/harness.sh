#!/bin/sh
# harness.sh — court RENDER-COMPRESS-0005 (dns_compress_setpermitted(false):
# no pointers emitted, but names still populate the table — RFC 3597
# per-name compression control).

set -eu

side=$1
court_dir=$(dirname "$0")
repo=$(cd "$court_dir" && while [ ! -f Cargo.toml ] && [ "$PWD" != "/" ]; do cd ..; done; pwd)

case "$side" in
    oracle)
        probe="$repo/forensics/oracle/build/probe_compress"
        [ -x "$probe" ] || { echo "oracle probe missing; run scripts/oracle/build-oracle-probes.sh" >&2; exit 1; }
        mode="nopermit"
        ;;
    rust)
        probe="$repo/target/debug/probe-compress"
        [ -x "$probe" ] || { echo "rust probe missing; run cargo build -p bind9-rs-forensics --bins" >&2; exit 1; }
        mode="nopermit"
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac

mkdir -p "$court_dir/captures/$side"
"$probe" $mode < "$court_dir/inputs/names.txt"
