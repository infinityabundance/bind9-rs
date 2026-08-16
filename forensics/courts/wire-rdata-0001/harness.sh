#!/bin/sh
# harness.sh — court WIRE-RDATA-0001

set -eu

side=$1
court_dir=$(dirname "$0")
repo=$(cd "$court_dir" && while [ ! -f Cargo.toml ] && [ "$PWD" != "/" ]; do cd ..; done; pwd)

case "$side" in
    oracle)
        probe="$repo/forensics/oracle/build/probe_rdata"
        [ -x "$probe" ] || { echo "oracle probe missing; run scripts/oracle/build-oracle-probes.sh" >&2; exit 1; }
        ;;
    rust)
        probe="$repo/target/debug/probe-rdata"
        [ -x "$probe" ] || { echo "rust probe missing; run cargo build -p bind9-rs-forensics --bins" >&2; exit 1; }
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac

mkdir -p "$court_dir/captures/$side"
"$probe" < "$court_dir/inputs/cases.txt"
