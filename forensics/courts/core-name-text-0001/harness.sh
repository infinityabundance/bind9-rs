#!/bin/sh
# harness.sh — court CORE-NAME-TEXT-0001
#
# Usage: harness.sh <oracle|rust>
#
# Feeds inputs/names.txt to the probe binary of the given side and writes
# stdout to captures/<side>/stdout.txt.  The court runner records stderr and
# exit status as well.

set -eu

side=$1
court_dir=$(dirname "$0")
repo=$(cd "$court_dir" && while [ ! -f Cargo.toml ] && [ "$PWD" != "/" ]; do cd ..; done; pwd)

case "$side" in
    oracle)
        probe="$repo/forensics/oracle/build/probe_name"
        [ -x "$probe" ] || { echo "oracle probe missing; run scripts/oracle/build-oracle-probes.sh" >&2; exit 1; }
        ;;
    rust)
        probe="$repo/target/debug/probe-name"
        [ -x "$probe" ] || { echo "rust probe missing; run cargo build -p bind9-rs-forensics --bins" >&2; exit 1; }
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac

mkdir -p "$court_dir/captures/$side"
"$probe" < "$court_dir/inputs/names.txt"
