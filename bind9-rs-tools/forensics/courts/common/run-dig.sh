#!/bin/sh
# run-dig.sh — shared dig court runner.
#
# Usage: run-dig.sh <oracle|rust> <cases-file>
#
# Reads one dig argv per line from <cases-file> and emits a delimited record
# per case to stdout (the court runner captures it):
#
#   ### CASE <n>: <argv>
#   --- STDOUT
#   ...
#   --- STDERR
#   ...
#   --- EXIT <rc>
#
# The oracle side runs the pinned BIND dig in the oracle container with
# --network host (so @127.0.0.1 -p <port> reaches the host responder); the
# rust side runs the workspace dig binary.  HOME is pinned to a scratch dir
# with no .digrc for both sides; IDN_DISABLE is unset (libidn2-enabled
# default, matching a BIND built with --with-libidn2).

set -eu

side=$1
cases=$2
court_dir=$(dirname "$0")/..
# Walk up until the workspace dig binary exists (the workspace target dir
# lives at the workspace root, not under a crate dir).
repo=$(cd "$court_dir" && while [ ! -x target/debug/dig ] && [ "$PWD" != "/" ]; do cd ..; done; pwd)
[ -x "$repo/target/debug/dig" ] || {
    echo "rust dig missing; run cargo build -p bind9-rs-tools --bin dig" >&2
    exit 1
}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

case "$side" in
    oracle)
        # ORACLE_IMAGE may point the court at the IDN-enabled oracle.
        image=${ORACLE_IMAGE:-oracle-bind-9.20.26}
        dig() {
            # IDN_DISABLE deliberately NOT passed: the container never has it
            # set, so BIND's getenv("IDN_DISABLE") == NULL → IDN enabled
            # (dighost.c make_empty_lookup).  LANG is passed through so the
            # court can pin a UTF-8 locale (idn_input is locale-sensitive).
            docker run --rm --network host -e HOME=/tmp -v "$scratch:/scratch" \
                -e LANG "$image" dig "$@"
        }
        ;;
    rust)
        dig() {
            # IDN_DISABLE must be *unset* (BIND: getenv() == NULL enables IDN);
            # `IDN_DISABLE=` would set it empty, which disables IDN.
            env -u IDN_DISABLE HOME="$scratch" "$repo/target/debug/dig" "$@"
        }
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac

n=0
while IFS= read -r line || [ -n "$line" ]; do
    # Skip blank lines and comments.
    case "$line" in
        "" | \#*) continue ;;
    esac
    n=$((n + 1))
    echo "### CASE $n: $line"
    echo "--- STDOUT"
    # shellcheck disable=SC2086
    dig $line > "$scratch/out" 2> "$scratch/err" || rc=$?
    rc=${rc:-0}
    cat "$scratch/out"
    echo "--- STDERR"
    cat "$scratch/err"
    echo "--- EXIT $rc"
    rm -f "$scratch/out" "$scratch/err"
    unset rc
done < "$cases"
