#!/bin/sh
# harness.sh — court CAP-PROC-0001
#
# Compares the process-observable libcap surface: the C probe and the Rust
# mirror run in the SAME container so both observe identical kernel state.
#
# Usage: harness.sh <oracle|rust>

set -eu

side=$1
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
court_dir=$(dirname "$0")

case "$side" in
    oracle)
        "$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh \
            -v "$repo/forensics/oracle/probes:/probes" \
            oracle-libcap-2.78 sh -c \
            'gcc -I/opt/dep/include -o /tmp/proc /probes/probe-libcap-proc.c \
             -L/opt/dep/lib64 -lcap && /tmp/proc'
        ;;
    rust)
        # Run the Rust mirror inside the SAME oracle container (equivalent
        # capability context) via a static build copied in.
        "$repo"/bind9-rs-tools/forensics/courts/common/docker-run.sh \
            -v "$repo/target/debug/cap-proc-probe:/proc-probe:ro" \
            -v "$repo/forensics/oracle/probes:/probes" \
            oracle-libcap-2.78 sh -c '/proc-probe'
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac
