#!/bin/sh
# harness.sh — court CAP-PROBE-0001
#
# Runs the libcap surface probe on the requested side (§37 C probe courts):
#   oracle: compiles forensics/oracle/probes/probe-libcap.c against the
#           pinned libcap 2.78 in oracle-libcap-2.78 and runs it
#   rust:   runs the mirror probe (bind9-rs-tools/tests/cap_probe.rs)
#
# The probe output is deterministic and kernel-version-dependent only via
# cap_max_bits, which is identical for both sides (same kernel).
#
# Usage: harness.sh <oracle|rust>

set -eu

side=$1
repo=$(cd "$(dirname "$0")/../../../.." && pwd)

case "$side" in
    oracle)
        docker run --rm \
            -v "$repo/forensics/oracle/probes:/probes" \
            oracle-libcap-2.78 sh -c \
            'gcc -I/opt/dep/include -o /tmp/probe /probes/probe-libcap.c \
             -L/opt/dep/lib64 -lcap && /tmp/probe'
        ;;
    rust)
        # The test harness prints its own lines; keep only the probe output.
        cargo test -p bind9-rs-tools --test cap_probe -- --nocapture 2>/dev/null |
            grep -E '^(cap_|from_text|iab|after|fill|get_flag|set_flag|copy_)'
        ;;
    *)
        echo "unknown side: $side" >&2
        exit 2
        ;;
esac
