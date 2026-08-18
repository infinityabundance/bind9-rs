#!/bin/sh
# build-oracle-probes.sh — compile the C oracle probes against the pinned
# BIND install tree (forensics/oracle/work/install).  The probes are oracle
# tooling only (spec §2).
#
# Usage: scripts/oracle/build-oracle-probes.sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL="$REPO_ROOT/forensics/oracle/work/install"
PROBES="$REPO_ROOT/forensics/oracle/probes"
OUT="$REPO_ROOT/forensics/oracle/build"
SRC="$REPO_ROOT/forensics/oracle/work/bind-9.20.26"

if [ ! -d "$INSTALL/lib" ] || [ ! -d "$SRC" ]; then
    echo "error: oracle install tree not found (run the oracle build first)" >&2
    exit 1
fi

mkdir -p "$OUT"

CFLAGS="-O2 -Wall -I$INSTALL/include -I$SRC/lib/dns/include -I$SRC/lib/isc/include -I$SRC/include"
LIBS="-L$INSTALL/lib -ldns -lisc -Wl,-rpath,$INSTALL/lib"

# Only the BIND-tree probes (probe_*.c) link against this install; the
# hyphenated probes (probe-fstrm, probe-lmdb, ...) build inside their own
# oracle containers.
for probe in "$PROBES"/probe_*.c; do
    name=$(basename "$probe" .c)
    echo "building oracle probe: $name"
    gcc $CFLAGS -o "$OUT/$name" "$probe" $LIBS
done

echo "probes built in $OUT:"
ls -la "$OUT"
