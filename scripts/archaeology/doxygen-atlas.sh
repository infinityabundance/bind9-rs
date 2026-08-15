#!/bin/sh
# doxygen-atlas.sh — generate the BIND API atlas for a pinned oracle tree.
#
# Usage: scripts/archaeology/doxygen-atlas.sh [BIND_SOURCE_DIR]
#
# Produces:
#   forensics/oracle/work/doxygen-out/    (raw HTML + XML, gitignored)
#   forensics/archaeology/api-atlas/      (parsed per-library JSON inventories)
#
# The atlas is version-pinned: it runs over the exact source tree recorded
# in forensics/sources/manifest-*.json.  Changing the oracle baseline is a
# forensic event (spec §81) and regenerates the whole atlas.

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIND_SRC=${1:-"$REPO_ROOT/forensics/oracle/work/bind-9.20.26"}

if [ ! -f "$BIND_SRC/config.h" ]; then
    echo "error: $BIND_SRC is not a configured BIND build tree" >&2
    exit 1
fi

cd "$REPO_ROOT"

VERSION=$(grep -oE 'PACKAGE_VERSION "[^"]+"' "$BIND_SRC/config.h" | head -1 | cut -d'"' -f2)
echo "building API atlas for BIND $VERSION from $BIND_SRC"

OUT_DIR="$REPO_ROOT/forensics/oracle/work/doxygen-out"
# Hermetic regeneration: doxygen does not delete stale output files, so a
# removed INPUT surface would otherwise linger in the XML and pollute the
# atlas.  Clean the output tree first (it is gitignored derived data).
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# The doxygen config INPUT paths are relative to the BIND tree; run doxygen
# there with an absolute OUTPUT_DIRECTORY pointing back at the repo.
TMPCONF=$(mktemp)
sed "s|^OUTPUT_DIRECTORY.*|OUTPUT_DIRECTORY = $OUT_DIR|" \
    "$REPO_ROOT/scripts/archaeology/doxygen-atlas.conf" > "$TMPCONF"

(cd "$BIND_SRC" && doxygen "$TMPCONF")
rm -f "$TMPCONF"

echo "parsing doxygen XML into inventories"
python3 "$REPO_ROOT/scripts/archaeology/parse-doxygen-xml.py" \
    "$OUT_DIR/xml" \
    "$REPO_ROOT/forensics/archaeology/api-atlas" \
    "$VERSION"

echo "atlas complete:"
ls -la "$REPO_ROOT/forensics/archaeology/api-atlas/"
