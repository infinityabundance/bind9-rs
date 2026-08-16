#!/bin/sh
# doxygen-deps.sh — Doxygen source-surface archaeology for the BIND dependency
# set conserved by bind9-rs-tools (addendum §1, §7, §8).
#
# Conserved modules (addendum §3): LMDB, fstrm, libcap, libidn2, libedit,
# liburcu, libuv, protobuf-c, libmaxminddb, zlib, json-c.
# openssl and libxml2 are archived for oracle-environment provenance
# (dependencies-9.20.26.json) but are not conserved modules, so no atlas is
# generated for them here.
#
# For each dependency:
#   1. extract the pinned source archive (from dependency-sources.json)
#      into bind9-rs-tools/forensics/oracle/work/deps/<name>-<ver>/
#   2. run Doxygen (adapted from the BIND atlas configuration; no BIND input
#      filter, dependency-appropriate INCLUDE_PATH)
#   3. parse the XML into
#      bind9-rs-tools/forensics/atlas/doxygen/<name>/api-atlas/
#
# Usage: scripts/archaeology/doxygen-deps.sh [deps-dir]

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$REPO_ROOT/bind9-rs-tools/forensics/sources"
MANIFEST="$REPO_ROOT/bind9-rs-tools/forensics/manifests/dependency-sources.json"
DEPS_WORK=${1:-"$REPO_ROOT/bind9-rs-tools/forensics/oracle/work/deps"}
OUT_ATLAS="$REPO_ROOT/bind9-rs-tools/forensics/atlas/doxygen"

CONSERVED="lmdb fstrm libcap libidn2 libedit liburcu libuv protobuf-c libmaxminddb zlib json-c"

mkdir -p "$DEPS_WORK" "$OUT_ATLAS"

for dep in $CONSERVED; do
    ver=$(python3 -c "
import json
d = json.load(open('$MANIFEST'))
print(d['$dep']['version'])
")
    [ -n "$ver" ] || { echo "warning: no manifest entry for $dep" >&2; continue; }
    # Locate the archive by name+version (codeload names are name-ver.tar.gz).
    archive=""
    for f in "$SRC/$dep-$ver.tar."* "$SRC/$(python3 -c "
import json
d = json.load(open('$MANIFEST'))
print(d['$dep']['url'].split('/')[-1])
" 2>/dev/null)"; do
        [ -f "$f" ] && archive="$f" && break
    done
    if [ -z "$archive" ]; then
        echo "warning: no archive for $dep $ver" >&2
        continue
    fi

    tree="$DEPS_WORK/$dep-$ver"
    rm -rf "$tree"
    mkdir -p "$tree"
    case "$archive" in
        *.tar.xz) tar -xf "$archive" -C "$tree" --strip-components=1 ;;
        *) tar -xf "$archive" -C "$tree" --strip-components=1 ;;
    esac

    echo "== doxygen: $dep $ver ($archive)"
    xml_out="$DEPS_WORK/doxygen-xml/$dep"
    rm -rf "$xml_out"
    mkdir -p "$xml_out"

    # Dependency-specific include paths for macro resolution.
    inc=""
    case "$dep" in
        fstrm)        inc="INCLUDE_PATH = $tree/src/include $tree" ;;
        libcap)       inc="INCLUDE_PATH = $tree/libcap/include $tree" ;;
        libedit)      inc="INCLUDE_PATH = $tree/src $tree" ;;
        libidn2)      inc="INCLUDE_PATH = $tree/lib $tree" ;;
        libmaxminddb) inc="INCLUDE_PATH = $tree/src $tree" ;;
        libuv)        inc="INCLUDE_PATH = $tree/include $tree/src" ;;
        *)            inc="INCLUDE_PATH = $tree" ;;
    esac

    TMPCONF=$(mktemp)
    sed "s|@TREE@|$tree|g; s|@XMLOUT@|$xml_out|g; s|^INCLUDE_PATH.*|$inc|" \
        "$REPO_ROOT/scripts/archaeology/doxygen-dep.conf" > "$TMPCONF"
    (cd "$tree" && doxygen "$TMPCONF") >/dev/null 2>&1 || {
        echo "warning: doxygen failed for $dep" >&2
        rm -f "$TMPCONF"
        continue
    }
    rm -f "$TMPCONF"

    out="$OUT_ATLAS/$dep/api-atlas"
    mkdir -p "$out"
    python3 "$REPO_ROOT/scripts/archaeology/parse-doxygen-xml.py" \
        "$xml_out/xml" "$out" "$ver"

    n=$(find "$out" -name '*.json' | wc -l)
    echo "   atlas: $n inventory file(s) -> $out"
done

echo "dependency atlas complete: $OUT_ATLAS"
