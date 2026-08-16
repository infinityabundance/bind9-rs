#!/bin/sh
# fetch-dependency-sources.sh — download and hash the BIND dependency source
# archives used by the oracle matrix (addendum §6, §7, §62).
#
# Pins: the versions the pinned BIND 9.20.26 oracle build linked against on
# the host (see bind9-rs-tools/forensics/manifests/dependencies-9.20.26.json),
# so the oracle images are reproducible against the same era of code the
# evidence was produced with.
#
# Writes: bind9-rs-tools/forensics/manifests/dependency-sources.json
#   { <dep>: { version, url, sha256, downloaded_at } }
#
# Usage: scripts/archaeology/fetch-dependency-sources.sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$REPO_ROOT/bind9-rs-tools/forensics/sources"
OUT="$REPO_ROOT/bind9-rs-tools/forensics/manifests/dependency-sources.json"
mkdir -p "$SRC"

# name|url-template|version  (url-template uses {ver})
# libuv/liburcu/zlib/fstrm use codeload source archives (upstream no longer
# attaches source tarballs to GitHub releases); json-c tags carry a date suffix
# (json-c-0.19-20260627) while the asset keeps the bare name.
DEPS="
libuv|https://github.com/libuv/libuv/archive/refs/tags/v{ver}.tar.gz|1.52.1
liburcu|https://github.com/urcu/userspace-rcu/archive/refs/tags/v{ver}.tar.gz|0.15.6
lmdb|https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_{ver}.tar.gz|0.9.35
libmaxminddb|https://github.com/maxmind/libmaxminddb/releases/download/{ver}/libmaxminddb-{ver}.tar.gz|1.13.3
zlib|https://github.com/madler/zlib/archive/refs/tags/v{ver}.tar.gz|1.3.1
libxml2|https://download.gnome.org/sources/libxml2/2.15/libxml2-{ver}.tar.xz|2.15.3
json-c|https://github.com/json-c/json-c/releases/download/json-c-0.19-20260627/json-c-{ver}.tar.gz|0.19
libcap|https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-{ver}.tar.xz|2.78
libedit|https://thrysoee.dk/editline/libedit-{ver}.tar.gz|20260512-3.1
libidn2|https://ftp.gnu.org/gnu/libidn/libidn2-{ver}.tar.gz|2.3.8
openssl|https://www.openssl.org/source/openssl-{ver}.tar.gz|3.6.3
fstrm|https://github.com/farsightsec/fstrm/archive/refs/tags/v{ver}.tar.gz|0.6.1
protobuf-c|https://github.com/protobuf-c/protobuf-c/releases/download/v{ver}/protobuf-c-{ver}.tar.gz|1.5.2
"

RESULTS="{}"
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

for entry in $DEPS; do
    name=$(echo "$entry" | cut -d'|' -f1)
    tmpl=$(echo "$entry" | cut -d'|' -f2)
    ver=$(echo "$entry" | cut -d'|' -f3)
    url=$(echo "$tmpl" | sed "s|{ver}|$ver|g")
    # codeload archives have no useful basename; give them one.
    case "$url" in
        *archive/refs/tags/*)
            base="$name-$ver.tar.gz" ;;
        *)
            base=$(basename "$url") ;;
    esac
    dest="$SRC/$base"
    if [ ! -f "$dest" ]; then
        if ! curl -fSL --retry 2 -o "$dest" "$url"; then
            echo "warning: failed to download $name ($url)" >&2
            rm -f "$dest"
            continue
        fi
    fi
    sha=$(sha256sum "$dest" | cut -d' ' -f1)
    echo "$name $ver: $sha"
    RESULTS=$(python3 -c "
import json, sys
r = json.loads('$RESULTS')
r['$name'] = {'version': '$ver', 'url': '$url', 'sha256': '$sha', 'downloaded_at': '$DATE'}
print(json.dumps(r))
")
done

printf '%s' "$RESULTS" | python3 -m json.tool > "$OUT"
echo "wrote $OUT"
