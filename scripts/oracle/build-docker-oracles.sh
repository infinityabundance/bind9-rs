#!/bin/sh
# build-docker-oracles.sh — build the pinned Docker oracle images (addendum
# §11, §12) and record their digests + provenance in
# bind9-rs-tools/forensics/oracle/docker/images.json
#
# Usage:
#   scripts/oracle/build-docker-oracles.sh [bind]   # only the BIND oracle
#   scripts/oracle/build-docker-oracles.sh          # BIND + dependency oracles

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DOCKER_DIR="$REPO_ROOT/bind9-rs-tools/forensics/oracle/docker"
SRC_DIR="$REPO_ROOT/forensics/sources"
DEPS_SRC_DIR="$REPO_ROOT/bind9-rs-tools/forensics/sources"
OUT="$DOCKER_DIR/images.json"

mkdir -p "$DOCKER_DIR"

images() {
    # Build the BIND 9.20.26 tool oracle (context = pinned-source dir).
    docker build -f "$DOCKER_DIR/oracle-bind-9.20.26/Dockerfile" \
        -t oracle-bind-9.20.26 "$SRC_DIR" >/dev/null

    # Dependency oracles: context = the tools sources dir (their pinned
    # archives), so the COPY of each hashed archive resolves.
    for d in "$DOCKER_DIR"/oracle-*; do
        name=$(basename "$d")
        [ "$name" = "oracle-bind-9.20.26" ] && continue
        docker build -f "$d/Dockerfile" -t "$name" "$DEPS_SRC_DIR" >/dev/null
    done
}

images

DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT_FILE=$(mktemp)
python3 - "$DATE" "$OUT_FILE" << 'PYEOF'
import json, subprocess, sys

out = {}
proc = subprocess.run(
    ["docker", "images", "--format",
     "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Digest}}"],
    capture_output=True, text=True, check=True,
)
for line in proc.stdout.splitlines():
    repo, tag, iid, digest = line.split("\t")
    if not repo.startswith("oracle-"):
        continue
    out[repo] = {
        "tag": tag,
        "image_id": iid,
        "repo_digest": digest or None,
        "built_at": sys.argv[1],
        "dockerfile":
            f"bind9-rs-tools/forensics/oracle/docker/{repo}/Dockerfile",
    }

with open(sys.argv[2], "w") as f:
    json.dump({"schema_version": 1, "generated_at": sys.argv[1], "images": out},
              f, indent=2, sort_keys=True)
print(json.dumps(out, indent=2))
PYEOF
mv "$OUT_FILE" "$OUT"
