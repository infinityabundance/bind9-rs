#!/bin/sh
# compare.sh — delegate to the shared dig comparator.
set -eu
sh "$(dirname "$0")/../common/compare-dig.sh" "$(cd "$(dirname "$0")" && pwd)"
