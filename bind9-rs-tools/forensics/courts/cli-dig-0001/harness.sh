#!/bin/sh
# harness.sh — court CLI-DIG-0001
#
# Usage: harness.sh <oracle|rust>

set -eu

side=$1
court_dir=$(dirname "$0")
runner="$court_dir/../common/run-dig.sh"

sh "$runner" "$side" "$court_dir/inputs/cases.txt"
