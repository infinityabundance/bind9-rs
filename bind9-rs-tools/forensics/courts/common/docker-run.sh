#!/bin/sh
# docker-run.sh — docker run with OOM-protection resource limits (§78).
#
# Every court harness that executes oracle/rust probes inside a container
# runs them through this wrapper, so a runaway or hung probe cannot exhaust
# the host:
#
#   --memory 1g --memory-swap 1g   the container is capped at 1 GiB of RAM
#                                  with swap disabled (no swap thrash; a
#                                  leak aborts inside the container instead
#                                  of starving the host — this is what
#                                  previously filled the /run tmpfs and
#                                  stalled the harness)
#   --pids-limit 256               a forking probe cannot fork-bomb the host
#   --rm                           the container is auto-removed on exit
#
# The limits can be raised for a specific court without editing this file:
#   DOCKER_RUN_MEM=2g DOCKER_RUN_PIDS=1024 bind9-court run NETMGR-0001
#
# Usage: docker-run.sh [docker-run-args...] <image> [cmd...]
#        (exactly the arguments `docker run` would take after `--rm`)
set -eu

mem="${DOCKER_RUN_MEM:-1g}"
pids="${DOCKER_RUN_PIDS:-256}"

exec docker run --rm \
    --memory "$mem" \
    --memory-swap "$mem" \
    --pids-limit "$pids" \
    "$@"
