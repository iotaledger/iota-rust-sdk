#!/usr/bin/env bash
# Run a command, retrying it on failure.
#
# The examples run against the public networks, whose GraphQL and gRPC
# endpoints occasionally drop a request (query timeouts, transient
# `service unavailable`). A single dropped request should not fail CI.
#
# Usage: scripts/retry_example.sh <command> [args...]
# Attempts default to 3 and can be overridden with EXAMPLE_ATTEMPTS.

set -uo pipefail

attempts=${EXAMPLE_ATTEMPTS:-3}

for attempt in $(seq 1 "$attempts"); do
    "$@" && exit 0
    status=$?
    if [ "$attempt" -eq "$attempts" ]; then
        exit "$status"
    fi
    delay=$((attempt * 5))
    printf 'Attempt %d/%d failed with exit %d, retrying in %ds\n' \
        "$attempt" "$attempts" "$status" "$delay" >&2
    sleep "$delay"
done
