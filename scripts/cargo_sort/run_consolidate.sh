#!/bin/bash

set -e  # Exit immediately if any command fails

source ./python_cmd.sh

$PYTHON_CMD cargo_sort.py --consolidate-deps \
  --strict \
  --strict-ignore "getrandom" \
  --strict-ignore "tracing:crates/iota-sdk/examples/polling-indexer" \
  --ignore "node_modules" \
  "$@"
