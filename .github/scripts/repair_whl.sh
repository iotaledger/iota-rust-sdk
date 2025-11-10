#!/bin/bash
set -Eeuo pipefail

if (( $# != 2 )); then
  echo "Usage: $0 /path/to/iota_sdk-x.y.z-*.whl LIB_EXT" >&2
  exit 2
fi

BROKEN_WHEEL_FILEPATH=$(realpath "$1")
LIB_EXT=$2

# Create a temporary dir to unpack the broken wheel into
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

# Unpack the broken wheel into a temp dir
python -m wheel unpack --dest "$TEMP_DIR" "$BROKEN_WHEEL_FILEPATH" >/dev/null

# Determine the name of the unpacked directory `iota_sdk-x.y.z` which is the only sub directory
UNPACKED_DIR="$(find "$TEMP_DIR" -mindepth 1 -maxdepth 1 -type d -print -quit)"
UNPACKED_PKG_DIR="$UNPACKED_DIR/iota_sdk"

# Fix the file name to what the `iota_sdk_ffi.py` stub expects
mv "$UNPACKED_PKG_DIR/libuniffi_iota_sdk_ffi.$LIB_EXT" "$UNPACKED_PKG_DIR/libiota_sdk_ffi.$LIB_EXT"

# Repack the wheel into a new `.whl` file, ensuring the RECORD file is updated
python -m wheel pack --dest "$TEMP_DIR" "$UNPACKED_DIR" >/dev/null
FIXED_WHEEL_PATH="$(find "$TEMP_DIR" -maxdepth 1 -type f -name '*.whl' -print -quit)"

# Replace the broken wheel with the fixed one
mv "$FIXED_WHEEL_PATH" "$BROKEN_WHEEL_FILEPATH"
echo "Repaired wheel at $BROKEN_WHEEL_FILEPATH"
