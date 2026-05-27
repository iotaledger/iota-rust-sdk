#!/usr/bin/env bash
# Fetch the compiled IOTA system-package blobs and `published_api.txt` from
# the iota monorepo and overwrite the vendored copies under
# `crates/iota-sdk-move-types/src/packages_compiled/`.
#
# The blobs are read by `move_shape_compare.rs` to cross-check each Rust
# mirror against its Move-side counterpart. `published_api.txt` is the
# upstream's public-API manifest — its committed copy is diffed against
# the upstream version by the nightly drift workflow.
#
# Usage:
#   ./update_compiled_packages.sh                 # pulls from `develop` (default)
#   ./update_compiled_packages.sh main            # pulls from a different branch
#   ./update_compiled_packages.sh some-feature    # pulls from a topic branch
#
# Run via `make update-compiled-packages [BRANCH=<branch>]` from the repo root.

set -euo pipefail

BRANCH="${1:-develop}"
REPO="iotaledger/iota"
SRC_BASE="crates/iota-framework"
TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)/crates/iota-sdk-move-types/src/packages_compiled"

# Each entry: <source-path-under-$SRC_BASE>:<dest-filename-under-$TARGET_DIR>
ARTIFACTS=(
    "packages_compiled/iota-framework:iota-framework"
    "packages_compiled/move-stdlib:move-stdlib"
    "packages_compiled/iota-system:iota-system"
    "packages_compiled/stardust:stardust"
    "published_api.txt:published_api.txt"
)

echo "Fetching artifacts from $REPO@$BRANCH into:"
echo "  $TARGET_DIR"
mkdir -p "$TARGET_DIR"

for entry in "${ARTIFACTS[@]}"; do
    src="${entry%%:*}"
    dst="${entry##*:}"
    url="https://raw.githubusercontent.com/$REPO/$BRANCH/$SRC_BASE/$src"
    out="$TARGET_DIR/$dst"
    printf "  %-20s <- %s\n" "$dst" "$url"
    curl --fail --location --silent --show-error "$url" --output "$out"
done

echo "Done."
