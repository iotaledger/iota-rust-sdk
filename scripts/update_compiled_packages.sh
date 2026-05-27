#!/usr/bin/env bash
# Fetch the compiled IOTA system-package blobs from the iota monorepo and
# overwrite the vendored copies under
# `crates/iota-sdk-move-types/src/packages_compiled/`.
#
# These blobs are read by `move_shape_compare.rs` to cross-check each Rust
# mirror against its Move-side counterpart.
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
SRC_PATH="crates/iota-framework/packages_compiled"
TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)/crates/iota-sdk-move-types/src/packages_compiled"

PACKAGES=(
    "iota-framework"
    "move-stdlib"
    "iota-system"
    "stardust"
)

echo "Fetching compiled packages from $REPO@$BRANCH into:"
echo "  $TARGET_DIR"
mkdir -p "$TARGET_DIR"

for pkg in "${PACKAGES[@]}"; do
    url="https://raw.githubusercontent.com/$REPO/$BRANCH/$SRC_PATH/$pkg"
    out="$TARGET_DIR/$pkg"
    printf "  %-16s <- %s\n" "$pkg" "$url"
    curl --fail --location --silent --show-error "$url" --output "$out"
done

echo "Done."
