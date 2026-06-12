#!/usr/bin/env bash
# Fetch the compiled IOTA system-package blobs and `published_api.txt` from
# the iota monorepo into `crates/iota-sdk-move-types/src/packages_compiled/`.
#
# The fetched files are not committed (the directory is gitignored); they
# are build inputs for the `move_shape_compare` tests, which `include_bytes!`
# them to cross-check each Rust mirror against its Move-side counterpart.
# `published_api.txt` is the upstream's public-API manifest — only
# `public struct`/`public enum` records are kept (function-signature churn
# is irrelevant to this crate). The nightly drift workflow diffs the
# manifest at the pinned rev against the one at upstream `develop` HEAD,
# applying the same filter to both.
#
# By default artifacts are fetched at the monorepo rev pinned by the
# `move-binary-format` dev-dependency in this crate's Cargo.toml — the
# single source of truth for the pin, since the parser must match the
# blobs it parses. Local runs and CI thus test the exact same bytes.
#
# Usage:
#   ./update_compiled_packages.sh                 # pulls at the pinned rev (default)
#   ./update_compiled_packages.sh develop         # pulls from a branch
#   ./update_compiled_packages.sh <sha>           # pulls at a specific commit
#
# Run via `make update-compiled-packages [REF=<branch-or-sha>]` from the
# repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The pinned monorepo rev is the `rev` of the `move-binary-format`
# dev-dependency in this crate's Cargo.toml. It is resolved through
# `cargo metadata` (cargo's own manifest parser) rather than by parsing
# the TOML textually, so manifest reformatting can't break it — and the
# script can never disagree with the rev the build actually uses.
# `--no-deps` keeps the call offline (no dependency resolution).
pinned_rev() {
    command -v jq >/dev/null || {
        echo "error: jq is required to resolve the pinned rev from cargo metadata" >&2
        exit 1
    }
    local source rev
    source="$(cargo metadata --no-deps --format-version 1 --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        | jq -r '.packages[]
                 | select(.name == "iota-sdk-move-types")
                 | .dependencies[]
                 | select(.name == "move-binary-format")
                 | .source')"
    rev="${source##*rev=}"
    if [[ ! "$rev" =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: could not resolve a 40-hex 'rev' for the move-binary-format dependency (source: ${source:-<none>})" >&2
        exit 1
    fi
    echo "$rev"
}

REPO="iotaledger/iota"
SRC_BASE="crates/iota-framework"
TARGET_DIR="$SCRIPT_DIR/src/packages_compiled"
# Records the ref the artifacts were last fetched at, so `--ensure` can
# skip the download when they already match the pin.
STAMP="$TARGET_DIR/.fetched-ref"

# `--ensure` (used by the make targets): fetch only when the artifacts are
# missing or were fetched at a different ref than the current pin. Keeps
# repeated `make test` runs offline-friendly while still re-fetching
# automatically after a pin bump (and re-pinning after a REF= override).
if [[ "${1:-}" == "--ensure" ]]; then
    REF="$(pinned_rev)"
    if [[ -f "$TARGET_DIR/published_api.txt" && -f "$STAMP" \
        && "$(cat "$STAMP")" == "$REF" ]]; then
        exit 0
    fi
else
    REF="${1:-$(pinned_rev)}"
fi

# Each entry: <source-path-under-$SRC_BASE>:<dest-filename-under-$TARGET_DIR>
ARTIFACTS=(
    "packages_compiled/iota-framework:iota-framework"
    "packages_compiled/move-stdlib:move-stdlib"
    "packages_compiled/iota-system:iota-system"
    "packages_compiled/stardust:stardust"
    "published_api.txt:published_api.txt"
)

echo "Fetching artifacts from $REPO@$REF into:"
echo "  $TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Keep only `public struct` / `public enum` records (3-line records whose
# second line ends in `struct` or `enum`) from the published_api.txt
# manifest. Used by both this script and the nightly drift workflow.
filter_published_api() {
    awk '
        NR%3==1 {name=$0}
        NR%3==2 {kind=$0}
        NR%3==0 {
            if (kind ~ /(struct|enum)$/) {
                print name; print kind; print $0
            }
        }
    ' "$1"
}

for entry in "${ARTIFACTS[@]}"; do
    src="${entry%%:*}"
    dst="${entry##*:}"
    url="https://raw.githubusercontent.com/$REPO/$REF/$SRC_BASE/$src"
    out="$TARGET_DIR/$dst"
    printf "  %-20s <- %s\n" "$dst" "$url"
    curl --fail --location --silent --show-error --retry 3 "$url" --output "$out"
    if [[ "$dst" == "published_api.txt" ]]; then
        filter_published_api "$out" > "$out.tmp"
        mv "$out.tmp" "$out"
    fi
done

echo "$REF" > "$STAMP"
echo "Done."
