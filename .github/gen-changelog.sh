#!/bin/bash

sed -i '1i\\' "$CRATE_ROOT/CHANGELOG.md"  # Prepend a newline for separation
git-cliff --unreleased --tag "$NEW_VERSION" --include-path "$CRATE_ROOT" --prepend "$CRATE_ROOT/CHANGELOG.md"
git add "*CHANGELOG.md"
