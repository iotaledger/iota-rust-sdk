#!/bin/bash

sed -i '1i\\' "$CRATE_ROOT/CHANGELOG.md"  # Prepend a newline for separation
git-cliff --unreleased --tag "$NEW_VERSION" --prepend "$CRATE_ROOT/CHANGELOG.md"
git add "*CHANGELOG.md"
