#!/bin/bash

PACKAGE_ROOT=$1
NEW_VERSION=$2

sed -i '1i\\' "$PACKAGE_ROOT/CHANGELOG.md"  # Prepend a newline for separation
git-cliff --unreleased --tag "$NEW_VERSION" --include-path "${PACKAGE_ROOT}/**" --prepend "$PACKAGE_ROOT/CHANGELOG.md"
git add "*CHANGELOG.md"
