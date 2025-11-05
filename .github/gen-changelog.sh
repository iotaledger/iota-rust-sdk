#!/bin/bash

git-cliff -o "$CRATE_ROOT/CHANGELOG.md" --tag "$NEW_VERSION"
git add "*CHANGELOG.md"
