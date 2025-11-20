#!/bin/bash

git-cliff --prepend -o "$CRATE_ROOT/CHANGELOG.md" --tag "$NEW_VERSION"
git add "*CHANGELOG.md"
