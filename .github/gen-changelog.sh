#!/bin/bash

git-cliff --unreleased --prepend -o "$CRATE_ROOT/CHANGELOG.md"
git add "*CHANGELOG.md"
