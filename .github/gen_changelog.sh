#!/bin/bash

PACKAGE=$1
PACKAGE_ROOT=$2
COMMIT_TO=$3
VERSION=$4
ADD=${5:-"false"}

git fetch --tags

echo "Generating changelog for package: $PACKAGE version $VERSION at $PACKAGE_ROOT" 1>&2

LATEST_TAG=$(git tag -l "$PACKAGE-v*" --sort=-v:refname | head -n 1)
echo "Latest tag: $LATEST_TAG" 1>&2

if [ -n "$LATEST_TAG" ]; then
    COMMIT_FROM=$(git show-ref $LATEST_TAG | cut -f 1 -d' ')
fi
echo "Commit from: $COMMIT_FROM" 1>&2

echo "Commit to: $COMMIT_TO" 1>&2

ENTRY=$(git-cliff "$COMMIT_FROM..$COMMIT_TO" --tag "$VERSION" --include-path "$PACKAGE_ROOT/**")
echo "$ENTRY"

if [ "$ADD" = "true" ]; then
    echo "git add $PACKAGE_ROOT/CHANGELOG.md" 1>&2
    echo -e "$ENTRY\n\n$(cat $PACKAGE_ROOT/CHANGELOG.md)" > $PACKAGE_ROOT/CHANGELOG.md
    git add $PACKAGE_ROOT/CHANGELOG.md
fi
