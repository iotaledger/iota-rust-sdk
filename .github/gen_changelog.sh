#!/bin/bash

PKG=$1
PKG_ROOT=$2
VERSION=$3
ADD=$4

git fetch --tags

LATEST_TAG=$(git tag -l "$PKG-v*" --sort=-v:refname | head -n 1)
echo "Latest tag: $LATEST_TAG"

COMMIT_FROM=$(git show-ref $LATEST_TAG | cut -f 1 -d' ')
echo "Commit from: $COMMIT_FROM"

COMMIT_TO=$(git show-ref $VERSION | cut -f 1 -d' ')
echo "Commit to: $COMMIT_TO"

ENTRY=$(git-cliff $COMMIT_FROM..$COMMIT_TO --tag $VERSION --include-path $PKG_ROOT)
echo "$ENTRY"

if [ "$ADD" = "true" ]; then
    echo -e "$ENTRY\n$(cat $PKG_ROOT/CHANGELOG.md)" > $PKG_ROOT/CHANGELOG.md
    git add $PKG/CHANGELOG.md
fi
