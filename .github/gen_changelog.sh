#!/bin/bash

PACKAGE=$1
PACKAGE_ROOT=$2
COMMIT_TO=$3
VERSION=$4
ADD=$5

git fetch --tags

LATEST_TAG=$(git tag -l "$PACKAGE-v*" --sort=-v:refname | head -n 1)
echo "Latest tag: $LATEST_TAG"

COMMIT_FROM=$(git show-ref $LATEST_TAG | cut -f 1 -d' ')
echo "Commit from: $COMMIT_FROM"

echo "Commit to: $COMMIT_TO"

ENTRY=$(git-cliff $COMMIT_FROM..$COMMIT_TO --tag $VERSION --include-path $PACKAGE_ROOT)
echo "$ENTRY"

if [ "$ADD" = "true" ]; then
    echo -e "$ENTRY\n$(cat $PACKAGE_ROOT/CHANGELOG.md)" > $PACKAGE_ROOT/CHANGELOG.md
    git add $PACKAGE/CHANGELOG.md
fi
