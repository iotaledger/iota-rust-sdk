#!/usr/bin/env bash
# Generates the per-language API reference markdown consumed by the docs
# site in the iota repository (docs/content/developer/iota-sdk/references/).
#
# Each language produces dist/reference-docs/<language>.tar.gz containing
# docs/<language>/**, the layout the docs build extracts.
#
# Requirements per language (in addition to the Rust toolchain):
#   python: pydoc-markdown        (pip install pydoc-markdown)
#   go:     gomarkdoc             (go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest)
#           uniffi-bindgen-go     (make install-uniffi-bindgen-go)
#   kotlin: JDK 21
#   csharp: .NET SDK 8, xmldoc2md (dotnet tool install -g XMLDoc2Markdown)
#           uniffi-bindgen-cs     (make install-uniffi-bindgen-cs)
#   swift:  docker (swiftdoc/swift-doc image)
#
# Usage: scripts/reference-docs/generate.sh [python|go|kotlin|csharp|swift|all]
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT_DIR="$REPO_ROOT/scripts/reference-docs"
OUT_DIR="$REPO_ROOT/dist/reference-docs"
cd "$REPO_ROOT"

package() {
    local language="$1"
    tar czf "$OUT_DIR/$language.tar.gz" -C "$OUT_DIR/$language" docs
    echo "Packaged $OUT_DIR/$language.tar.gz"
}

gen_python() {
    make python
    rm -rf "$OUT_DIR/python"
    mkdir -p "$OUT_DIR/python/docs"
    pydoc-markdown "$SCRIPT_DIR/pydoc-markdown.yml"
    package python
}

gen_go() {
    make go
    rm -rf "$OUT_DIR/go"
    mkdir -p "$OUT_DIR/go/docs"
    local tmp
    tmp="$(mktemp)"
    (cd bindings/go && gomarkdoc --output "$tmp" ./iota_sdk)
    python3 "$SCRIPT_DIR/split_go_api.py" "$tmp" "$OUT_DIR/go/docs/go"
    rm -f "$tmp"
    package go
}

gen_kotlin() {
    make kotlin
    rm -rf "$OUT_DIR/kotlin"
    mkdir -p "$OUT_DIR/kotlin/docs"
    (cd bindings/kotlin && ./gradlew --no-daemon dokkaGfm)
    python3 "$SCRIPT_DIR/postprocess_kotlin.py" \
        bindings/kotlin/build/dokka/gfm "$OUT_DIR/kotlin/docs/kotlin"
    package kotlin
}

gen_csharp() {
    make csharp
    rm -rf "$OUT_DIR/csharp"
    mkdir -p "$OUT_DIR/csharp/docs"
    dotnet build bindings/csharp/src/IotaSdk -c Release -p:GenerateDocumentationFile=true
    local dll
    dll="$(find bindings/csharp/src/IotaSdk/bin/Release -name IotaSdk.dll | head -1)"
    xmldoc2md "$dll" "$OUT_DIR/csharp/docs/csharp" --index-page-name index
    package csharp
}

gen_swift() {
    make swift
    rm -rf "$OUT_DIR/swift"
    mkdir -p "$OUT_DIR/swift/docs"
    docker run --rm -v "$REPO_ROOT/bindings/swift:/src" swiftdoc/swift-doc:latest \
        generate /src/Sources/IotaSDK --module-name IotaSDK \
        --format commonmark --output /src/build/reference-docs
    # The container writes as root; copy out and normalize the entry page.
    cp -R bindings/swift/build/reference-docs/. "$OUT_DIR/swift/docs/swift/"
    if [ -f "$OUT_DIR/swift/docs/swift/Home.md" ]; then
        mv "$OUT_DIR/swift/docs/swift/Home.md" "$OUT_DIR/swift/docs/swift/index.md"
    fi
    rm -f "$OUT_DIR/swift/docs/swift/_Sidebar.md" "$OUT_DIR/swift/docs/swift/_Footer.md"
    package swift
}

case "${1:-all}" in
python) gen_python ;;
go) gen_go ;;
kotlin) gen_kotlin ;;
csharp) gen_csharp ;;
swift) gen_swift ;;
all)
    gen_python
    gen_go
    gen_kotlin
    gen_csharp
    gen_swift
    ;;
*)
    echo "Unknown language: $1" >&2
    exit 1
    ;;
esac
