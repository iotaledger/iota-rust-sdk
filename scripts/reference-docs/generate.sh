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
#   swift:  Swift 6 toolchain
#   wasm:   pnpm, wasm-pack, wasm-bindgen-cli, the wasm32-unknown-unknown
#           target, and typedoc + typedoc-plugin-markdown on PATH
#
# Usage: scripts/reference-docs/generate.sh [python|go|kotlin|csharp|swift|wasm|all]
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
    python3 "$SCRIPT_DIR/split_python_api.py" \
        "$OUT_DIR/python/docs/python/iota_sdk.md" \
        bindings/python/lib/iota_sdk.py \
        "$OUT_DIR/python/docs/python"
    rm -f "$OUT_DIR/python/docs/python/iota_sdk.md" \
        "$OUT_DIR/python/docs/python/sidebar.json"
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
    dll="$(find bindings/csharp/src/IotaSdk/bin/Release -name IotaSdk.dll -print -quit)"
    if [ -z "$dll" ]; then
        echo "IotaSdk.dll not found under bindings/csharp/src/IotaSdk/bin/Release" >&2
        exit 1
    fi
    xmldoc2md "$dll" --output "$OUT_DIR/csharp/docs/csharp" \
        --platform docusaurus --member-accessibility-level public
    # Drop UniFFI plumbing pages and their index entries.
    find "$OUT_DIR/csharp/docs/csharp" -name '*._uniffilib.*' -delete
    sed -i.bak '/_uniffilib/d' "$OUT_DIR/csharp/docs/csharp/index.md" &&
        rm -f "$OUT_DIR/csharp/docs/csharp/index.md.bak"
    package csharp
}

gen_swift() {
    make swift
    rm -rf "$OUT_DIR/swift"
    mkdir -p "$OUT_DIR/swift/docs"
    (cd bindings/swift && swift package dump-symbol-graph)
    local graph
    graph="$(find bindings/swift/.build -name 'IotaSDK.symbols.json' -print -quit)"
    if [ -z "$graph" ]; then
        echo "IotaSDK.symbols.json not found under bindings/swift/.build" >&2
        exit 1
    fi
    python3 "$SCRIPT_DIR/swift_symbolgraph_to_md.py" "$graph" "$OUT_DIR/swift/docs/swift"
    package swift
}

gen_wasm() {
    make wasm
    rm -rf "$OUT_DIR/wasm"
    mkdir -p "$OUT_DIR/wasm/docs/wasm"
    (cd "$SCRIPT_DIR" && typedoc --options typedoc-wasm.json --out "$OUT_DIR/wasm/docs/wasm")
    python3 "$SCRIPT_DIR/postprocess_wasm.py" "$OUT_DIR/wasm/docs/wasm"
    package wasm
}

case "${1:-all}" in
python) gen_python ;;
go) gen_go ;;
kotlin) gen_kotlin ;;
csharp) gen_csharp ;;
swift) gen_swift ;;
wasm) gen_wasm ;;
all)
    gen_python
    gen_go
    gen_kotlin
    gen_csharp
    gen_swift
    gen_wasm
    ;;
*)
    echo "Unknown language: $1" >&2
    exit 1
    ;;
esac
