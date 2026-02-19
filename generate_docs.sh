#!/bin/bash
# generate_docs.sh
set -e

echo "Step 1: Python Docs"
cd bindings/python

# Ensure virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# Ensure required build tools are installed in the venv
echo "Installing/Updating build tools..."
pip install --upgrade pip
pip install maturin

# Build native bindings so symbols are discoverable
cd src && maturin develop && cd ..

# Target the FFI layer specifically for full API coverage
echo "Extracting Python API reference..."
python3 -c "import iota_sdk.iota_sdk_ffi; help(iota_sdk.iota_sdk_ffi)" > python_api.md

deactivate
cd ../..

echo "Step 2: Kotlin Docs"
cd bindings/kotlin
# Disable config cache due to Dokka/Gradle 9.2 incompatibility
./gradlew dokkaGfm --no-configuration-cache
cd ../..

echo "Step 3: Go Docs"
cd bindings/go
# Target the specific subfolder containing the .go source
go doc -all ./iota_sdk > go_api.md
cd ../..

echo "All generations complete!"