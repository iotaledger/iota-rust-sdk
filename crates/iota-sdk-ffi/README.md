# IOTA SDK FFI

This crate can generate bindings for various languages (Go, Kotlin, Python, etc.) using [UniFFI](https://github.com/mozilla/uniffi-rs).

Start by building the library to generate the appropriate dylib files.

```sh
cargo build -p iota-sdk-ffi --lib --release
```

Next, run the binary to generate the bindings for the desired language.

```sh
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.dylib" --language python --out-dir bindings/python/lib --no-format
```

Finally, copy the dylib file to the output directory.

```sh
cp target/release/libiota_sdk_ffi.dylib bindings/python/lib/
```

# Generate Bindings Script
```bash
#!/bin/bash
LANGUAGE="python"  # Change this to the desired language (e.g., go, kotlin, python)
# Start by building the library to generate the appropriate dylib files
cargo build -p iota-sdk-ffi --lib --release
# Determine the library extension based on the platform
case "$(uname -s)" in
  Darwin)   LIB_EXT=".dylib" ;;
  Linux)    LIB_EXT=".so" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;;
  *)        echo "Unsupported platform"; exit 1 ;;
esac
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi${LIB_EXT}" --language $LANGUAGE --out-dir bindings/$LANGUAGE/lib --no-format
#Finally, copy the library file to the output directory.
cp target/release/libiota_sdk_ffi${LIB_EXT} bindings/$LANGUAGE/lib/
```
