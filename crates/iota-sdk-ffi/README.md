# IOTA SDK Bindings

This crate can generate bindings for various languages (Go, Kotlin, Python, etc.) using [UniFFI](https://github.com/mozilla/uniffi-rs).

## 1. Build the Rust FFI library

Start by building the library to generate the appropriate `.dylib` (Mac) or `.so` (Linux) files.

```sh
cargo build -p iota-sdk-ffi --lib --release
```

## 2. Generate the binding

Next, run the `iota_sdk_bindings` binary to generate the bindings for the desired language.

```sh
# Mac
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.dylib" --language python --out-dir bindings/python/lib --no-format

# Linux
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.so" --language python --out-dir bindings/python/lib --no-format
```

## 3. Copy the Rust FFI library to the output directory

```sh
# Mac
cp target/release/libiota_sdk_ffi.dylib bindings/python/lib/

# Linux
cp target/release/libiota_sdk_ffi.so bindings/python/lib/
```

Or alternatively, create a symbolic link to always point to the latest build.

```sh
# Mac
ln -s target/release/libiota_sdk_ffi.dylib bindings/python/lib/libiota_sdk_ffi.dylib

# Linux
ln -s target/release/libiota_sdk_ffi.so bindings/python/lib/libiota_sdk_ffi.so
```
