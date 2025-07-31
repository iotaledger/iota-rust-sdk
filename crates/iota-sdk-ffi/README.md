# IOTA SDK Bindings

This crate can generate bindings for various languages (Go, Kotlin, Python, etc.) using [UniFFI](https://github.com/mozilla/uniffi-rs).

## 1. Build the Rust FFI library

To build the Rust FFI library for the IOTA SDK, run:

```sh
cargo build -p iota-sdk-ffi --lib --release
```

Note that the generated library will have an OS specific file extension. For simplicity the commands below target Linux. But if you're using any other platform, please make sure to adapt the extension accordingly, i.e. Mac users need to replace `.so` with `.dylib`, Windows users `.so` with `.dll`.

## 2. Generate binding

Next, run the `iota_sdk_bindings` binary to generate the bindings for, e.g., Python, Kotlin, Go.
Note that the command below targets Python as an example. Make sure to change the `--language` parameter and the `--out-dir` path to your desired language, e.g. `kotlin`, `go`, etc.

```sh
cargo run --bin iota_sdk_bindings -- generate --library target/release/libiota_sdk_ffi.so --language python --out-dir bindings/python/lib --no-format
```

## 3. Copy or Link the FFI library

Copy the Rust FFI library to the output directory for the new binding:

```sh
cp target/release/libiota_sdk_ffi.so bindings/python/lib/
```

Alternatively (to skip this step for future builds), create a symbolic link to always point to the latest release build:

```sh
ln -s target/release/libiota_sdk_ffi.so bindings/python/lib/libiota_sdk_ffi.so
```
