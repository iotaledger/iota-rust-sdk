# IOTA SDK Bindings

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
