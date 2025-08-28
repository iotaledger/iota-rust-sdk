# IOTA SDK - Python Bindings

```sh
cargo build --all-features -p iota-sdk-ffi --lib --release
```

# Generate the Go bindings

## MacOS

```sh
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.dylib" --language python --out-dir bindings/python/lib --no-format
```

## Linux

```sh
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.so" --language python --out-dir bindings/python/lib --no-format
```

## Windows

```sh
cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi.dll" --language python --out-dir bindings/python/lib --no-format
```

# Run an example

```sh
PYTHONPATH=. python3 examples/chain_id.py
```

or

```sh
make python-example chain_id
```
