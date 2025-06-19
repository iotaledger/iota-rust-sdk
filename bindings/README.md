This folder contains bindings generated with [UniFFI](https://github.com/mozilla/uniffi-rs).

In order to generate bindings for a specific language, start by building the library.

```sh
cargo build --lib --release -F uniffi
```

And then generate the bindings via the binary.

```sh

cargo run -F uniffi --bin iota_graphql_client_bindings -- generate --library "target/release/libiota_graphql_client.dylib" --language python --out-dir bindings/python/lib --no-format

cp target/release/libiota_graphql_client.* bindings/python/lib/

python bindings/python/test.py
```

## License

This project is available under the terms of the [Apache 2.0 license](LICENSE).
