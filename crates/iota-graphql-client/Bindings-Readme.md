cargo build --lib --release -f uniffi

cargo run -F uniffi --bin iota_graphql_client_bindings -- generate --library "target/release/libiota_graphql_client.dylib" --language python --out-dir crates/iota-graphql-client/bindings/python/lib

cp target/release/libiota_graphql_client.* bindings/python/lib/

python bindings/python/test.py
