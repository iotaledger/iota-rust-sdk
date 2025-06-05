cargo build --lib --release

cargo run -F=uniffi/cli --bin iota_graphql_client_bindings generate src/client.udl --language python --out-dir bindings/python/lib/

cp target/release/libiota_graphql_client.* bindings/python/lib/

python bindings/python/test.py
