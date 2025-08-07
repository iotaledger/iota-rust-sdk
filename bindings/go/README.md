# IOTA SDK - Go Bindings

First install [uniffi-bindgen-go](https://github.com/NordSecurity/uniffi-bindgen-go)

Then compile the FFI crate to a dynamic library

```sh
cargo build --all-features -p iota-sdk-ffi --lib --release
```

And finally, generate the Go bindings

```sh
uniffi-bindgen-go --library target/release/libiota_sdk_ffi.dylib --out-dir ./bindings/go --no-format
```

To test it

```sh
BINARIES_DIR="../../target/release" \
LD_LIBRARY_PATH="$BINARIES_DIR" \
CGO_LDFLAGS="-liota_sdk_ffi -L$BINARIES_DIR" \
CGO_ENABLED=1 \
go run test.go
```
