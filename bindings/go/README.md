# IOTA SDK - Go Bindings

First install [uniffi-bindgen-go](https://github.com/NordSecurity/uniffi-bindgen-go)

Then compile the FFI crate to a dynamic library:

```sh
cargo build --all-features -p iota-sdk-ffi --lib --release
```

And finally, generate the Go bindings

```sh
uniffi-bindgen-go --library target/release/libiota_sdk_ffi.dylib --out-dir ./bindings/go --no-format
```
