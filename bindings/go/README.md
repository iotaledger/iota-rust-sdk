# IOTA SDK - Go Bindings

# Install `uniffi-bindgen-go`

https://github.com/NordSecurity/uniffi-bindgen-go

`cargo install uniffi-bindgen-go --git https://github.com/filament-dm/uniffi-bindgen-go --rev ab7315502bd6b979207fdae854e87d531ee8764d` until https://github.com/NordSecurity/uniffi-bindgen-go/pull/77 is merged

# Compile the FFI crate to a dynamic library

```sh
cargo build --all-features -p iota-sdk-ffi --lib --release
```

# Generate the Go bindings

## MacOS

```sh
uniffi-bindgen-go --library target/release/libiota_sdk_ffi.dylib --out-dir ./bindings/go --no-format
```

## Linux

```sh
uniffi-bindgen-go --library target/release/libiota_sdk_ffi.so --out-dir ./bindings/go --no-format
```

## Windows

```sh
uniffi-bindgen-go --library target/release/libiota_sdk_ffi.dll --out-dir ./bindings/go --no-format
```

# Test it

```sh
LD_LIBRARY_PATH="../../target/release" CGO_LDFLAGS="-liota_sdk_ffi -L../../target/release" go run test.go
```
