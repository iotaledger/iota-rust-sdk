# IOTA SDK - Go Bindings

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Go
- uniffi-bindgen-go

Until https://github.com/NordSecurity/uniffi-bindgen-go/pull/77 is merged, it is recommended to install `uniffi-bindgen-go` via:

```bash
cargo install uniffi-bindgen-go --git https://github.com/filament-dm/uniffi-bindgen-go --rev ab7315502bd6b979207fdae854e87d531ee8764d
```

Verify by running `make --version`, `go version`, and `uniffi-bindgen-go --version`.

## Generate the Kotlin bindings

```bash
make go
```

## Run an example

```sh
make go-example chain_id
```
