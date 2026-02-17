# IOTA SDK - Swift Bindings (Milestone 1)

This folder contains the initial Swift bindings scaffold for the IOTA Rust SDK.

## Status

⚠️ Milestone 1 scaffold:

- Swift binding generation is wired via `make swift`
- Basic Swift example layout is added under `bindings/swift/examples`
- CI generation check is added in `.github/workflows/bindings.yml`

Follow-up milestones should:

- Translate and validate the full examples suite
- Add Swift formatting/lint checks
- Add Swift release automation

## Prerequisites

- GNU Make
- Rust toolchain (for `iota-sdk-ffi` + `uniffi-bindgen`)
- Swift toolchain (Xcode or Swift.org)

Verify by running:

```bash
make --version
cargo --version
swift --version
```

## Generate Swift bindings

```bash
make swift
```

Generated files are written to `bindings/swift/lib`.

## Swift example scaffold

```bash
make swift-example chain_id
```

> Note: This is a scaffold translation for milestone 1 and may require integration in an Xcode/SwiftPM project before execution.
