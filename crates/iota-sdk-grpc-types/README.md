# iota-sdk-grpc-types

[![iota-sdk-grpc-types on crates.io](https://img.shields.io/crates/v/iota-sdk-grpc-types)](https://crates.io/crates/iota-sdk-grpc-types)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-grpc-types)

Protobuf/gRPC types for the IOTA blockchain, consumed by
[`iota-sdk-grpc-client`](https://crates.io/crates/iota-sdk-grpc-client). It contains:

- the generated protobuf message and service types (under `proto`), with conversions to and from
  the core [`iota-sdk-types`](https://crates.io/crates/iota-sdk-types) types,
- typed field-mask constants and the `field_mask!` / `field_masks_merge!` macros for building
  read masks, and
- gRPC header constants.

## Generated code

The types under `src/proto/` are build output — do not edit them by hand. They are regenerated
from the upstream proto definitions with `make grpc` at the repository root (see
`crates/iota-sdk-grpc-proto-build/`).
