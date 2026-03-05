# iota-sdk-types

[![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

The `iota-sdk-types` crate provides the definitions of the core types that are
part of the public API of the IOTA blockchain.

## Display Support

All public types implement `std::fmt::Display` for readable console output. Multi-field structs render as tree structures using box-drawing characters.

### Example

```rust
use iota_sdk_types::GasCostSummary;

let gas = GasCostSummary::new(1000, 500, 200, 50, 10);
println!("{gas}");
```

```
Gas Cost Summary
├── Computation Cost: 1000
├── Computation Cost Burned: 500
├── Storage Cost: 200
├── Storage Rebate: 50
└── Non-Refundable Storage Fee: 10
```
