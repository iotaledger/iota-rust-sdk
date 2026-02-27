# iota-sdk-types

[![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

The `iota-sdk-types` crate provides the definitions of the core types that are
part of the public API of the IOTA blockchain.

## Display Support

All public types implement `std::fmt::Display` for readable console output. Multi-field structs render as structured key-value tables using [`tabled`](https://crates.io/crates/tabled).

### Example

```rust
use iota_sdk_types::GasCostSummary;

let gas = GasCostSummary {
    computation_cost: 1000,
    computation_cost_burned: 500,
    storage_cost: 200,
    storage_rebate: 50,
    non_refundable_storage_fee: 10,
};
println!("{gas}");
```

```
+----------------------------+------+
| Computation Cost           | 1000 |
+----------------------------+------+
| Computation Cost Burned    | 500  |
+----------------------------+------+
| Storage Cost               | 200  |
+----------------------------+------+
| Storage Rebate             | 50   |
+----------------------------+------+
| Non-Refundable Storage Fee | 10   |
+----------------------------+------+
```
