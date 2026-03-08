# iota-sdk-types

[![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

The `iota-sdk-types` crate provides the definitions of the core types that are
part of the public API of the IOTA blockchain.

## Display Support

All public types implement `std::fmt::Display` for readable console output. Multi-field structs render as tree structures using box-drawing characters.

### Example

Multi-field structs render as tree structures with box-drawing characters, including nested sub-trees:

```
Gas Payment
├── Objects
│   └── 0
│       ├── Object ID: 0x19ea...
│       ├── Version: 1438
│       └── Digest: 79jAf...
├── Owner: 0xfc4c...
├── Price: 1000
└── Budget: 4264800
```
