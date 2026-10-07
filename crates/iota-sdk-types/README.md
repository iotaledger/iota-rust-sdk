# iota-sdk-types

[![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

Core type definitions for the IOTA blockchain.

[IOTA] is a next-generation smart contract platform with high throughput,
low latency, and an asset-oriented programming model powered by the Move
programming language. This crate provides type definitions for working with
the data that makes up the IOTA blockchain.

[IOTA]: https://iota.org

## Feature flags

This library uses a set of [feature flags] to reduce the number of
dependencies and amount of compiled code. By default, no features are
enabled which allows one to enable a subset specifically for their use case.
Below is a list of the available feature flags.

- `serde`: Enables support for serializing and deserializing types to/from
  BCS utilizing [serde] library. Note: JSON serialization is NOT guaranteed
  to match the IOTA monorepo's JSON-RPC format.
- `rand`: Enables support for generating random instances of a number of
  types via the [rand] library.
- `hash`: Enables support for hashing, which is required for deriving
  addresses and calculating digests for various types.
- `proptest`: Enables support for the [proptest] library by providing
  implementations of [proptest::arbitrary::Arbitrary] for many types.

[feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
[serde]: https://docs.rs/serde
[rand]: https://docs.rs/rand
[proptest]: https://docs.rs/proptest
[proptest::arbitrary::Arbitrary]: https://docs.rs/proptest/latest/proptest/arbitrary/trait.Arbitrary.html

## BCS

[BCS] is the serialization format used to represent the state of the
blockchain and is used extensively throughout the IOTA ecosystem. In
particular the BCS format is leveraged because it _"guarantees canonical
serialization, meaning that for any given data type, there is a one-to-one
correspondence between in-memory values and valid byte representations."_
One benefit of this property of having a canonical serialized representation
is to allow different entities in the ecosystem to all agree on how a
particular type should be interpreted and more importantly define a
deterministic representation for hashing and signing.

This library strives to guarantee that the types defined are fully
BCS-compatible with the data that the network produces. The one caveat to
this would be that as the IOTA protocol evolves, new type variants are added
and older versions of this library may not support those newly
added variants. The expectation is that the most recent release of this
library will support new variants and types as they are released to IOTA's
`testnet` network.

The BCS serialized form of every type in this crate is specified in ABNF
notation, as described by [RFC-5234], in [`bcs-schema.abnf`]. In addition to
the format itself, some types have an extra layer of verification and may
impose additional restrictions on valid byte representations above and
beyond those already provided by BCS. In these instances the documentation
for those types will clearly specify these additional restrictions.

[BCS]: https://docs.rs/bcs
[RFC-5234]: https://datatracker.ietf.org/doc/html/rfc5234
[`bcs-schema.abnf`]: https://github.com/iotaledger/iota-rust-sdk/blob/develop/crates/iota-sdk-types/bcs-schema.abnf

## Display Support

All public types implement `std::fmt::Display` for readable console output. Multi-field structs render as tree structures using box-drawing characters, including nested sub-trees:

```text
Gas Payment
├── Objects
│   └── 0: Object Reference
│       ├── Object ID: 0x0000000000000000000000000000000000000000000000000000000000000000
│       ├── Version: 42
│       └── Digest: 11111111111111111111111111111111
├── Owner: 0x0000000000000000000000000000000000000000000000000000000000000000
├── Price: 1000
└── Budget: 5000000
```
