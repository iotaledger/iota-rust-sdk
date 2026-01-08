# IOTA SDK

A Rust SDK for integrating with the [IOTA blockchain](https://docs.iota.org/).

> [!NOTE]
> This is project is under development and many features may still be under
> development or missing.

## Overview

This repository contains a collection of libraries for integrating with the IOTA blockchain.

A few of the project's high-level goals are as follows:

- **Be modular** - user's should only need to pay the cost (in terms of dependencies/compilation time) for the features that they use.
- **Be light** - strive to have a minimal dependency footprint.
- **Support developers** - provide all needed types, abstractions and APIs to enable developers to build robust applications on IOTA.
- **Support wasm** - where possible, libraries should be usable in wasm environments.

## Crates

In an effort to be modular, functionality is split between a number of crates. The main crate, `iota-sdk`, contains the others.

- [`iota-sdk`](crates/iota-sdk)
  [![iota-sdk on crates.io](https://img.shields.io/crates/v/iota-sdk)](https://crates.io/crates/iota-sdk)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk)
- [`iota-sdk-crypto`](crates/iota-sdk-crypto)
  [![iota-sdk-crypto on crates.io](https://img.shields.io/crates/v/iota-sdk-crypto)](https://crates.io/crates/iota-sdk-crypto)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-crypto)
- [`iota-sdk-graphql-client`](crates/iota-sdk-graphql-client)
  [![iota-sdk-graphql-client on crates.io](https://img.shields.io/crates/v/iota-sdk-graphql-client)](https://crates.io/crates/iota-sdk-graphql-client)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-graphql-client)
- [`iota-sdk-transaction-builder`](crates/iota-sdk-transaction-builder)
  [![iota-sdk-transaction-builder on crates.io](https://img.shields.io/crates/v/iota-sdk-transaction-builder)](https://crates.io/crates/iota-sdk-transaction-builder)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-transaction-builder)
- [`iota-sdk-types`](crates/iota-sdk-types)
  [![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

## License

This project is available under the terms of the [Apache 2.0 license](LICENSE).
