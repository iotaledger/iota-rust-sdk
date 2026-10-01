# IOTA SDK

[![Coverage Status](https://coveralls.io/repos/github/iotaledger/iota-rust-sdk/badge.svg?branch=develop)](https://coveralls.io/github/iotaledger/iota-rust-sdk?branch=develop)

A Rust SDK for integrating with the [IOTA blockchain](https://docs.iota.org/).

> [!NOTE]
> This project is under development and many features may still be under
> development or missing.

## Overview

This repository contains a collection of libraries for integrating with the IOTA blockchain.

A few of the project's high-level goals are as follows:

- **Be modular** - users should only need to pay the cost (in terms of dependencies/compilation time) for the features that they use.
- **Be light** - strive to have a minimal dependency footprint.
- **Support developers** - provide all needed types, abstractions and APIs to enable developers to build robust applications on IOTA.
- **Support wasm** - where possible, libraries should be usable in wasm environments.

## Crates

In an effort to be modular, functionality is split between a number of crates. The main crate, `iota-sdk`, contains the others.

- [`iota-sdk`](crates/iota-sdk)
  [![iota-sdk on crates.io](https://img.shields.io/crates/v/iota-sdk)](https://crates.io/crates/iota-sdk)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk)
- [`iota-sdk-bcs-schema`](crates/iota-sdk-bcs-schema)
  [![iota-sdk-bcs-schema on crates.io](https://img.shields.io/crates/v/iota-sdk-bcs-schema)](https://crates.io/crates/iota-sdk-bcs-schema)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-bcs-schema)
- [`iota-sdk-crypto`](crates/iota-sdk-crypto)
  [![iota-sdk-crypto on crates.io](https://img.shields.io/crates/v/iota-sdk-crypto)](https://crates.io/crates/iota-sdk-crypto)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-crypto)
- [`iota-sdk-graphql-client`](crates/iota-sdk-graphql-client)
  [![iota-sdk-graphql-client on crates.io](https://img.shields.io/crates/v/iota-sdk-graphql-client)](https://crates.io/crates/iota-sdk-graphql-client)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-graphql-client)
- [`iota-sdk-graphql-client-build`](crates/iota-sdk-graphql-client-build)
  [![iota-sdk-graphql-client-build on crates.io](https://img.shields.io/crates/v/iota-sdk-graphql-client-build)](https://crates.io/crates/iota-sdk-graphql-client-build)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-graphql-client-build)
- [`iota-sdk-grpc-client`](crates/iota-sdk-grpc-client)
  [![iota-sdk-grpc-client on crates.io](https://img.shields.io/crates/v/iota-sdk-grpc-client)](https://crates.io/crates/iota-sdk-grpc-client)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-grpc-client)
- [`iota-sdk-grpc-types`](crates/iota-sdk-grpc-types)
  [![iota-sdk-grpc-types on crates.io](https://img.shields.io/crates/v/iota-sdk-grpc-types)](https://crates.io/crates/iota-sdk-grpc-types)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-grpc-types)
- [`iota-sdk-move-types`](crates/iota-sdk-move-types)
  [![iota-sdk-move-types on crates.io](https://img.shields.io/crates/v/iota-sdk-move-types)](https://crates.io/crates/iota-sdk-move-types)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-move-types)
- [`iota-sdk-transaction-builder`](crates/iota-sdk-transaction-builder)
  [![iota-sdk-transaction-builder on crates.io](https://img.shields.io/crates/v/iota-sdk-transaction-builder)](https://crates.io/crates/iota-sdk-transaction-builder)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-transaction-builder)
- [`iota-sdk-types`](crates/iota-sdk-types)
  [![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)

## License

This project is available under the terms of the [Apache 2.0 license](LICENSE).
