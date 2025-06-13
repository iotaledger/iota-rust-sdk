# IOTA Sdk

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

In an effort to be modular, functionality is split between a number of crates.

- [`iota-sdk-types`](crates/iota-sdk-types)
  [![iota-sdk-types on crates.io](https://img.shields.io/crates/v/iota-sdk-types)](https://crates.io/crates/iota-sdk-types)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-types)
  [![Documentation (develop)](https://img.shields.io/badge/docs-develop-59f)](https://github.com/iotaledger/iota-rust-sdk/iota_sdk_types/)
- [`iota-crypto`](crates/iota-crypto)
  [![iota-crypto on crates.io](https://img.shields.io/crates/v/iota-crypto)](https://crates.io/crates/iota-crypto)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-crypto)
  [![Documentation (develop)](https://img.shields.io/badge/docs-develop-59f)](https://github.com/iotaledger/iota-rust-sdk/iota_crypto/)
- [`iota-graphql-client`](crates/iota-crypto)
  [![iota-graphql-client on crates.io](https://img.shields.io/crates/v/iota-graphql-client)](https://crates.io/crates/iota-graphql-client)
  [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-graphql-client)
  [![Documentation (develop)](https://img.shields.io/badge/docs-develop-59f)](https://github.com/iotaledger/iota-rust-sdk/iota-graphql-client/)
