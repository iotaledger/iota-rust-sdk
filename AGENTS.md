# AGENTS.md

This file provides context for AI agents working with the IOTA Rust SDK repository.

## Project Overview

The **IOTA Rust SDK** is a modular software development kit for integrating with the IOTA blockchain. IOTA is a next-generation smart contract platform powered by Move.

**Key Design Goals:**

- Modularity: Users only pay for features they use
- Lightweight: Minimal dependency footprint
- WASM Support: Libraries usable in browser environments
- Multi-language: FFI bindings for Go, Kotlin, Python

## Repository Structure

```
crates/
├── iota-sdk/                      # Main umbrella SDK (re-exports everything)
├── iota-sdk-types/                # Core blockchain types (Address, Object, Transaction, etc.)
├── iota-sdk-crypto/               # Cryptographic signing (ed25519, secp256r1, secp256k1, etc.)
├── iota-sdk-graphql-client/       # GraphQL RPC client for blockchain interaction
├── iota-sdk-graphql-client-build/ # Build-time GraphQL schema registration
├── iota-sdk-transaction-builder/  # Type-safe transaction construction
└── iota-sdk-ffi/                  # FFI for language bindings (not published)

bindings/
├── go/                            # Go bindings with examples
├── kotlin/                        # Kotlin bindings with Gradle
└── python/                        # Python bindings
```

## Crate Responsibilities

| Crate                          | Purpose                                                                     |
| ------------------------------ | --------------------------------------------------------------------------- |
| `iota-sdk`                     | Umbrella crate that re-exports all functionality via feature flags          |
| `iota-sdk-types`               | Core types: Address, ObjectId, Transaction, Checkpoint, etc. BCS-compatible |
| `iota-sdk-crypto`              | Signing traits (`IotaSigner`, `IotaVerifier`) and implementations           |
| `iota-sdk-graphql-client`      | Type-safe GraphQL client using `cynic` for schema-derived types             |
| `iota-sdk-transaction-builder` | Fluent API for building transactions (online/offline modes)                 |

## Build & Test Commands

```bash
# Run all tests
make test

# Run clippy lints
make clippy

# Format code (requires nightly)
make fmt

# Check formatting
make check-fmt

# Build WASM modules
make wasm

# Build FFI bindings
make bindings        # All bindings
make go              # Go only
make kotlin          # Kotlin only
make python          # Python only

# Run examples
make examples

# Full CI check
make ci
```

## Code Conventions

### Rust Edition & Style

- **Edition**: 2024 (latest)
- **Formatting**: Nightly rustfmt with `rustfmt.toml` config
- **Linting**: Clippy with warnings as errors (`-Dwarnings`)

### Naming

- Crates: `iota-sdk-*` prefix
- Modules: `snake_case`
- Types: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`

### Error Handling

Use `thiserror` for error types:

```rust
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum MyError {
    #[error("description: {0}")]
    VariantName(String),
}
```

### Feature Flags

Features are used extensively. Common patterns:

```rust
#[cfg(feature = "serde")]
impl Serialize for MyType { ... }

#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub fn my_function() { ... }
```

### License Headers

All source files must have:

```rust
// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
```

## Key Patterns

### GraphQL Client Usage

```rust
use iota_sdk::graphql_client::Client;

let client = Client::devnet();
let chain_id = client.chain_id().await?;
```

### Transaction Building

```rust
use iota_sdk::transaction_builder::TransactionBuilder;

let mut builder = TransactionBuilder::new(sender).with_client(&client);
builder.send_iota(recipient, amount);
let tx = builder.finish().await?;
```

### Signing

```rust
use iota_sdk::crypto::{IotaSigner, Ed25519PrivateKey};

let key = Ed25519PrivateKey::generate(&mut rng);
let signature = key.sign_transaction(&tx)?;
```

## Important Files

| File                 | Purpose                                     |
| -------------------- | ------------------------------------------- |
| `Cargo.toml` (root)  | Workspace manifest with shared dependencies |
| `Makefile`           | Build orchestration (62 targets)            |
| `rustfmt.toml`       | Formatting rules                            |
| `deny.toml`          | Security/license policy                     |
| `.github/workflows/` | 19 CI workflows                             |

## Testing

- **Unit tests**: Inline with `#[cfg(test)]`
- **Doc tests**: Examples in documentation
- **Property tests**: Using `proptest` for type variants
- **Integration tests**: Transaction builder has test Move packages
- **WASM tests**: `wasm-pack test` for browser compatibility

Run specific test categories:

```bash
cargo nextest run                    # Unit tests
cargo test --doc                     # Doc tests
make test-with-localnet              # Tests requiring local network
```

## Git Workflow

- **Main branch**: `develop` (not `main`)
- **CI**: All tests must pass, no clippy warnings, proper formatting
- Draft PRs can force CI with `[run-ci]` in PR body

## Common Tasks

### Adding a New Type to `iota-sdk-types`

1. Add type definition with `#[derive(Debug, Clone, PartialEq, Eq)]`
2. Add `#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]` if needed
3. Add `#[cfg_attr(feature = "schemars", derive(JsonSchema))]` if needed
4. Export from appropriate module

### Adding a New GraphQL Query

1. Add `.graphql` file in `crates/iota-sdk-graphql-client/queries/`
2. Define corresponding types in `query_types/`
3. Add convenience method in `api/` module

### Adding a New Signature Scheme

1. Create module in `crates/iota-sdk-crypto/src/`
2. Implement `IotaSigner` and/or `IotaVerifier` traits
3. Add feature flag in `Cargo.toml`
4. Re-export from `iota-sdk` with feature gate

## Dependencies

Key dependencies:

- **Serialization**: `serde`, `bcs` (IOTA's binary format)
- **Crypto**: `ed25519-dalek`, `p256`, `k256`, `blst`
- **Async**: `tokio`, `futures`
- **GraphQL**: `cynic` (type-safe client)
- **HTTP**: `reqwest` with `rustls-tls`

## WASM Considerations

All crates support WASM. When adding dependencies:

- Ensure they support `wasm32-unknown-unknown` target
- Use `getrandom` with `js` feature for randomness
- Avoid OS-specific functionality

## CI Workflows

| Workflow             | Trigger | Purpose                      |
| -------------------- | ------- | ---------------------------- |
| `tests.yml`          | Push/PR | Unit and integration tests   |
| `lints.yml`          | Push/PR | Clippy, rustfmt, cargo-deny  |
| `wasm.yml`           | Push/PR | WASM compilation             |
| `check_features.yml` | Daily   | Feature compatibility matrix |
| `bindings.yml`       | Push/PR | FFI binding generation       |

## Tips for Agents

1. **Read before modifying**: Always read files before suggesting changes
2. **Feature flags matter**: Check which features are enabled for the code you're modifying
3. **BCS compatibility**: Types in `iota-sdk-types` must be BCS-serialization compatible
4. **Run tests locally**: Use `make test` before committing
5. **Check formatting**: Use `make check-fmt` to verify formatting
6. **Examples are documentation**: The 40+ examples in `crates/iota-sdk/examples/` show idiomatic usage
7. **Prefer checking than compiling**: Use `cargo check` instead of `cargo build`
