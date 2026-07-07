# AGENTS.md

This file provides context for AI agents working with the IOTA Rust SDK repository.

## Project Overview

The **IOTA Rust SDK** is a modular software development kit for integrating with the IOTA blockchain. IOTA is a next-generation smart contract platform powered by Move.

**Key Design Goals:**

- Modularity: Users only pay for features they use
- Lightweight: Minimal dependency footprint
- WASM Support: Libraries usable in browser environments
- Multi-language: FFI bindings for Go, Kotlin, Python, C#, Swift (via `uniffi`)

## Critical development notes

1. **NEVER make breaking changes** — this SDK is consumed externally. New fields must be optional, removals require a deprecation step first.
2. **NEVER disable or skip tests** — all tests must pass and stay enabled.
3. **NEVER use `#[allow(dead_code)]`, `#[allow(unused)]`, or other lint suppressions** to silence warnings — fix the underlying issue.
4. **Types in `iota-sdk-types` must stay BCS-compatible** — verify BCS and JSON round-trips when adding or changing a type. `u64` is serialized as a string in JSON for JS safety.
5. **Format and lint after every change** — `cargo +nightly fmt`, `dprint fmt`, and `make bindings-examples-format-check` for binding examples.
6. **Keep pull requests small** — prefer small, focused PRs over large ones. A small diff is easier to review, easier to revert, and less likely to introduce regressions.
7. **Split work into multiple PRs when possible** — if a change spans multiple concerns (e.g. a refactor plus a new feature, or changes across unrelated crates), split it into separate PRs. Land independent pieces incrementally rather than bundling them together. **Critically: when given multiple GitHub issues, ALWAYS create one PR per issue** — never bundle multiple issues into a single PR unless explicitly instructed or the issues are genuinely interdependent.
8. **Keep PR descriptions short and skimmable** — write for a human reviewer who has 30 seconds. Cover the _why_ and the high-level _what_, and stop. Don't enumerate every line of the diff; reviewers can read the code. Avoid long wall-of-text summaries, exhaustive bullet lists of every renamed symbol, or restating what the diff obviously shows. A few crisp sentences (plus a test plan if relevant) is the goal.
9. **Feature flags matter** — the umbrella `iota-sdk` gates everything behind features. Check what's enabled for the code you're modifying before assuming an item exists.
10. **NEVER hand-edit generated gRPC types** under `crates/iota-sdk-grpc-types/src/proto/` — they are build output. Changes go into the proto sources / `update_grpc_types.sh`.

## Repository Structure

```
crates/
├── iota-sdk/                       # Umbrella SDK that re-exports the other crates behind feature flags
├── iota-sdk-bcs-schema/            # Proc macro that generates BCS schema definitions (ABNF) from Rust types
├── iota-sdk-crypto/                # Signing traits (`IotaSigner`, `IotaVerifier`) and implementations (ed25519, secp256r1, secp256k1, bls12381, passkey)
├── iota-sdk-ffi/                   # FFI layer powering language bindings via `uniffi` (not published)
├── iota-sdk-graphql-client/        # Type-safe GraphQL RPC client using `cynic`
├── iota-sdk-graphql-client-build/  # Build-time GraphQL schema registration for `cynic` codegen
├── iota-sdk-grpc-client/           # gRPC client built on `tonic` (ledger, execution, state, move package services)
├── iota-sdk-grpc-proto-build/      # Build-time codegen for gRPC/protobuf types (`update_grpc_types.sh` regenerates from upstream protos)
├── iota-sdk-grpc-types/            # Generated gRPC/protobuf types
├── iota-sdk-transaction-builder/   # Fluent API for building transactions (online/offline modes)
└── iota-sdk-types/                 # Core blockchain types (Address, ObjectId, Transaction, Checkpoint, ...) — BCS-compatible

bindings/
├── csharp/                         # C# bindings
├── go/                             # Go bindings
├── kotlin/                         # Kotlin bindings
├── python/                         # Python bindings
├── swift/                          # Swift bindings
└── wasm/                           # WASM/TypeScript bindings (browser + Node)
```

The `iota-sdk` umbrella crate exposes the other crates via modules gated by feature flags: `crypto`, `graphql` (→ `graphql_client`), `grpc` (→ `grpc_client` + `grpc_types`), `move-types` (→ `move_types`), `txn-builder` (→ `transaction_builder`), and `types`. `grpc` and `move-types` are opt-in (not in `default`); `graphql`, `crypto`, `types`, `txn-builder` are on by default.

## Build & Test Commands

```bash
# Lint, format, tests
make test                        # Unit tests (nextest)
make test-docs                   # Doc tests
make test-with-localnet          # Tests requiring a running localnet
make clippy                      # Clippy
make fmt                         # Format Rust code (requires nightly)
make check-fmt                   # Verify Rust formatting
make bindings-examples-format        # Format the examples shipped with each binding
make bindings-examples-format-check  # Verify formatting of binding examples

# WASM
make wasm32          # Check that SDK crates compile to wasm32-unknown-unknown
make wasm            # Build the WASM/TypeScript bindings package

# FFI bindings
make bindings        # Build all bindings
make go              # Go only
make kotlin          # Kotlin only
make python          # Python only
make csharp          # C# only
make swift           # Swift only

# gRPC proto regeneration
make grpc   # Pull/refresh protos and regenerate types

# BCS schema
make bcs-schema      # Regenerate bcs-schema.abnf

# Examples
make examples                    # Run all Rust examples
make bindings-examples           # Run all binding examples
make <lang>-example NAME         # Run a single example (lang ∈ {go, kotlin, python, csharp, swift})

# Full CI check
make ci              # check-features + check-fmt + check-sort-derives + test + wasm32

# Localnet (IOTA node + faucet + indexer + GraphQL + gas station)
./run_localnet.sh start [iota-localnet-binary]   # Start localnet + gas station (Postgres, Redis)
./run_localnet.sh stop                           # Tear it all down
# Defaults to `iota-localnet` on PATH; pass explicit path as second arg to override

# Direct cargo invocations
cargo nextest run                # Direct nextest invocation
cargo test --doc                 # Direct doc test invocation
```

## Code Conventions

- **Edition**: 2024
- **Formatting**: Nightly rustfmt (config in `rustfmt.toml`)
- **Linting**: Clippy with warnings as errors (`-Dwarnings`)
- **Naming**: crates `iota-sdk-*`, modules `snake_case`, types `PascalCase`, constants `UPPER_SNAKE_CASE`
- **Errors**: `thiserror` enums, `#[non_exhaustive]` at the type level
- **Feature gating**: optional functionality lives behind features; APIs use `#[cfg(feature = "…")]` and `#[cfg_attr(doc_cfg, doc(cfg(feature = "…")))]` for docs.rs visibility
- **Comments**: Write comments for a future reader of the code — document what the code does and the invariants it relies on. Do not narrate the change being made, nor explain why a problem was fixed when that problem was only introduced within the same change. Keep comments concise and durable, not a changelog of in-session edits.

## Important Files

| File                                      | Purpose                                                |
| ----------------------------------------- | ------------------------------------------------------ |
| `Cargo.toml` (root)                       | Workspace manifest with shared dependencies            |
| `Makefile`                                | Build orchestration                                    |
| `deny.toml`                               | Security/license policy                                |
| `.github/workflows/`                      | CI workflows                                           |
| `crates/iota-sdk-grpc-proto-build/`       | Proto sources and codegen entry point for gRPC types   |
| `crates/iota-sdk-graphql-client/queries/` | `.graphql` query files consumed by the `cynic` codegen |

## Git Workflow

- **Main branch**: `develop` (not `main`)
- **CI**: All tests must pass, no clippy warnings, proper formatting
- Draft PRs can force CI with `[run-ci]` in the PR body
- **PR title format**: Titles are validated in CI (`.github/workflows/pr_title.yml`) and must follow the [Conventional Commits](https://www.conventionalcommits.org/) style. Allowed types are `feat`, `fix`, `refactor`, `chore`, `upstream`, and `release` (e.g. `feat: add new gRPC method`, `chore: update docs`). No other prefixes (such as `docs:` or `test:`) are accepted — use `chore:` for those.

## WASM Considerations

The `make wasm32` target checks that the following crates compile to `wasm32-unknown-unknown`: `iota-sdk`, `iota-sdk-crypto`, `iota-sdk-graphql-client`, `iota-sdk-transaction-builder`, and `iota-sdk-types`. The full WASM/TypeScript bindings package (which also builds `iota-sdk-ffi` for wasm32) is built with `make wasm`. The gRPC client/types are not built for WASM. When adding dependencies to any of the WASM-built crates:

- Ensure they support `wasm32-unknown-unknown`
- Use `getrandom` with the `js` / `wasm_js` feature for randomness
- Avoid OS-specific functionality
- Run `make wasm32` after changes to verify the SDK crates still build for `wasm32-unknown-unknown`
