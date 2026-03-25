---
phase: planning
title: "Planning: GraphQL Client Restructure"
description: "Task breakdown and implementation order for the restructuring bounty"
---

# Project Planning & Task Breakdown

## Milestones

- [x] **M1**: Extract shared types into `common.rs` and clean up `mod.rs`
- [x] **M2**: Standardize QueryVariables naming across all files
- [x] **M3**: Standardize file structure (section headers + ordering)
- [x] **M4**: Rename misleading types + add deprecated aliases
- [x] **M5**: Verification (clippy, tests, doc tests)

## Task Breakdown

### Phase 1: Foundation — Extract `common.rs`
- [x] 1.1: Create `query_types/common.rs` with scalars (`Base64`, `BigInt`, `DateTime`, `MoveData`) and `impl_scalar!` calls
- [x] 1.2: Move shared fragments (`GQLAddress`, `MoveObject`, `MoveObjectContents`, `MoveValue`, `MoveType`) to `common.rs`
- [x] 1.3: Move `PageInfo` struct and `TryFrom<BigInt> for u64` impl to `common.rs`
- [x] 1.4: Update `query_types/mod.rs` to `mod common;` and `pub use common::*`
- [x] 1.5: Remove moved code from `mod.rs`, leaving only `mod` + `pub use` + `schema`
- [x] 1.6: Update imports in all query_types files that reference moved types (they already use `crate::query_types::X` which will still work via re-exports)
- [x] 1.7: Run `cargo check` to verify

### Phase 2: Naming Standardization
- [x] 2.1: Rename `BalanceArgs` → `BalanceQueryArgs` in `balance.rs` + update usages in `api/balance.rs`
- [x] 2.2: Rename `CheckpointArgs` → `CheckpointQueryArgs`, `CheckpointsArgs` → `CheckpointsQueryArgs` + update usages
- [x] 2.3: Rename `EpochArgs` → `EpochQueryArgs` + update usages
- [x] 2.4: Rename `DryRunArgs` → `DryRunQueryArgs` + update usages
- [x] 2.5: Rename `ExecuteTransactionArgs` → `ExecuteTransactionQueryArgs` + update usages
- [x] 2.6: Rename `ActiveValidatorsArgs` → `ActiveValidatorsQueryArgs` + update usages
- [x] 2.7: Rename `DynamicFieldArgs` → `DynamicFieldQueryArgs`, `DynamicFieldConnectionArgs` → `DynamicFieldsQueryArgs` + update usages
- [x] 2.8: Rename IoTA Names args types + update usages
- [x] 2.9: Rename `MoveViewCallArgs` → `MoveViewCallQueryArgs` + update usages
- [x] 2.10: Rename `ProtocolVersionArgs` → `ProtocolConfigQueryArgs` + update usages
- [x] 2.11: Rename `PackageArgs` → `PackageQueryArgs`, `PackageVersionsArgs` → `PackageVersionsQueryArgs` + update usages
- [x] 2.12: Rename `TransactionBlockArgs` → `TransactionBlockQueryArgs` + update usages
- [x] 2.13: Add deprecated type aliases in `mod.rs` for all renamed types
- [x] 2.14: Run `cargo check` to verify

### Phase 3: File Structure Uniformization
- [x] 3.1: Add/fix section headers in `balance.rs`
- [x] 3.2: Add/fix section headers in `active_validators.rs`
- [x] 3.3: Reorder Args sections in files where they're out of order (e.g., `coin.rs` has imports between sections)
- [x] 3.4: Ensure consistent section header wording across all files
- [x] 3.5: Add module-level doc comments where missing

### Phase 4: Rename Misleading Types
- [x] 4.1: Rename `MovePackageQuery` → `MovePackage` in `packages.rs`, update references
- [x] 4.2: Add deprecated alias for `MovePackageQuery`
- [x] 4.3: Rename `TransactionsFilter` → `TransactionBlockFilter` in `transaction.rs` + update usages + deprecated alias *(added from requirements Q1)*
- [x] 4.4: Merge `execute_tx.rs` into `transaction.rs` under its own section header *(added from requirements Q2)*

### Phase 5: Verification
- [x] 5.1: `cargo clippy --all-features --all-targets` — zero warnings over the entire workspace
- [x] 5.2: `cargo test --all-features` — passes for all crates
- [x] 5.3: `cargo test --all-features --doc` — doc tests pass 
- [x] 5.4: Verify public API surface hasn't changed — all renamed types have `#[deprecated]` aliases in `mod.rs`

### Phase 6: CI & Workflows (Newly Discovered Work)
- [x] 6.1: Run `make test-with-localnet` to verify e2e bindings logic (all 45 tests passed)
- [x] 6.2: Resolve deprecated type warnings (`TransactionsFilter`, `MovePackageQuery`) cascading into `iota-sdk-ffi` and examples
- [x] 6.3: Fix broken internal rustdoc link for `TransactionBlockEffects`
- [x] 6.4: Replace broken `generator.cynic-rs.dev` URLs in READMEs to satisfy `lychee` links checker workflow

## Dependencies

- Phase 2 depends on Phase 1 (renames reference the common module)
- Phase 3 is independent of Phase 2 (can be interleaved)
- Phase 4 is independent of Phase 2/3
- Phase 5 runs after all other phases

## Timeline & Estimates

| Phase | Estimated Effort |
|-------|-----------------|
| Phase 1 | ~30 min |
| Phase 2 | ~45 min |
| Phase 3 | ~20 min |
| Phase 4 | ~10 min |
| Phase 5 | ~15 min |
| **Total** | **~2 hours** |

## Risks & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Downstream breakage from renamed types | Medium | Low | Add `#[deprecated]` aliases for all renamed types |
| cynic codegen issues with moved types | Low | Medium | Verify `cargo check` after each phase |
| Missing import updates | Low | Low | Compiler will catch immediately |
