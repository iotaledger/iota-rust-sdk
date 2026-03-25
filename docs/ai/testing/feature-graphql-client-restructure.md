---
phase: testing
title: "Testing Strategy: GraphQL Client Restructure"
description: "Verification approach for the refactoring — entirely regression-based"
---

# Testing Strategy

## Test Coverage Goals

This is a pure refactor with no new logic. Verification is entirely regression-based:
all existing tests must continue to pass unchanged.

One pre-existing test fragility was identified and fixed during this refactor:
`test_transaction_data_effects` and `test_transactions_data_effects` hard-coded a
specific devnet digest that went stale. Both tests now derive digests dynamically.

## Existing Tests

### API-layer integration tests (require network)

All tests live in `#[cfg(test)] mod tests` blocks within their respective `src/api/*.rs` files.
Run with:
```bash
NETWORK=testnet cargo test --all-features -p iota-sdk-graphql-client
```

| Test | File | Status |
|------|------|--------|
| `test_balance_query` | `api/balance.rs` | ✅ pass |
| `test_checkpoint_query` | `api/checkpoints.rs` | ✅ pass |
| `test_checkpoints_query` | `api/checkpoints.rs` | ✅ pass |
| `test_latest_checkpoint_sequence_number_query` | `api/checkpoints.rs` | ✅ pass |
| `test_total_transaction_blocks` | `api/checkpoints.rs` | ✅ pass |
| `test_coins_query` | `api/coins.rs` | ✅ pass |
| `test_coins_stream` | `api/coins.rs` | ✅ pass |
| `test_coin_metadata_query` | `api/coins.rs` | ✅ pass |
| `test_total_supply` | `api/coins.rs` | ✅ pass |
| `test_dry_run` | `api/dry_run.rs` | ✅ pass |
| `test_dynamic_field_query` | `api/dynamic_fields.rs` | ✅ pass |
| `test_dynamic_fields_query` | `api/dynamic_fields.rs` | ✅ pass |
| `test_epoch_query` | `api/epochs.rs` | ✅ pass |
| `test_epoch_summary_query` | `api/epochs.rs` | ✅ pass |
| `test_epoch_total_checkpoints_query` | `api/epochs.rs` | ✅ pass |
| `test_epoch_total_transaction_blocks_query` | `api/epochs.rs` | ✅ pass |
| `test_events_query` | `api/events.rs` | ✅ pass |
| `test_chain_id` | `api/network.rs` | ✅ pass |
| `test_reference_gas_price_query` | `api/network.rs` | ✅ pass |
| `test_protocol_config_query` | `api/network.rs` | ✅ pass |
| `test_active_validators` | `api/network.rs` | ✅ pass |
| `test_object_query` | `api/objects.rs` | ✅ pass |
| `test_object_bcs_query` | `api/objects.rs` | ✅ pass |
| `test_objects_query` | `api/objects.rs` | ✅ pass |
| `test_package` | `api/package.rs` | ✅ pass |
| `test_latest_package_query` | `api/package.rs` | ✅ pass |
| `test_packages_query` | `api/package.rs` | ✅ pass |
| `test_transaction_effects_query` | `api/transactions.rs` | ✅ pass |
| `test_transactions_effects_query` | `api/transactions.rs` | ✅ pass |
| `test_transactions_query` | `api/transactions.rs` | ✅ pass |
| `test_transaction_data_effects` | `api/transactions.rs` | ✅ pass (fixed) |
| `test_transactions_data_effects` | `api/transactions.rs` | ✅ pass (fixed) |
| `test_rpc_server` | `client.rs` | ✅ pass |
| `test_service_config_query` | `client.rs` | ✅ pass |
| `test_move_view_call` | `api/move_view_call.rs` | ⚠️ known fail (see below) |
| `test_move_view_call_json` | `api/move_view_call.rs` | ⚠️ known fail (see below) |

### Known failing tests (pre-existing network limitations)

- **`test_move_view_call`** and **`test_move_view_call_json`**: These tests call the
  `viewCall` GraphQL mutation which is not yet supported on testnet (`"Unsupported feature:
  View calls are not yet supported on testnet"`). These are tracked network-infrastructure
  limitations, not code defects. They will pass once view call support is rolled out.

### Doc Tests
```bash
cargo test --all-features --doc -p iota-sdk-graphql-client
```
No doc tests currently exist in this crate.

### Clippy
```bash
cargo clippy --all-features --all-targets -p iota-sdk-graphql-client
```

## Fixed Tests (this refactor)

### `test_transaction_data_effects` and `test_transactions_data_effects`

**Problem**: Both tests hard-coded a devnet digest (`Agug2GETToZj4Ncw3RJn2KgDUEpVQKG1WaTZVcLcqYnf`)
and used `Client::new_devnet()` directly, bypassing the `$NETWORK` environment variable. The digest
went stale and the tests began panicking with `Option::unwrap()` on `None`.

**Fix** (`api/transactions.rs`):
- Switched to `test_client()` to respect `$NETWORK`
- Fetch a live digest from `transactions(None, ...)` before calling the method under test
- Added explicit error messages on failures instead of bare `.unwrap()`
- Added meaningful assertions on the returned data

## Verification Steps

1. After Phase 1 (common.rs): `cargo check -p iota-sdk-graphql-client`
2. After Phase 2 (naming): `cargo check -p iota-sdk-graphql-client`
3. Full verification (run with `NETWORK=testnet` or `NETWORK=devnet`):
   ```bash
   cargo clippy --all-features --all-targets -p iota-sdk-graphql-client
   NETWORK=testnet cargo test --all-features -p iota-sdk-graphql-client
   cargo test --all-features --doc -p iota-sdk-graphql-client
   ```

## Follow-up Work

- [ ] `test_move_view_call` — enable once testnet adds view call support
- [ ] Consider adding `#[ignore = "requires view call support on network"]` attribute
      to the move_view_call tests so they don't pollute CI failure output

