# iota-dca Milestone 1 (Issue #808)

This document proposes and delivers a minimal, review-friendly first milestone for `iota-dca` in the Rust SDK ecosystem.

## Scope (Delivered)

- A **typed architecture scaffold** for treasury automation in:
  - `crates/iota-sdk/examples/dca_treasury_scaffold.rs`
- The scaffold covers:
  - deterministic multi-account allocation planning (basis points)
  - typed transaction-intent modeling for treasury flows
  - stake + transfer intent partitioning
  - conservation-safe rounding behavior for allocations

This milestone intentionally avoids network execution and key management to keep review risk low.

## Why this milestone

Issue #808 covers a large full-stack target. This PR starts with a narrow subset that can be validated quickly and serve as a base for incremental delivery.

## How to run

```bash
cargo run -p iota-sdk --example dca_treasury_scaffold
```

## Validation

- Example compiles and runs in workspace context.
- Output shows generated intents and allocation distribution.

## Next milestones

1. **Milestone 2: Builder mapping**
   - map `TreasuryIntent` to `TransactionBuilder` operations
   - produce dry-run transaction bytes per intent

2. **Milestone 3: GraphQL read-model integration**
   - fetch balances/coins and validator metadata
   - dynamic gas/coin selection strategy

3. **Milestone 4: Scheduling & execution boundaries**
   - periodic DCA scheduling
   - idempotency keys and replay-safe execution

4. **Milestone 5: API/CLI surface**
   - expose planner and executor behind stable crate interfaces
   - add integration tests and docs for end-to-end flows
