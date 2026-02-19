# IOTA Indexer Plan ([Bounty] Create indexer using SDK #511)

## Goal
Build an indexer with the IOTA Rust SDK that:
- Processes checkpoints.
- Processes transactions.
- Processes events.
- Applies filters.
- Stores data in a database.

## Scope
- Runtime: Rust + tokio.
- Data source: `iota-sdk` GraphQL client.
- Storage: PostgreSQL via SQLx.
- Execution modes:
  - One-shot sync for a checkpoint window.
  - Continuous polling mode to index new checkpoints.

## Data Model
- `checkpoints`: summary per sequence number.
- `transactions`: digest, sender, kind, status, and BCS payloads.
- `events`: per transaction event index, type/module/package, payload.
- `indexer_state`: watermark (`last_processed_checkpoint`) for resume safety.

## Processing Strategy
1. Read watermark from DB.
2. Determine sync range (`watermark + 1 .. latest`).
3. For each checkpoint in sequence:
   - fetch checkpoint summary;
   - fetch transactions for `at_checkpoint = seq`;
   - for each transaction, fetch events by `transaction_digest`;
   - apply filters;
   - persist rows in a single DB transaction;
   - update watermark only after successful commit.

## Filtering
- Transactions:
  - by signer (`tx_sender`),
  - by function (`tx_function`),
  - by transaction kind (`tx_kind`),
  - optional exclusion of failed txs.
- Events:
  - by sender,
  - by event type,
  - by emitting module.

## Reliability
- Idempotent writes using primary keys + unique constraints.
- Upserts for checkpoint/tx/event rows.
- Watermark update after successful checkpoint commit.
- Continuous mode polls on interval and only processes unseen checkpoints.

## Quality Bar
Before each PR push:
- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo build`
- `cargo test`
- no `.unwrap()` in production paths.

## Commit Plan
1. `feat(indexer): scaffold iota-indexer crate and config`
2. `feat(db): add postgres schema and state watermarking`
3. `feat(pipeline): process checkpoints transactions and events`
4. `feat(filters): add tx/event filter config`
5. `test(indexer): add unit tests for config parsing`
6. `docs(indexer): add architecture and validation guide`
