# IOTA Indexer Plan ([Bounty] Create indexer using SDK #511)

## Required SDK Pattern
This implementation now follows the issue's required approach using:
- `iota_sdk::graphql_client::Client`
- polling-based checkpoint ingestion
- checkpoint-range transaction queries via `TransactionsFilter::after_checkpoint` / `before_checkpoint`
- event queries via `EventFilter` and cursor pagination
- file-based progress watermark for resumability

## Acceptance Criteria Mapping
- Process network checkpoints:
  - loop polls `latest_checkpoint_sequence_number` and processes sequential checkpoints.
- Process transactions and events:
  - transactions fetched with `transactions_data_effects`.
  - events fetched per transaction digest via `events`.
- Filter data:
  - transaction filters: function, signer, include/exclude failed.
  - event filters: event type, module, package.
- Store in database:
  - PostgreSQL tables for checkpoints, transactions, and events.
- Progress tracking:
  - progress file stores `next_checkpoint` watermark and resumes safely.

## Storage Model
- `checkpoints(sequence_number, timestamp_ms, digest, raw_json)`
- `transactions(checkpoint_seq, transaction_digest, sender, kind, success, timestamp_ms, raw_json)`
- `events(checkpoint_seq, transaction_digest, package_id, module, event_name, sender, raw_json)`

## Runtime Behavior
- bounded sync: `--start-checkpoint` + `--end-checkpoint`
- continuous mode: omit `--end-checkpoint`
- poll interval is configurable with `--poll-interval-ms`
