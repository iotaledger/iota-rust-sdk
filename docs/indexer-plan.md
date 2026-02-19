# IOTA Indexer Plan ([Bounty] Create indexer using SDK #511)

## Standard SDK Pattern
This implementation follows the official IOTA custom indexer pattern using:
- `iota-data-ingestion-core`
- `Worker` + `WorkerPool` + `IndexerExecutor`
- `FileProgressStore` for resumable checkpoint ingestion

## Acceptance Criteria Mapping
- Process network checkpoints: done via `CheckpointReaderConfig` remote URLs.
- Process transactions and events: done in `DbWorker::process_checkpoint`.
- Filter data: sender/event filters are applied before inserts.
- Store in database: PostgreSQL tables for checkpoints, transactions, and events.

## Storage Model
- `checkpoints(sequence_number, timestamp_ms, digest, raw_data)`
- `transactions(checkpoint_seq, transaction_digest, sender, kind, success, timestamp_ms, raw_transaction)`
- `events(checkpoint_seq, transaction_digest, package_id, module, event_name, sender, raw_event)`

## Operational Notes
- Progress persistence is in `.iota_indexer_progress.json` by default.
- `--start-checkpoint` updates watermark forward only.
- `--end-checkpoint` uses `IngestionLimit::MaxCheckpoint` for bounded runs.
