# polling-indexer

Polling-based custom indexer example built on top of `iota_sdk::graphql_client::Client`.

This example demonstrates a polling indexer flow with:

- checkpoint polling with persisted watermark progress,
- transaction ingestion using `TransactionsFilter::after_checkpoint` / `before_checkpoint`,
- event ingestion + filtering,
- storage into PostgreSQL.

## What It Indexes

- `checkpoints` table: checkpoint summary metadata + raw JSON
- `transactions` table: tx digest, sender, kind, status + raw JSON
- `events` table: package/module/type data + raw JSON

## Read Indexed Data (Examples)

```bash
psql "postgres://postgres:postgres@localhost:5432/polling_indexer"
```

Latest checkpoints:

```sql
SELECT sequence_number, timestamp_ms, digest
FROM checkpoints
ORDER BY sequence_number DESC
LIMIT 10;
```

Recent transactions:

```sql
SELECT checkpoint_seq, transaction_digest, sender, success, kind
FROM transactions
ORDER BY checkpoint_seq DESC, id DESC
LIMIT 20;
```

Recent events:

```sql
SELECT checkpoint_seq, transaction_digest, package_id, module, event_name
FROM events
ORDER BY checkpoint_seq DESC, id DESC
LIMIT 20;
```

## Run PostgreSQL

```bash
docker run --name polling-indexer-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_DB=polling_indexer \
  -p 5432:5432 -d postgres:16
```

## Run the Indexer

```bash
cargo run -p polling-indexer -- \
  --network testnet \
  --db-url postgres://postgres:postgres@localhost:5432/polling_indexer \
  --progress-file .polling_indexer_progress.json \
  --start-checkpoint 0 \
  --end-checkpoint 50
```

Continuous mode (no end checkpoint):

```bash
cargo run -p polling-indexer -- \
  --network testnet \
  --db-url postgres://postgres:postgres@localhost:5432/polling_indexer
```

Custom GraphQL endpoint via network:

```bash
cargo run -p polling-indexer -- \
  --network custom:https://your.graphql.endpoint/graphql \
  --db-url postgres://postgres:postgres@localhost:5432/polling_indexer
```

If your local Postgres requires an explicit user, use:

```bash
--db-url postgres://<your_local_role>@localhost:5432/polling_indexer
```

## Filters

Transaction-level:

```bash
--tx-function 0x2::iota_system::request_add_stake
--tx-sender 0x...address
--include-failed-txs false
```

Event-level:

```bash
--event-type 0x...::module::EventName
--event-sending-module module_name
--event-package-id 0x...package
```

`--event-sending-module` matches the module where the event was emitted (`sending_module`), not necessarily the module where the event type was defined.

## Config File (JSON)

You can store settings in a JSON file and override individual values via CLI flags.
CLI flags take precedence over file values.

```json
{
  "network": "testnet",
  "db_url": "postgres://postgres:postgres@localhost:5432/polling_indexer",
  "progress_file": ".polling_indexer_progress.json",
  "start_checkpoint": 0,
  "end_checkpoint": 50,
  "page_size": 50,
  "poll_interval_ms": 2000,
  "include_failed_txs": true,
  "tx_function": "0x2::iota_system::request_add_stake",
  "event_sending_module": "iota_system"
}
```

```bash
cargo run -p polling-indexer -- --config polling-indexer.config.json
```

## Progress Tracking

A JSON progress file (default: `.polling_indexer_progress.json`) stores the `next_checkpoint` watermark.
On restart, indexing resumes from the stored value.
