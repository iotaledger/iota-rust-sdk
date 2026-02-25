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
--event-module module_name
--event-package-id 0x...package
```

## Progress Tracking

A JSON progress file stores the `next_checkpoint` watermark.
On restart, indexing resumes from the stored value.
