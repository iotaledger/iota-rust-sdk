# iota-indexer

A Postgres-backed custom indexer built in the standard IOTA way using:
- `iota-data-ingestion-core`
- `iota-types`

## What it does
- Ingests network checkpoints.
- Extracts transactions and events from each checkpoint.
- Applies filters.
- Stores filtered data in PostgreSQL.
- Persists progress with `FileProgressStore` so it can resume.

## PostgreSQL Setup

```bash
docker run --name iota-indexer-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_DB=iota_indexer \
  -p 5432:5432 \
  -d postgres:16
```

## Run

```bash
cargo run -p iota-indexer -- \
  --network testnet \
  --db-url postgres://postgres:postgres@localhost:5432/iota_indexer \
  --progress-file .iota_indexer_progress.json \
  --start-checkpoint 0 \
  --end-checkpoint 20
```

Continuous mode:

```bash
cargo run -p iota-indexer -- \
  --network testnet \
  --db-url postgres://postgres:postgres@localhost:5432/iota_indexer
```

## Verify

```bash
psql postgres://postgres:postgres@localhost:5432/iota_indexer -c "SELECT COUNT(*) FROM checkpoints;"
psql postgres://postgres:postgres@localhost:5432/iota_indexer -c "SELECT COUNT(*) FROM transactions;"
psql postgres://postgres:postgres@localhost:5432/iota_indexer -c "SELECT COUNT(*) FROM events;"
```
