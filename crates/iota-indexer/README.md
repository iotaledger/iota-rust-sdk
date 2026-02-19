# iota-indexer

A minimal indexer built with the IOTA Rust SDK.

## Features
- Checkpoint ingestion.
- Transaction ingestion per checkpoint.
- Event ingestion per transaction.
- Filtered persistence into PostgreSQL.
- Watermark-based resume support.

## PostgreSQL Setup
Run a local Postgres container:
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
  --start-checkpoint 0
```

Continuous mode:
```bash
cargo run -p iota-indexer -- \
  --network testnet \
  --continuous
```
