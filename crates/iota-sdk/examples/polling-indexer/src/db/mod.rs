// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::Context;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

pub async fn connect(db_url: &str) -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(db_url)?;
    let connect_result = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await;

    let pool = match connect_result {
        Ok(pool) => pool,
        Err(err) => {
            let err_text = err.to_string();
            if err_text.contains("role") && err_text.contains("does not exist") {
                return Err(anyhow::anyhow!(
                    "database role from --db-url does not exist; use an existing local role (example: postgres://<your_user>@localhost:5432/polling_indexer)"
                ))
                .context(err_text);
            }
            return Err(err).context("failed to connect to PostgreSQL");
        }
    };

    Ok(pool)
}

pub async fn init(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS checkpoints (
            sequence_number BIGINT PRIMARY KEY,
            timestamp_ms BIGINT NOT NULL,
            digest TEXT NOT NULL UNIQUE,
            raw_json JSONB NOT NULL,
            indexed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS transactions (
            id BIGSERIAL PRIMARY KEY,
            checkpoint_seq BIGINT NOT NULL REFERENCES checkpoints(sequence_number),
            transaction_digest TEXT NOT NULL,
            sender TEXT,
            kind TEXT,
            success BOOLEAN NOT NULL,
            timestamp_ms BIGINT,
            raw_json JSONB NOT NULL,
            UNIQUE(checkpoint_seq, transaction_digest)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY,
            checkpoint_seq BIGINT NOT NULL REFERENCES checkpoints(sequence_number),
            transaction_digest TEXT NOT NULL,
            package_id TEXT,
            module TEXT,
            event_name TEXT,
            sender TEXT,
            raw_json JSONB NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS indexer_progress (
            progress_key TEXT PRIMARY KEY,
            next_checkpoint BIGINT NOT NULL,
            updated_at_ms BIGINT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "ALTER TABLE events DROP CONSTRAINT IF EXISTS events_transaction_digest_raw_json_key;",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender);")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_events_package_module ON events(package_id, module);",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_checkpoint ON events(checkpoint_seq);")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_tx_raw_json_md5 ON events(transaction_digest, md5(raw_json::text));",
    )
    .execute(pool)
    .await?;

    Ok(())
}
