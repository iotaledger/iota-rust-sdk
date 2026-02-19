use std::str::FromStr;

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::error::{AppError, AppResult};

pub const WATERMARK_KEY: &str = "last_processed_checkpoint";

pub async fn connect(db_url: &str) -> AppResult<PgPool> {
    let options = PgConnectOptions::from_str(db_url)
        .map_err(|e| AppError::validation("db_url", format!("invalid postgres url: {e}")))?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;
    Ok(pool)
}

pub async fn init(pool: &PgPool) -> AppResult<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS checkpoints (
            sequence_number BIGINT PRIMARY KEY,
            digest TEXT NOT NULL UNIQUE,
            timestamp_ms BIGINT NOT NULL,
            raw_json TEXT NOT NULL,
            indexed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS transactions (
            digest TEXT PRIMARY KEY,
            checkpoint_sequence BIGINT NOT NULL,
            sender TEXT NOT NULL,
            kind TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            tx_bcs_base64 TEXT NOT NULL,
            effects_bcs_base64 TEXT NOT NULL,
            indexed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (checkpoint_sequence) REFERENCES checkpoints(sequence_number)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_transactions_checkpoint ON transactions(checkpoint_sequence);",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY,
            tx_digest TEXT NOT NULL,
            event_index BIGINT NOT NULL,
            checkpoint_sequence BIGINT NOT NULL,
            sender TEXT,
            emitting_module TEXT,
            package TEXT,
            event_type TEXT NOT NULL,
            event_timestamp TEXT,
            event_json TEXT NOT NULL,
            event_bcs_base64 TEXT NOT NULL,
            indexed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (tx_digest, event_index),
            FOREIGN KEY (tx_digest) REFERENCES transactions(digest),
            FOREIGN KEY (checkpoint_sequence) REFERENCES checkpoints(sequence_number)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_checkpoint ON events(checkpoint_sequence);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
        .execute(pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS indexer_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_watermark(pool: &PgPool) -> AppResult<Option<u64>> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key = $1")
            .bind(WATERMARK_KEY)
            .fetch_optional(pool)
            .await?;

    value
        .map(|inner| inner.parse::<u64>())
        .transpose()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::{WATERMARK_KEY, get_watermark, init};

    #[tokio::test]
    async fn watermark_roundtrip() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };

        let pool = PgPool::connect(&db_url)
            .await
            .expect("postgres should connect");
        init(&pool).await.expect("db init should succeed");

        let initial = get_watermark(&pool).await.expect("read watermark");
        assert!(initial.is_none());

        sqlx::query(
            "INSERT INTO indexer_state (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(WATERMARK_KEY)
        .bind("42")
        .execute(&pool)
        .await
        .expect("upsert watermark");

        let updated = get_watermark(&pool).await.expect("read updated watermark");
        assert_eq!(updated, Some(42));
    }
}
