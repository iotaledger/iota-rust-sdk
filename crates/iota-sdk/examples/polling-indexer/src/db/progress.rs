// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProgressState {
    pub next_checkpoint: u64,
    pub updated_at_ms: u128,
}

impl Default for ProgressState {
    fn default() -> Self {
        Self {
            next_checkpoint: 0,
            updated_at_ms: now_ms(),
        }
    }
}

pub async fn load(pool: &PgPool, progress_key: &str) -> anyhow::Result<ProgressState> {
    let row = sqlx::query(
        r#"
        SELECT next_checkpoint, updated_at_ms
        FROM indexer_progress
        WHERE progress_key = $1
        "#,
    )
    .bind(progress_key)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(ProgressState::default());
    };

    let next_checkpoint_i64: i64 = row.try_get("next_checkpoint")?;
    let updated_at_ms_i64: i64 = row.try_get("updated_at_ms")?;
    Ok(ProgressState {
        next_checkpoint: u64::try_from(next_checkpoint_i64)?,
        updated_at_ms: u128::try_from(updated_at_ms_i64)?,
    })
}

pub async fn store(pool: &PgPool, progress_key: &str, next_checkpoint: u64) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO indexer_progress (progress_key, next_checkpoint, updated_at_ms)
        VALUES ($1, $2, $3)
        ON CONFLICT(progress_key)
        DO UPDATE SET
            next_checkpoint = excluded.next_checkpoint,
            updated_at_ms = excluded.updated_at_ms
        "#,
    )
    .bind(progress_key)
    .bind(i64::try_from(next_checkpoint)?)
    .bind(i64::try_from(now_ms())?)
    .execute(pool)
    .await?;

    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
