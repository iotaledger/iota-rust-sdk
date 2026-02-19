use std::sync::Arc;

use async_trait::async_trait;
use iota_data_ingestion_core::Worker;
use iota_types::{
    effects::TransactionEffectsAPI,
    full_checkpoint_content::{CheckpointData, CheckpointTransaction},
    transaction::TransactionDataAPI,
};
use sqlx::PgPool;
use tracing::info;

use crate::config::FilterConfig;

#[derive(Clone)]
pub struct DbWorker {
    pool: PgPool,
    filters: FilterConfig,
}

impl DbWorker {
    pub fn new(pool: PgPool, filters: FilterConfig) -> Self {
        Self { pool, filters }
    }

    fn tx_matches(&self, tx: &CheckpointTransaction) -> bool {
        if !self.filters.include_failed_txs && tx.effects.status().is_err() {
            return false;
        }

        if let Some(expected_sender) = &self.filters.tx_sender {
            let sender = tx.transaction.sender_address().to_string();
            if &sender != expected_sender {
                return false;
            }
        }

        true
    }

    fn event_matches(&self, event: &iota_types::event::Event) -> bool {
        if let Some(expected_pkg) = &self.filters.event_package_id
            && &event.package_id.to_string() != expected_pkg
        {
            return false;
        }

        if let Some(expected_module) = &self.filters.event_module
            && &event.transaction_module.to_string() != expected_module
        {
            return false;
        }

        if let Some(expected_type) = &self.filters.event_type
            && &event.type_.to_string() != expected_type
        {
            return false;
        }

        true
    }
}

#[async_trait]
impl Worker for DbWorker {
    type Error = anyhow::Error;
    type Message = ();

    async fn process_checkpoint(
        &self,
        checkpoint: Arc<CheckpointData>,
    ) -> Result<Self::Message, Self::Error> {
        let mut db_tx = self.pool.begin().await?;

        let sequence = checkpoint.checkpoint_summary.sequence_number as i64;
        let timestamp_ms = checkpoint.checkpoint_summary.timestamp_ms as i64;
        let digest = checkpoint.checkpoint_summary.digest().to_string();
        let checkpoint_json = serde_json::to_value(&*checkpoint)?;

        sqlx::query(
            r#"
            INSERT INTO checkpoints (sequence_number, timestamp_ms, digest, raw_data)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (sequence_number) DO UPDATE SET
                timestamp_ms = EXCLUDED.timestamp_ms,
                digest = EXCLUDED.digest,
                raw_data = EXCLUDED.raw_data
            "#,
        )
        .bind(sequence)
        .bind(timestamp_ms)
        .bind(digest)
        .bind(checkpoint_json)
        .execute(&mut *db_tx)
        .await?;

        for tx in &checkpoint.transactions {
            if !self.tx_matches(tx) {
                continue;
            }

            let tx_digest = tx.transaction.digest().to_string();
            let sender = Some(tx.transaction.sender_address().to_string());
            let kind = tx
                .transaction
                .data()
                .intent_message()
                .value
                .kind()
                .to_string();
            let success = tx.effects.status().is_ok();
            let tx_json = serde_json::to_value(tx)?;

            sqlx::query(
                r#"
                INSERT INTO transactions
                    (checkpoint_seq, transaction_digest, sender, kind, success, timestamp_ms, raw_transaction)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (checkpoint_seq, transaction_digest) DO UPDATE SET
                    sender = EXCLUDED.sender,
                    kind = EXCLUDED.kind,
                    success = EXCLUDED.success,
                    timestamp_ms = EXCLUDED.timestamp_ms,
                    raw_transaction = EXCLUDED.raw_transaction
                "#,
            )
            .bind(sequence)
            .bind(&tx_digest)
            .bind(sender)
            .bind(kind)
            .bind(success)
            .bind(timestamp_ms)
            .bind(tx_json)
            .execute(&mut *db_tx)
            .await?;

            if let Some(events) = &tx.events {
                for event in &events.data {
                    if !self.event_matches(event) {
                        continue;
                    }

                    let event_json = serde_json::to_value(event)?;
                    let event_name = event.type_.name.to_string();

                    sqlx::query(
                        r#"
                        INSERT INTO events
                            (checkpoint_seq, transaction_digest, package_id, module, event_name, sender, raw_event)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        "#,
                    )
                    .bind(sequence)
                    .bind(&tx_digest)
                    .bind(event.package_id.to_string())
                    .bind(event.transaction_module.to_string())
                    .bind(event_name)
                    .bind(event.sender.to_string())
                    .bind(event_json)
                    .execute(&mut *db_tx)
                    .await?;
                }
            }
        }

        db_tx.commit().await?;
        info!(sequence, "Stored checkpoint");
        Ok(())
    }
}
