use std::{cmp, future::Future, time::Duration};

use base64ct::Encoding;
use iota_sdk::{
    graphql_client::{
        Client, PaginationFilter,
        output_types::TransactionDataEffects,
        query_types::{Event, EventFilter, TransactionsFilter},
    },
    types::{CheckpointSummary, ExecutionStatus, Transaction, TransactionKind},
};
use sqlx::{PgPool, Postgres, Transaction as PgTransaction};
use tracing::{debug, info};

use crate::{
    config::AppConfig,
    db::{WATERMARK_KEY, get_watermark},
    error::{AppError, AppResult},
    types::{EventRecord, TransactionRecord},
};

pub struct Indexer {
    client: Client,
    pool: PgPool,
    config: AppConfig,
}

impl Indexer {
    pub fn new(client: Client, pool: PgPool, config: AppConfig) -> Self {
        Self {
            client,
            pool,
            config,
        }
    }

    pub async fn run(&self) -> AppResult<()> {
        if self.config.continuous {
            loop {
                self.sync_once().await?;
                tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
            }
        }

        self.sync_once().await
    }

    async fn sync_once(&self) -> AppResult<()> {
        let latest_checkpoint = self.client.latest_checkpoint_sequence_number().await?;
        let Some(latest_checkpoint) = latest_checkpoint else {
            info!("No checkpoint is available yet from the target RPC");
            return Ok(());
        };

        let stored_watermark = get_watermark(&self.pool).await?;
        let resume_checkpoint = stored_watermark.map(|wm| wm.saturating_add(1));
        let start_checkpoint = match (resume_checkpoint, self.config.start_checkpoint) {
            (Some(resume), Some(requested)) => cmp::max(resume, requested),
            (Some(resume), None) => resume,
            (None, Some(requested)) => requested,
            (None, None) => 0,
        };
        let end_checkpoint = self
            .config
            .end_checkpoint
            .unwrap_or(latest_checkpoint)
            .min(latest_checkpoint);

        if start_checkpoint > end_checkpoint {
            debug!(
                start_checkpoint,
                end_checkpoint, latest_checkpoint, "No new checkpoints to index"
            );
            return Ok(());
        }

        info!(
            start_checkpoint,
            end_checkpoint, latest_checkpoint, "Starting checkpoint sync window"
        );

        for seq in start_checkpoint..=end_checkpoint {
            self.process_checkpoint(seq).await?;
        }

        Ok(())
    }

    async fn process_checkpoint(&self, sequence_number: u64) -> AppResult<()> {
        info!(sequence_number, "Processing checkpoint");

        let checkpoint = self
            .with_retry("fetch_checkpoint", || async {
                self.client
                    .checkpoint(None, Some(sequence_number))
                    .await
                    .map_err(Into::into)
            })
            .await?
            .ok_or(AppError::CheckpointNotFound(sequence_number))?;

        let transactions = self
            .fetch_transactions_for_checkpoint(sequence_number)
            .await?;
        let mut db_tx = self.pool.begin().await?;

        self.insert_checkpoint(&mut db_tx, &checkpoint).await?;

        for tx in transactions {
            let tx_record = tx_record_from_data_effects(&tx)?;
            if !self.config.include_failed_txs && !tx_record.success {
                continue;
            }

            self.insert_transaction(&mut db_tx, sequence_number, &tx_record)
                .await?;

            let events = self.fetch_events_for_tx(&tx_record.digest).await?;
            for (idx, event) in events.iter().enumerate() {
                let event_record = event_record_from_event(&tx_record.digest, idx as i64, event)?;
                self.insert_event(&mut db_tx, sequence_number, &event_record)
                    .await?;
            }
        }

        self.set_watermark(&mut db_tx, sequence_number).await?;
        db_tx.commit().await?;

        info!(sequence_number, "Checkpoint committed");
        Ok(())
    }

    async fn fetch_transactions_for_checkpoint(
        &self,
        checkpoint: u64,
    ) -> AppResult<Vec<TransactionDataEffects>> {
        let mut cursor = None;
        let mut all = Vec::new();

        loop {
            let tx_page = self
                .with_retry("fetch_transactions_page", || async {
                    self.client
                        .transactions_data_effects(
                            Some(self.build_transactions_filter(checkpoint)),
                            PaginationFilter {
                                cursor: cursor.clone(),
                                limit: Some(self.config.page_size),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
                .await?;

            let (page_info, page_data) = tx_page.into_parts();
            all.extend(page_data);

            if page_info.has_next_page {
                cursor = page_info.end_cursor;
            } else {
                break;
            }
        }

        Ok(all)
    }

    async fn fetch_events_for_tx(&self, tx_digest: &str) -> AppResult<Vec<Event>> {
        let mut cursor = None;
        let mut all = Vec::new();

        loop {
            let events_page = self
                .with_retry("fetch_events_page", || async {
                    self.client
                        .events(
                            Some(self.build_event_filter(tx_digest)),
                            PaginationFilter {
                                cursor: cursor.clone(),
                                limit: Some(self.config.page_size),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
                .await?;

            let (page_info, page_data) = events_page.into_parts();
            all.extend(page_data);

            if page_info.has_next_page {
                cursor = page_info.end_cursor;
            } else {
                break;
            }
        }

        Ok(all)
    }

    fn build_transactions_filter(&self, checkpoint: u64) -> TransactionsFilter {
        TransactionsFilter {
            function: self.config.tx_filter.function.clone(),
            kind: self.config.tx_filter.kind,
            at_checkpoint: Some(checkpoint),
            sign_address: self.config.tx_filter.sender,
            ..Default::default()
        }
    }

    fn build_event_filter(&self, tx_digest: &str) -> EventFilter {
        EventFilter {
            transaction_digest: Some(tx_digest.to_owned()),
            sender: self.config.event_filter.sender,
            event_type: self.config.event_filter.event_type.clone(),
            emitting_module: self.config.event_filter.emitting_module.clone(),
        }
    }

    async fn insert_checkpoint(
        &self,
        db_tx: &mut PgTransaction<'_, Postgres>,
        checkpoint: &CheckpointSummary,
    ) -> AppResult<()> {
        let raw_json = serde_json::to_string(checkpoint)?;

        sqlx::query(
            r#"
            INSERT INTO checkpoints (sequence_number, digest, timestamp_ms, raw_json)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT(sequence_number)
            DO UPDATE SET
                digest = excluded.digest,
                timestamp_ms = excluded.timestamp_ms,
                raw_json = excluded.raw_json
            "#,
        )
        .bind(checkpoint.sequence_number as i64)
        .bind(checkpoint.content_digest.to_string())
        .bind(checkpoint.timestamp_ms as i64)
        .bind(raw_json)
        .execute(&mut **db_tx)
        .await?;

        Ok(())
    }

    async fn insert_transaction(
        &self,
        db_tx: &mut PgTransaction<'_, Postgres>,
        checkpoint_sequence: u64,
        record: &TransactionRecord,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO transactions (
                digest,
                checkpoint_sequence,
                sender,
                kind,
                success,
                tx_bcs_base64,
                effects_bcs_base64
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT(digest)
            DO UPDATE SET
                checkpoint_sequence = excluded.checkpoint_sequence,
                sender = excluded.sender,
                kind = excluded.kind,
                success = excluded.success,
                tx_bcs_base64 = excluded.tx_bcs_base64,
                effects_bcs_base64 = excluded.effects_bcs_base64
            "#,
        )
        .bind(&record.digest)
        .bind(checkpoint_sequence as i64)
        .bind(&record.sender)
        .bind(&record.kind)
        .bind(record.success)
        .bind(&record.tx_bcs_base64)
        .bind(&record.effects_bcs_base64)
        .execute(&mut **db_tx)
        .await?;

        Ok(())
    }

    async fn insert_event(
        &self,
        db_tx: &mut PgTransaction<'_, Postgres>,
        checkpoint_sequence: u64,
        record: &EventRecord,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO events (
                tx_digest,
                event_index,
                checkpoint_sequence,
                sender,
                emitting_module,
                package,
                event_type,
                event_timestamp,
                event_json,
                event_bcs_base64
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT(tx_digest, event_index)
            DO UPDATE SET
                checkpoint_sequence = excluded.checkpoint_sequence,
                sender = excluded.sender,
                emitting_module = excluded.emitting_module,
                package = excluded.package,
                event_type = excluded.event_type,
                event_timestamp = excluded.event_timestamp,
                event_json = excluded.event_json,
                event_bcs_base64 = excluded.event_bcs_base64
            "#,
        )
        .bind(&record.tx_digest)
        .bind(record.event_index)
        .bind(checkpoint_sequence as i64)
        .bind(&record.sender)
        .bind(&record.emitting_module)
        .bind(&record.package)
        .bind(&record.event_type)
        .bind(&record.event_timestamp)
        .bind(&record.event_json)
        .bind(&record.event_bcs_base64)
        .execute(&mut **db_tx)
        .await?;

        Ok(())
    }

    async fn set_watermark(
        &self,
        db_tx: &mut PgTransaction<'_, Postgres>,
        checkpoint: u64,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO indexer_state (key, value, updated_at)
            VALUES ($1, $2, CURRENT_TIMESTAMP)
            ON CONFLICT(key)
            DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(WATERMARK_KEY)
        .bind(checkpoint.to_string())
        .execute(&mut **db_tx)
        .await?;

        Ok(())
    }

    async fn with_retry<T, F, Fut>(&self, operation: &'static str, mut f: F) -> AppResult<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = AppResult<T>>,
    {
        let max_retries = self.config.max_retries;
        let base_ms = self.config.retry_base_ms;
        let mut attempt: u32 = 0;

        loop {
            match f().await {
                Ok(value) => return Ok(value),
                Err(err) if attempt < max_retries => {
                    let exp = 1_u64 << attempt;
                    let delay_ms = base_ms.saturating_mul(exp);
                    info!(
                        operation,
                        attempt = attempt + 1,
                        max_retries,
                        delay_ms,
                        error = %err,
                        "Operation failed; retrying with backoff"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }
}

fn tx_record_from_data_effects(
    data_effects: &TransactionDataEffects,
) -> AppResult<TransactionRecord> {
    let transaction = &data_effects.tx.transaction;
    let sender = tx_sender(transaction);
    let kind = tx_kind_label(transaction);
    let success = matches!(data_effects.effects.status(), ExecutionStatus::Success);

    let tx_bcs = bcs::to_bytes(&data_effects.tx)?;
    let effects_bcs = bcs::to_bytes(&data_effects.effects)?;

    Ok(TransactionRecord {
        digest: transaction.digest().to_string(),
        sender,
        kind,
        success,
        tx_bcs_base64: base64ct::Base64::encode_string(&tx_bcs),
        effects_bcs_base64: base64ct::Base64::encode_string(&effects_bcs),
    })
}

fn event_record_from_event(
    tx_digest: &str,
    event_index: i64,
    event: &Event,
) -> AppResult<EventRecord> {
    let emitting_module = event.sending_module.as_ref().map(|m| m.name.clone());
    let package = event
        .sending_module
        .as_ref()
        .map(|m| m.package.address.to_string());

    let event_json = serde_json::to_string(&event.json)?;

    Ok(EventRecord {
        tx_digest: tx_digest.to_owned(),
        event_index,
        sender: event.sender.as_ref().map(|s| s.address.to_string()),
        emitting_module,
        package,
        event_type: event.type_.repr.clone(),
        event_timestamp: event.timestamp.as_ref().map(|t| t.0.clone()),
        event_json,
        event_bcs_base64: event.bcs.0.clone(),
    })
}

fn tx_sender(transaction: &Transaction) -> String {
    match transaction {
        Transaction::V1(v1) => v1.sender.to_string(),
        _ => "unknown".to_owned(),
    }
}

fn tx_kind_label(transaction: &Transaction) -> String {
    let label = match transaction {
        Transaction::V1(v1) => match &v1.kind {
            TransactionKind::ProgrammableTransaction(_) => "programmable_tx",
            TransactionKind::Genesis(_) => "genesis",
            TransactionKind::ConsensusCommitPrologueV1(_) => "consensus_commit_prologue_v1",
            TransactionKind::AuthenticatorStateUpdateV1(_) => "authenticator_state_update_v1",
            TransactionKind::EndOfEpoch(_) => "end_of_epoch_tx",
            TransactionKind::RandomnessStateUpdate(_) => "randomness_state_update",
            _ => "unknown",
        },
        _ => "unknown",
    };

    label.to_owned()
}

#[cfg(test)]
mod tests {
    use iota_sdk::graphql_client::query_types::TransactionBlockKindInput;

    use crate::config::{AppConfig, Cli, Network};

    #[test]
    fn parse_tx_kind_programmable() {
        let cli = Cli {
            network: Network::Testnet,
            rpc_url: None,
            db_url: "postgres://postgres:postgres@localhost:5432/iota_indexer".to_owned(),
            start_checkpoint: None,
            end_checkpoint: None,
            page_size: 10,
            continuous: false,
            poll_interval_ms: 1000,
            max_retries: 3,
            retry_base_ms: 500,
            include_failed_txs: true,
            tx_sender: None,
            tx_function: None,
            tx_kind: Some("programmable".to_owned()),
            event_sender: None,
            event_type: None,
            event_emitting_module: None,
        };

        let config = AppConfig::try_from(cli).expect("config should parse");
        assert!(matches!(
            config.tx_filter.kind,
            Some(TransactionBlockKindInput::ProgrammableTx)
        ));
    }
}
