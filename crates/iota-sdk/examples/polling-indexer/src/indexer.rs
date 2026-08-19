// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{cmp, collections::HashMap, time::Duration};

use iota_sdk::{
    graphql_client::{
        Client, PaginationFilter,
        query_types::{EventFilter, TransactionsFilter},
    },
    types::{ExecutionStatus, SignedTransaction, Transaction},
};
use serde_json::json;
use sqlx::PgPool;
use tracing::{debug, info, warn};

use crate::{
    config::{AppConfig, FilterConfig},
    db::progress,
};

// ------------------------------------------------------------------
// Processing result & retry helpers
// ------------------------------------------------------------------

enum ProcessResult {
    /// Successfully processed. Value is the next checkpoint to resume from.
    Advance(u64),
    /// The unit of work is not ready yet (e.g. checkpoint not indexed
    /// on-chain).
    NotReady,
}

struct RetryState {
    consecutive_failures: u32,
    base_interval: Duration,
}

impl RetryState {
    const MAX_DELAY: Duration = Duration::from_secs(30);

    fn new(base_interval: Duration) -> Self {
        Self {
            consecutive_failures: 0,
            base_interval,
        }
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    fn failures(&self) -> u32 {
        self.consecutive_failures
    }

    fn next_delay(&mut self) -> Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let exponent = self.consecutive_failures.saturating_sub(1).min(5);
        let factor = 1_u32 << exponent;
        cmp::min(self.base_interval.saturating_mul(factor), Self::MAX_DELAY)
    }
}

// ------------------------------------------------------------------
// Indexer
// ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // Polling loop
    // ------------------------------------------------------------------

    pub async fn run(&self) -> anyhow::Result<()> {
        let filtered = self.config.filters.has_filters();
        let mode_name = if filtered {
            "batch filtered"
        } else {
            "per-checkpoint"
        };

        let state = progress::load(&self.pool, &self.config.progress_key).await?;
        let mut position = self
            .config
            .start_checkpoint
            .unwrap_or(state.next_checkpoint);

        if let Some(start) = self.config.start_checkpoint
            && start != state.next_checkpoint
            && state.next_checkpoint > 0
        {
            warn!(
                configured_start_checkpoint = start,
                stored_next_checkpoint = state.next_checkpoint,
                "configured start_checkpoint differs from stored progress; \
                 using configured value"
            );
        }

        let mut retry = RetryState::new(self.config.poll_interval);

        info!(
            graphql_url = %self.config.graphql_url,
            start = position,
            "starting SDK polling indexer ({mode_name} mode)"
        );

        loop {
            let latest = self
                .client
                .latest_checkpoint_sequence_number()
                .await?
                .unwrap_or(0);

            let upper = self
                .config
                .end_checkpoint
                .map_or(latest, |end| end.min(latest));

            if position > upper {
                if self.config.end_checkpoint.is_some() {
                    info!(position, upper, "reached configured end checkpoint");
                    return Ok(());
                }
                debug!(position, latest, "no new checkpoints yet");
                tokio::time::sleep(self.config.poll_interval).await;
                continue;
            }

            let result = if filtered {
                let range_end = position.saturating_add(self.config.batch_range).min(upper);
                self.process_batch(position, range_end)
                    .await
                    .map(|()| ProcessResult::Advance(range_end.saturating_add(1)))
            } else {
                self.process_checkpoint(position).await.map(|ready| {
                    if ready {
                        ProcessResult::Advance(position.saturating_add(1))
                    } else {
                        ProcessResult::NotReady
                    }
                })
            };

            match result {
                Ok(ProcessResult::Advance(next)) => {
                    retry.reset();
                    position = next;
                    progress::store(&self.pool, &self.config.progress_key, position).await?;
                }
                Ok(ProcessResult::NotReady) => {
                    retry.reset();
                    warn!(checkpoint = position, "checkpoint not ready yet; retrying");
                    tokio::time::sleep(self.config.poll_interval).await;
                }
                Err(err) => {
                    let delay = retry.next_delay();
                    warn!(
                        position,
                        error = %err,
                        consecutive_failures = retry.failures(),
                        retry_in_ms = delay.as_millis(),
                        "processing failed; retrying with backoff"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Batch filtered mode
    // ------------------------------------------------------------------

    /// Query transactions across `[range_start, range_end]` in one paginated
    /// stream, storing matching transactions and their events.
    async fn process_batch(&self, range_start: u64, range_end: u64) -> anyhow::Result<()> {
        info!(range_start, range_end, "processing batch");

        let tx_filter = TransactionsFilter::default()
            .with_function(self.config.filters.derived_tx_function())
            .with_sent_address(self.config.filters.tx_sender)
            .with_after_checkpoint(range_start.checked_sub(1))
            .with_before_checkpoint(range_end.saturating_add(1));

        let mut tx_cursor: Option<String> = None;
        let mut tx_count = 0_u64;

        loop {
            let tx_page = self
                .client
                .transactions_data_effects(
                    tx_filter.clone(),
                    PaginationFilter {
                        limit: Some(self.config.page_size),
                        cursor: tx_cursor.clone(),
                        ..Default::default()
                    },
                )
                .await?;

            // Single pass: pair each eligible transaction with its digest.
            let eligible: Vec<_> = tx_page
                .data()
                .iter()
                .filter(|td| {
                    self.config.filters.include_failed_txs
                        || matches!(td.effects.as_v1().status, ExecutionStatus::Success)
                })
                .map(|td| {
                    let digest = td.effects.as_v1().transaction_digest.to_string();
                    (td, digest)
                })
                .collect();

            // Batch-fetch checkpoint numbers in a single GraphQL query.
            let digests: Vec<String> = eligible.iter().map(|(_, d)| d.clone()).collect();
            let checkpoint_map = batch_lookup_tx_checkpoints(&self.client, &digests).await?;

            for (tx_data, tx_digest) in &eligible {
                let checkpoint_seq = checkpoint_map.get(tx_digest).copied().flatten();

                let event_count = self
                    .store_events_for_transaction(checkpoint_seq, tx_digest)
                    .await?;

                // When only event filters are set (package derived from
                // event_type), skip transactions that produced no matching
                // events.
                if self.config.filters.is_event_only() && event_count == 0 {
                    continue;
                }

                let sender = sender_str(&tx_data.tx);
                let kind = tx_kind_str(&tx_data.tx);
                let success = matches!(tx_data.effects.as_v1().status, ExecutionStatus::Success);

                sqlx::query(
                    r#"
                    INSERT INTO transactions
                        (checkpoint_seq, transaction_digest, sender, kind, success, raw_json)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT(transaction_digest) DO NOTHING
                    "#,
                )
                .bind(checkpoint_seq.map(|c| c as i64))
                .bind(tx_digest.as_str())
                .bind(sender)
                .bind(kind)
                .bind(success)
                .bind(serde_json::to_value(tx_data)?)
                .execute(&self.pool)
                .await?;

                tx_count += 1;
            }

            if !tx_page.page_info.has_next_page {
                break;
            }
            tx_cursor = tx_page.page_info.end_cursor.clone();
        }

        info!(range_start, range_end, tx_count, "batch complete");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Per-checkpoint mode
    // ------------------------------------------------------------------

    async fn checkpoint_exists(&self, sequence: u64) -> anyhow::Result<bool> {
        let row = sqlx::query("SELECT 1 FROM checkpoints WHERE sequence_number = $1")
            .bind(sequence as i64)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn process_checkpoint(&self, sequence: u64) -> anyhow::Result<bool> {
        if self.checkpoint_exists(sequence).await? {
            debug!(sequence, "checkpoint already indexed; skipping");
            return Ok(true);
        }

        let Some(checkpoint) = self.client.checkpoint(None, Some(sequence)).await? else {
            return Ok(false);
        };

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
        .bind(sequence as i64)
        .bind(checkpoint.contents_digest.to_string())
        .bind(checkpoint.timestamp_ms as i64)
        .bind(serde_json::to_value(&checkpoint)?)
        .execute(&self.pool)
        .await?;

        let tx_filter = TransactionsFilter::default()
            .with_function(self.config.filters.tx_function.clone())
            .with_sent_address(self.config.filters.tx_sender)
            .with_after_checkpoint(sequence.checked_sub(1))
            .with_before_checkpoint(sequence.saturating_add(1));

        let mut tx_cursor: Option<String> = None;
        loop {
            let tx_page = self
                .client
                .transactions_data_effects(
                    tx_filter.clone(),
                    PaginationFilter {
                        limit: Some(self.config.page_size),
                        cursor: tx_cursor.clone(),
                        ..Default::default()
                    },
                )
                .await?;

            for tx_data in tx_page.data() {
                if !self.config.filters.include_failed_txs
                    && !matches!(tx_data.effects.as_v1().status, ExecutionStatus::Success)
                {
                    continue;
                }

                let tx_digest = tx_data.effects.as_v1().transaction_digest.to_string();
                let sender = sender_str(&tx_data.tx);
                let kind = tx_kind_str(&tx_data.tx);
                let success = matches!(tx_data.effects.as_v1().status, ExecutionStatus::Success);

                sqlx::query(
                    r#"
                    INSERT INTO transactions
                        (checkpoint_seq, transaction_digest, sender, kind, success, timestamp_ms, raw_json)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT(transaction_digest)
                    DO UPDATE SET
                        checkpoint_seq = excluded.checkpoint_seq,
                        sender = excluded.sender,
                        kind = excluded.kind,
                        success = excluded.success,
                        timestamp_ms = excluded.timestamp_ms,
                        raw_json = excluded.raw_json
                    "#,
                )
                .bind(sequence as i64)
                .bind(&tx_digest)
                .bind(sender)
                .bind(kind)
                .bind(success)
                .bind(checkpoint.timestamp_ms as i64)
                .bind(serde_json::to_value(tx_data)?)
                .execute(&self.pool)
                .await?;

                self.store_events_for_transaction(Some(sequence), &tx_digest)
                    .await?;
            }

            if !tx_page.page_info.has_next_page {
                break;
            }
            tx_cursor = tx_page.page_info.end_cursor.clone();
        }

        info!(sequence, "stored checkpoint");
        Ok(true)
    }

    // ------------------------------------------------------------------
    // Shared: event storage
    // ------------------------------------------------------------------

    /// Store events for a transaction. Returns the number of matching events
    /// stored.
    async fn store_events_for_transaction(
        &self,
        checkpoint: Option<u64>,
        transaction_digest: &str,
    ) -> anyhow::Result<u64> {
        let mut cursor: Option<String> = None;
        let mut stored = 0_u64;

        loop {
            let event_page = self
                .client
                .events(
                    EventFilter::default()
                        .with_transaction_digest(transaction_digest.to_owned())
                        .with_event_type(self.config.filters.event_type.clone()),
                    PaginationFilter {
                        limit: Some(self.config.page_size),
                        cursor: cursor.clone(),
                        ..Default::default()
                    },
                )
                .await?;

            for event in event_page.data() {
                if !event_matches(event, &self.config.filters) {
                    continue;
                }

                let package_id = event
                    .sending_module
                    .as_ref()
                    .map(|m| m.package.address.to_string());
                let module = event.sending_module.as_ref().map(|m| m.name.clone());
                let sender = event.sender.as_ref().map(|s| s.address.to_string());
                let event_type = event.type_.repr.clone();
                let event_name = extract_event_name(&event_type);

                let raw_json = json!({
                    "event_type": event_type,
                    "module": module,
                    "package_id": package_id,
                    "sender": sender,
                    "timestamp": event.timestamp.as_ref().map(|t| t.0.clone()),
                    "json": event.json,
                });

                sqlx::query(
                    r#"
                    INSERT INTO events
                        (checkpoint_seq, transaction_digest, package_id, module, event_name, sender, raw_json)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(checkpoint.map(|c| c as i64))
                .bind(transaction_digest)
                .bind(package_id)
                .bind(module)
                .bind(event_name)
                .bind(sender)
                .bind(raw_json)
                .execute(&self.pool)
                .await?;

                stored += 1;
            }

            if !event_page.page_info.has_next_page {
                break;
            }
            cursor = event_page.page_info.end_cursor.clone();
        }

        Ok(stored)
    }
}

// ------------------------------------------------------------------
// Free functions
// ------------------------------------------------------------------

fn sender_str(tx: &SignedTransaction) -> Option<String> {
    match &tx.transaction {
        Transaction::V1(v1) => Some(v1.sender.to_string()),
        _ => None,
    }
}

fn tx_kind_str(tx: &SignedTransaction) -> String {
    match &tx.transaction {
        Transaction::V1(v1) => match &v1.kind {
            iota_sdk::types::transaction::TransactionKind::Programmable(_) => {
                "programmable".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::Genesis(_) => "genesis".to_owned(),
            iota_sdk::types::transaction::TransactionKind::ConsensusCommitPrologueV1(_) => {
                "consensus_commit_prologue_v1".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::AuthenticatorStateUpdateV1Deprecated => {
                "authenticator_state_update_v1_deprecated".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::EndOfEpoch(_) => {
                "end_of_epoch".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::RandomnessStateUpdate(_) => {
                "randomness_state_update".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::TransactionDenyRulesUpdate(_) => {
                "transaction_deny_rules_update".to_owned()
            }
            _ => "unknown".to_owned(),
        },
        _ => "unknown".to_owned(),
    }
}

/// Extract the short event name from a fully qualified event type.
/// Handles generic types like `0x2::display::DisplayCreated<0x107a::nft::Nft>`
/// → `DisplayCreated<0x107a::nft::Nft>`.
fn extract_event_name(event_type: &str) -> String {
    if let Some(angle_pos) = event_type.find('<') {
        let prefix = &event_type[..angle_pos];
        let name = prefix.rsplit("::").next().unwrap_or(prefix);
        format!("{}{}", name, &event_type[angle_pos..])
    } else {
        event_type
            .rsplit("::")
            .next()
            .unwrap_or(event_type)
            .to_owned()
    }
}

/// Batch-fetch checkpoint sequence numbers for multiple transactions using
/// aliased GraphQL queries, avoiding per-transaction round-trips. Digests are
/// processed in chunks to stay within GraphQL query complexity limits.
async fn batch_lookup_tx_checkpoints(
    client: &Client,
    digests: &[String],
) -> anyhow::Result<HashMap<String, Option<u64>>> {
    const CHUNK_SIZE: usize = 50;

    if digests.is_empty() {
        return Ok(HashMap::new());
    }

    let mut result = HashMap::with_capacity(digests.len());

    for chunk in digests.chunks(CHUNK_SIZE) {
        let mut var_decls = Vec::with_capacity(chunk.len());
        let mut query_fields = Vec::with_capacity(chunk.len());
        let mut variables = serde_json::Map::new();

        for (i, digest) in chunk.iter().enumerate() {
            var_decls.push(format!("$d{i}: String!"));
            query_fields.push(format!(
                "t{i}: transactionBlock(digest: $d{i}) \
                 {{ effects {{ checkpoint {{ sequenceNumber }} }} }}"
            ));
            variables.insert(format!("d{i}"), serde_json::Value::String(digest.clone()));
        }

        let query_str = format!(
            "query({}) {{ {} }}",
            var_decls.join(", "),
            query_fields.join(" "),
        );

        let request = serde_json::json!({
            "query": query_str,
            "variables": serde_json::Value::Object(variables),
        });
        let map = request.as_object().unwrap().clone();
        let response = client.run_query_from_json(map).await?;

        if let Some(data) = response.data {
            for (i, digest) in chunk.iter().enumerate() {
                let seq = data
                    .get(format!("t{i}").as_str())
                    .and_then(|tb| tb.get("effects"))
                    .and_then(|e| e.get("checkpoint"))
                    .and_then(|c| c.get("sequenceNumber"))
                    .and_then(|s| s.as_u64());
                result.insert(digest.clone(), seq);
            }
        }
    }

    Ok(result)
}

fn event_matches(
    event: &iota_sdk::graphql_client::query_types::Event,
    filters: &FilterConfig,
) -> bool {
    if let Some(expected_module) = &filters.event_sending_module {
        let module = event.sending_module.as_ref().map(|m| m.name.as_str());
        if module != Some(expected_module.as_str()) {
            return false;
        }
    }

    if let Some(expected_package) = &filters.event_package_id {
        let package = event
            .sending_module
            .as_ref()
            .map(|m| m.package.address.to_string());
        if package.as_deref() != Some(expected_package.as_str()) {
            return false;
        }
    }

    true
}
