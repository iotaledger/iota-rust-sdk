// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{cmp, time::Duration};

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

    pub async fn run(&self) -> anyhow::Result<()> {
        if self.config.filters.has_event_filters() && !self.config.filters.has_tx_filters() {
            info!("event filters active — using direct event query mode");
            self.run_event_only().await
        } else if self.config.filters.has_tx_filters() {
            info!("transaction filters active — using batch query mode");
            self.run_filtered().await
        } else {
            self.run_per_checkpoint().await
        }
    }

    // ------------------------------------------------------------------
    // Direct event query mode: query events via the events API
    // ------------------------------------------------------------------

    /// Query events directly using the events API with cursor-based progress.
    /// Used when only event filters are set (no transaction filters), which is
    /// much faster than iterating through all transactions in a checkpoint
    /// range.
    async fn run_event_only(&self) -> anyhow::Result<()> {
        let state = progress::load(&self.pool, &self.config.progress_key).await?;
        let mut cursor = state.last_cursor;
        let mut consecutive_failures = 0_u32;

        if self.config.start_checkpoint.is_some() || self.config.end_checkpoint.is_some() {
            warn!(
                "start_checkpoint/end_checkpoint are ignored in direct event query mode; \
                 progress is tracked by cursor"
            );
        }

        info!(
            graphql_url = %self.config.graphql_url,
            has_cursor = cursor.is_some(),
            "starting SDK polling indexer (direct event query mode)"
        );

        // NOTE: The GraphQL EventFilter does not support combining
        // emitting_module and event_type in the same query (the server will
        // error). We prefer event_type when available, and fall back to
        // emitting_module. event_package_id is always a post-filter.
        let event_filter = if self.config.filters.event_type.is_some() {
            EventFilter {
                event_type: self.config.filters.event_type.clone(),
                ..Default::default()
            }
        } else {
            EventFilter {
                emitting_module: self.config.filters.event_sending_module.clone(),
                ..Default::default()
            }
        };

        loop {
            match self.poll_events(&event_filter, &mut cursor).await {
                Ok(count) => {
                    consecutive_failures = 0;
                    if count == 0 {
                        debug!("no new events; waiting");
                        tokio::time::sleep(self.config.poll_interval).await;
                    }
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let delay = retry_delay(self.config.poll_interval, consecutive_failures);
                    warn!(
                        error = %err,
                        consecutive_failures,
                        retry_in_ms = delay.as_millis(),
                        "event polling failed; retrying with backoff"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Paginate through all available events from the current cursor, storing
    /// each matching event. Returns the total number of events stored in this
    /// poll cycle. Updates `cursor` in place and persists it after each page.
    async fn poll_events(
        &self,
        filter: &EventFilter,
        cursor: &mut Option<String>,
    ) -> anyhow::Result<u64> {
        let mut total_stored = 0_u64;

        loop {
            let page = self
                .client
                .events(
                    filter.clone(),
                    PaginationFilter {
                        limit: Some(self.config.page_size),
                        cursor: cursor.clone(),
                        ..Default::default()
                    },
                )
                .await?;

            for event in page.data() {
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
                let event_name = event_type
                    .rsplit("::")
                    .next()
                    .unwrap_or(event_type.as_str())
                    .to_owned();

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
                        (package_id, module, event_name, sender, raw_json)
                    VALUES ($1, $2, $3, $4, $5)
                    "#,
                )
                .bind(&package_id)
                .bind(&module)
                .bind(&event_name)
                .bind(&sender)
                .bind(&raw_json)
                .execute(&self.pool)
                .await?;

                total_stored += 1;
            }

            if let Some(end_cursor) = &page.page_info.end_cursor {
                *cursor = Some(end_cursor.clone());
                progress::store_cursor(&self.pool, &self.config.progress_key, end_cursor).await?;
            }

            if !page.page_info.has_next_page {
                break;
            }
        }

        if total_stored > 0 {
            info!(total_stored, "stored events");
        }

        Ok(total_stored)
    }

    // ------------------------------------------------------------------
    // Batch filtered mode: query transactions across large checkpoint ranges
    // ------------------------------------------------------------------

    async fn run_filtered(&self) -> anyhow::Result<()> {
        let state = progress::load(&self.pool, &self.config.progress_key).await?;
        let mut range_start = self
            .config
            .start_checkpoint
            .unwrap_or(state.next_checkpoint);

        let mut consecutive_failures = 0_u32;

        info!(
            graphql_url = %self.config.graphql_url,
            range_start,
            "starting SDK polling indexer (batch filtered mode)"
        );

        loop {
            let latest = self
                .client
                .latest_checkpoint_sequence_number()
                .await?
                .unwrap_or(0);

            let global_upper = self
                .config
                .end_checkpoint
                .map_or(latest, |end| end.min(latest));

            if range_start > global_upper {
                if self.config.end_checkpoint.is_some() {
                    info!(
                        range_start,
                        global_upper, "reached configured end checkpoint"
                    );
                    return Ok(());
                }
                debug!(range_start, latest, "no new checkpoints yet");
                tokio::time::sleep(self.config.poll_interval).await;
                continue;
            }

            let range_end = (range_start + self.config.batch_range).min(global_upper);

            match self.process_batch(range_start, range_end).await {
                Ok(()) => {
                    consecutive_failures = 0;
                    range_start = range_end.saturating_add(1);
                    progress::store(&self.pool, &self.config.progress_key, range_start).await?;
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let delay = retry_delay(self.config.poll_interval, consecutive_failures);
                    warn!(
                        range_start,
                        range_end,
                        error = %err,
                        consecutive_failures,
                        retry_in_ms = delay.as_millis(),
                        "batch processing failed; retrying with backoff"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Query transactions across `[range_start, range_end]` in one paginated
    /// stream, storing matching transactions and their events.
    async fn process_batch(&self, range_start: u64, range_end: u64) -> anyhow::Result<()> {
        info!(range_start, range_end, "processing batch");

        let tx_filter = TransactionsFilter {
            function: self.config.filters.tx_function.clone(),
            sign_address: self.config.filters.tx_sender,
            after_checkpoint: range_start.checked_sub(1),
            before_checkpoint: Some(range_end.saturating_add(1)),
            ..Default::default()
        };

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

            for tx_data in tx_page.data() {
                if !self.config.filters.include_failed_txs
                    && !matches!(tx_data.effects.status(), ExecutionStatus::Success)
                {
                    continue;
                }

                let tx_digest = tx_data.effects.as_v1().transaction_digest.to_string();
                let checkpoint_seq = lookup_tx_checkpoint(&self.client, &tx_digest).await?;
                let sender = sender_str(&tx_data.tx);
                let kind = tx_kind_str(&tx_data.tx);
                let success = matches!(tx_data.effects.status(), ExecutionStatus::Success);

                sqlx::query(
                    r#"
                    INSERT INTO transactions
                        (checkpoint_seq, transaction_digest, sender, kind, success, raw_json)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT(transaction_digest) DO NOTHING
                    "#,
                )
                .bind(checkpoint_seq.map(|c| c as i64))
                .bind(&tx_digest)
                .bind(sender)
                .bind(kind)
                .bind(success)
                .bind(serde_json::to_value(tx_data)?)
                .execute(&self.pool)
                .await?;

                self.store_events_for_transaction(checkpoint_seq, &tx_digest)
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
    // Per-checkpoint mode: full indexing without filters
    // ------------------------------------------------------------------

    async fn run_per_checkpoint(&self) -> anyhow::Result<()> {
        let state = progress::load(&self.pool, &self.config.progress_key).await?;
        let mut next_checkpoint = state.next_checkpoint;
        let mut consecutive_failures = 0_u32;

        if let Some(start) = self.config.start_checkpoint {
            if start != state.next_checkpoint && state.next_checkpoint > 0 {
                warn!(
                    configured_start_checkpoint = start,
                    stored_next_checkpoint = state.next_checkpoint,
                    "configured start_checkpoint differs from stored progress; using configured value"
                );
            }
            next_checkpoint = start;
        }

        info!(
            graphql_url = %self.config.graphql_url,
            next_checkpoint,
            "starting SDK polling indexer (per-checkpoint mode)"
        );

        loop {
            let latest = self
                .client
                .latest_checkpoint_sequence_number()
                .await?
                .unwrap_or(0);

            let upper_bound = self
                .config
                .end_checkpoint
                .map_or(latest, |end| end.min(latest));

            if next_checkpoint > upper_bound {
                if self.config.end_checkpoint.is_some() {
                    info!(
                        next_checkpoint,
                        upper_bound, "reached configured end checkpoint"
                    );
                    return Ok(());
                }

                debug!(
                    next_checkpoint,
                    latest,
                    poll_interval_ms = self.config.poll_interval.as_millis(),
                    "no new checkpoints yet"
                );
                tokio::time::sleep(self.config.poll_interval).await;
                continue;
            }

            match self.process_checkpoint(next_checkpoint).await {
                Ok(true) => {
                    consecutive_failures = 0;
                    next_checkpoint = next_checkpoint.saturating_add(1);
                    progress::store(&self.pool, &self.config.progress_key, next_checkpoint).await?;
                }
                Ok(false) => {
                    consecutive_failures = 0;
                    warn!(
                        checkpoint = next_checkpoint,
                        "checkpoint not indexed yet; retrying"
                    );
                    tokio::time::sleep(self.config.poll_interval).await;
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let retry_delay = retry_delay(self.config.poll_interval, consecutive_failures);
                    warn!(
                        checkpoint = next_checkpoint,
                        error = %err,
                        consecutive_failures,
                        retry_in_ms = retry_delay.as_millis(),
                        "checkpoint processing failed; retrying with backoff"
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

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
        .bind(checkpoint.content_digest.to_string())
        .bind(checkpoint.timestamp_ms as i64)
        .bind(serde_json::to_value(&checkpoint)?)
        .execute(&self.pool)
        .await?;

        let tx_filter = TransactionsFilter {
            function: self.config.filters.tx_function.clone(),
            sign_address: self.config.filters.tx_sender,
            after_checkpoint: sequence.checked_sub(1),
            before_checkpoint: Some(sequence.saturating_add(1)),
            ..Default::default()
        };

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
                    && !matches!(tx_data.effects.status(), ExecutionStatus::Success)
                {
                    continue;
                }

                let tx_digest = tx_data.effects.as_v1().transaction_digest.to_string();
                let sender = sender_str(&tx_data.tx);
                let kind = tx_kind_str(&tx_data.tx);
                let success = matches!(tx_data.effects.status(), ExecutionStatus::Success);

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
                    EventFilter {
                        transaction_digest: Some(transaction_digest.to_owned()),
                        event_type: self.config.filters.event_type.clone(),
                        ..Default::default()
                    },
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
                let event_name = event_type
                    .rsplit("::")
                    .next()
                    .unwrap_or(event_type.as_str())
                    .to_owned();

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

fn sender_str(tx: &SignedTransaction) -> Option<String> {
    match &tx.transaction {
        Transaction::V1(v1) => Some(v1.sender.to_string()),
        _ => None,
    }
}

fn tx_kind_str(tx: &SignedTransaction) -> String {
    match &tx.transaction {
        Transaction::V1(v1) => match &v1.kind {
            iota_sdk::types::transaction::TransactionKind::ProgrammableTransaction(_) => {
                "programmable_transaction".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::Genesis(_) => "genesis".to_owned(),
            iota_sdk::types::transaction::TransactionKind::ConsensusCommitPrologueV1(_) => {
                "consensus_commit_prologue_v1".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::AuthenticatorStateUpdateV1(_) => {
                "authenticator_state_update_v1".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::EndOfEpoch(_) => {
                "end_of_epoch".to_owned()
            }
            iota_sdk::types::transaction::TransactionKind::RandomnessStateUpdate(_) => {
                "randomness_state_update".to_owned()
            }
            _ => "unknown".to_owned(),
        },
        _ => "unknown".to_owned(),
    }
}

fn retry_delay(base: Duration, consecutive_failures: u32) -> Duration {
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
    let exponent = consecutive_failures.saturating_sub(1).min(5);
    let factor = 1_u32 << exponent;
    cmp::min(base.saturating_mul(factor), MAX_RETRY_DELAY)
}

/// Look up the checkpoint sequence number for a transaction via a raw GraphQL
/// query, since the SDK's `transactions_data_effects` response does not include
/// checkpoint info.
async fn lookup_tx_checkpoint(client: &Client, tx_digest: &str) -> anyhow::Result<Option<u64>> {
    let query = serde_json::json!({
        "query": "query($digest: String!) { transactionBlock(digest: $digest) { effects { checkpoint { sequenceNumber } } } }",
        "variables": { "digest": tx_digest }
    });
    let map = query.as_object().unwrap().clone();
    let response = client.run_query_from_json(map).await?;
    let Some(data) = response.data else {
        return Ok(None);
    };
    let seq = data
        .get("transactionBlock")
        .and_then(|tb| tb.get("effects"))
        .and_then(|e| e.get("checkpoint"))
        .and_then(|c| c.get("sequenceNumber"))
        .and_then(|s| s.as_u64());
    Ok(seq)
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
