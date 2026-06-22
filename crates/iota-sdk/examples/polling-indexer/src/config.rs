// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, time::Duration};

use iota_sdk::types::Address;
use serde::Deserialize;

use crate::cli::{Cli, Network};

const DEFAULT_DB_URL: &str = "postgres://localhost:5432/polling_indexer";
const DEFAULT_PROGRESS_KEY: &str = "polling-indexer";
const DEFAULT_PAGE_SIZE: i32 = 50;
const DEFAULT_BATCH_RANGE: u64 = 100_000;
const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;
const DEFAULT_INCLUDE_FAILED_TXS: bool = true;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    /// Network preset name.
    /// Examples: "testnet", "mainnet", "localnet"
    network: Option<Network>,
    /// Explicit GraphQL URL override.
    /// Example: "https://graphql.testnet.iota.cafe"
    graphql_url: Option<String>,
    /// PostgreSQL connection string.
    /// Example: "postgres://postgres:postgres@localhost:5432/polling_indexer"
    db_url: Option<String>,
    /// Progress row key in the indexer_progress table.
    /// Example: "polling-indexer"
    progress_key: Option<String>,
    /// First checkpoint to index (inclusive).
    start_checkpoint: Option<u64>,
    /// Last checkpoint to index (inclusive). Omit for continuous mode.
    end_checkpoint: Option<u64>,
    /// GraphQL page size per request (must be > 0).
    page_size: Option<i32>,
    /// Number of checkpoints per batch in filtered mode.
    batch_range: Option<u64>,
    /// Polling interval in milliseconds when waiting for new checkpoints.
    poll_interval_ms: Option<u64>,
    /// Whether failed transactions should be indexed.
    include_failed_txs: Option<bool>,
    /// Transaction function filter.
    /// Example: "0x2::iota_system::request_add_stake"
    tx_function: Option<String>,
    /// Transaction signer address filter.
    /// Example: "0xabc123..."
    tx_sender: Option<String>,
    /// Event type filter.
    /// Example: "0x2::some_module::SomeEvent"
    event_type: Option<String>,
    /// Event sending module filter (where the event was emitted).
    /// Example: "iota_system"
    #[serde(alias = "event_module")]
    event_sending_module: Option<String>,
    /// Event sending package address filter.
    /// Example: "0x2"
    event_package_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FilterConfig {
    pub include_failed_txs: bool,
    pub tx_function: Option<String>,
    pub tx_sender: Option<Address>,
    pub event_type: Option<String>,
    pub event_sending_module: Option<String>,
    pub event_package_id: Option<String>,
}

impl FilterConfig {
    /// Returns `true` when any transaction or event filter is set, enabling
    /// batch query mode which queries across large checkpoint ranges instead
    /// of processing checkpoints one by one.
    pub fn has_filters(&self) -> bool {
        self.has_tx_filters() || self.has_event_filters()
    }

    pub fn has_tx_filters(&self) -> bool {
        self.tx_function.is_some() || self.tx_sender.is_some()
    }

    pub fn has_event_filters(&self) -> bool {
        self.event_type.is_some()
            || self.event_sending_module.is_some()
            || self.event_package_id.is_some()
    }

    /// Returns `true` when only event filters are active (no transaction-level
    /// filters). In this mode, the indexer derives a package filter from the
    /// event type and skips transactions that produce no matching events.
    pub fn is_event_only(&self) -> bool {
        self.has_event_filters() && !self.has_tx_filters()
    }

    /// Derive an effective transaction function filter for batch mode.
    /// When only event filters are set, extracts the package address from
    /// `event_type` (e.g. `"0x...::module::Event"` → `"0x..."`) or falls
    /// back to `event_package_id`.
    pub fn derived_tx_function(&self) -> Option<String> {
        self.tx_function.clone().or_else(|| {
            self.event_type
                .as_ref()
                .and_then(|et| et.split("::").next().map(|s| s.to_string()))
                .or_else(|| self.event_package_id.clone())
        })
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub graphql_url: String,
    pub db_url: String,
    pub progress_key: String,
    pub start_checkpoint: Option<u64>,
    pub end_checkpoint: Option<u64>,
    pub page_size: i32,
    pub batch_range: u64,
    pub poll_interval: Duration,
    pub filters: FilterConfig,
}

impl TryFrom<Cli> for AppConfig {
    type Error = anyhow::Error;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        let file_config = match value.config.as_deref() {
            Some(path) => {
                let contents = std::fs::read_to_string(path)?;
                serde_json::from_str::<FileConfig>(&contents).map_err(|err| {
                    anyhow::anyhow!("failed to parse config file '{path}' as JSON: {err}")
                })?
            }
            None => FileConfig::default(),
        };

        let network = match (value.network, file_config.network) {
            (Some(network), _) => network,
            (None, Some(network)) => network,
            (None, None) => Network::Testnet,
        };

        let page_size = value
            .page_size
            .or(file_config.page_size)
            .unwrap_or(DEFAULT_PAGE_SIZE);
        if page_size <= 0 {
            anyhow::bail!("page_size must be > 0");
        }

        let tx_sender = value
            .tx_sender
            .or(file_config.tx_sender)
            .as_deref()
            .map(Address::from_str)
            .transpose()?;

        let start_checkpoint = value.start_checkpoint.or(file_config.start_checkpoint);
        let end_checkpoint = value.end_checkpoint.or(file_config.end_checkpoint);

        if let (Some(start), Some(end)) = (start_checkpoint, end_checkpoint)
            && start > end
        {
            anyhow::bail!("start_checkpoint must be <= end_checkpoint");
        }

        let graphql_url = value
            .graphql_url
            .or(file_config.graphql_url)
            .unwrap_or_else(|| network.graphql_url().to_owned());

        let batch_range = value
            .batch_range
            .or(file_config.batch_range)
            .unwrap_or(DEFAULT_BATCH_RANGE);

        let poll_interval_ms = value
            .poll_interval_ms
            .or(file_config.poll_interval_ms)
            .unwrap_or(DEFAULT_POLL_INTERVAL_MS);

        let filters = FilterConfig {
            include_failed_txs: value
                .include_failed_txs
                .or(file_config.include_failed_txs)
                .unwrap_or(DEFAULT_INCLUDE_FAILED_TXS),
            tx_function: value.tx_function.or(file_config.tx_function),
            tx_sender,
            event_type: value.event_type.or(file_config.event_type),
            event_sending_module: value
                .event_sending_module
                .or(file_config.event_sending_module),
            event_package_id: value.event_package_id.or(file_config.event_package_id),
        };

        if filters.is_event_only() && filters.derived_tx_function().is_none() {
            anyhow::bail!(
                "event filters require --event-type or --event-package-id so the \
                 indexer can derive a transaction-level package filter"
            );
        }

        Ok(Self {
            graphql_url,
            db_url: value
                .db_url
                .or(file_config.db_url)
                .unwrap_or_else(|| DEFAULT_DB_URL.to_owned()),
            progress_key: value
                .progress_key
                .or(file_config.progress_key)
                .unwrap_or_else(|| DEFAULT_PROGRESS_KEY.to_owned()),
            start_checkpoint,
            end_checkpoint,
            page_size,
            batch_range,
            poll_interval: Duration::from_millis(poll_interval_ms),
            filters,
        })
    }
}
