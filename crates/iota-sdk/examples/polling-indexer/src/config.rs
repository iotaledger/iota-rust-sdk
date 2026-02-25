// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_sdk::types::Address;
use serde::Deserialize;

use crate::cli::{Cli, Network};

const DEFAULT_DB_URL: &str = "postgres://localhost:5432/polling_indexer";
const DEFAULT_PROGRESS_FILE: &str = ".polling_indexer_progress.json";
const DEFAULT_PAGE_SIZE: i32 = 50;
const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;
const DEFAULT_INCLUDE_FAILED_TXS: bool = true;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    network: Option<String>,
    graphql_url: Option<String>,
    db_url: Option<String>,
    progress_file: Option<String>,
    start_checkpoint: Option<u64>,
    end_checkpoint: Option<u64>,
    page_size: Option<i32>,
    poll_interval_ms: Option<u64>,
    include_failed_txs: Option<bool>,
    tx_function: Option<String>,
    tx_sender: Option<String>,
    event_type: Option<String>,
    event_module: Option<String>,
    event_package_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub include_failed_txs: bool,
    pub tx_function: Option<String>,
    pub tx_sender: Option<Address>,
    pub event_type: Option<String>,
    pub event_module: Option<String>,
    pub event_package_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub graphql_url: String,
    pub db_url: String,
    pub progress_file: String,
    pub start_checkpoint: Option<u64>,
    pub end_checkpoint: Option<u64>,
    pub page_size: i32,
    pub poll_interval_ms: u64,
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

        let network = match (value.network, file_config.network.as_deref()) {
            (Some(network), _) => network,
            (None, Some(network)) => Network::from_str(network)?,
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

        Ok(Self {
            graphql_url,
            db_url: value
                .db_url
                .or(file_config.db_url)
                .unwrap_or_else(|| DEFAULT_DB_URL.to_owned()),
            progress_file: value
                .progress_file
                .or(file_config.progress_file)
                .unwrap_or_else(|| DEFAULT_PROGRESS_FILE.to_owned()),
            start_checkpoint,
            end_checkpoint,
            page_size,
            poll_interval_ms: value
                .poll_interval_ms
                .or(file_config.poll_interval_ms)
                .unwrap_or(DEFAULT_POLL_INTERVAL_MS),
            filters: FilterConfig {
                include_failed_txs: value
                    .include_failed_txs
                    .or(file_config.include_failed_txs)
                    .unwrap_or(DEFAULT_INCLUDE_FAILED_TXS),
                tx_function: value.tx_function.or(file_config.tx_function),
                tx_sender,
                event_type: value.event_type.or(file_config.event_type),
                event_module: value.event_module.or(file_config.event_module),
                event_package_id: value.event_package_id.or(file_config.event_package_id),
            },
        })
    }
}
