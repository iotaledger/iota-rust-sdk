// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_sdk::types::Address;

use crate::cli::Cli;

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
        if value.page_size <= 0 {
            anyhow::bail!("page_size must be > 0");
        }

        let tx_sender = value
            .tx_sender
            .as_deref()
            .map(Address::from_str)
            .transpose()?;

        if let (Some(start), Some(end)) = (value.start_checkpoint, value.end_checkpoint)
            && start > end
        {
            anyhow::bail!("start_checkpoint must be <= end_checkpoint");
        }

        let graphql_url = value
            .graphql_url
            .unwrap_or_else(|| value.network.graphql_url().to_owned());

        Ok(Self {
            graphql_url,
            db_url: value.db_url,
            progress_file: value.progress_file,
            start_checkpoint: value.start_checkpoint,
            end_checkpoint: value.end_checkpoint,
            page_size: value.page_size,
            poll_interval_ms: value.poll_interval_ms,
            filters: FilterConfig {
                include_failed_txs: value.include_failed_txs,
                tx_function: value.tx_function,
                tx_sender,
                event_type: value.event_type,
                event_module: value.event_module,
                event_package_id: value.event_package_id,
            },
        })
    }
}
