// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr};

use clap::Parser;
use serde::Deserialize;

#[derive(Clone, Debug, Parser)]
#[command(name = "polling-indexer")]
#[command(about = "Custom polling indexer using iota_sdk::graphql_client::Client")]
pub struct Cli {
    #[arg(
        long,
        help = "Path to a JSON config file. CLI flags override file values"
    )]
    pub config: Option<String>,

    #[arg(
        long,
        help = "Network name (mainnet|testnet|devnet|localnet) (default: testnet)"
    )]
    pub network: Option<Network>,

    #[arg(long)]
    pub graphql_url: Option<String>,

    #[arg(
        long,
        help = "PostgreSQL connection URL (default: postgres://localhost:5432/polling_indexer)"
    )]
    pub db_url: Option<String>,

    #[arg(
        long,
        help = "Progress row key in PostgreSQL table indexer_progress (default: polling-indexer)"
    )]
    pub progress_key: Option<String>,

    #[arg(long)]
    pub start_checkpoint: Option<u64>,

    #[arg(long)]
    pub end_checkpoint: Option<u64>,

    #[arg(long, help = "Page size for GraphQL polling (default: 50)")]
    pub page_size: Option<i32>,

    #[arg(
        long,
        help = "Number of checkpoints per batch in filtered mode (default: 100000)"
    )]
    pub batch_range: Option<u64>,

    #[arg(long, help = "Polling interval in milliseconds (default: 2000)")]
    pub poll_interval_ms: Option<u64>,

    #[arg(long, action = clap::ArgAction::Set)]
    pub include_failed_txs: Option<bool>,

    #[arg(long, help = "Transaction function filter e.g. 0x2::module::function")]
    pub tx_function: Option<String>,

    #[arg(long, help = "Transaction signer address filter")]
    pub tx_sender: Option<String>,

    #[arg(long, help = "Event type filter e.g. 0x2::module::EventName")]
    pub event_type: Option<String>,

    #[arg(
        long,
        visible_alias = "event-module",
        help = "Event sending module filter (module where the event was emitted, not necessarily where the event type was defined)"
    )]
    pub event_sending_module: Option<String>,

    #[arg(long)]
    pub event_package_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
}

impl Network {
    pub fn graphql_url(&self) -> &str {
        match self {
            Self::Mainnet => "https://graphql.mainnet.iota.cafe",
            Self::Testnet => "https://graphql.testnet.iota.cafe",
            Self::Devnet => "https://graphql.devnet.iota.cafe",
            Self::Localnet => "http://localhost:9125/graphql",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
            Self::Localnet => write!(f, "localnet"),
        }
    }
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            "localnet" => Ok(Self::Localnet),
            _ => anyhow::bail!(
                "invalid network '{s}'. Expected one of mainnet|testnet|devnet|localnet"
            ),
        }
    }
}
