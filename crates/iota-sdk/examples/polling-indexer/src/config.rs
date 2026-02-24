// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr};

use clap::Parser;
use iota_sdk::types::Address;

#[derive(Debug, Clone, Parser)]
#[command(name = "polling-indexer")]
#[command(about = "Custom polling indexer using iota_sdk::graphql_client::Client")]
pub struct Cli {
    #[arg(
        long,
        default_value_t = Network::Testnet,
        help = "Network name (mainnet|testnet|devnet|localnet) or custom:<graphql_url>"
    )]
    pub network: Network,

    #[arg(long)]
    pub graphql_url: Option<String>,

    #[arg(long, default_value = "postgres://localhost:5432/polling_indexer")]
    pub db_url: String,

    #[arg(long, default_value = ".polling_indexer_progress.json")]
    pub progress_file: String,

    #[arg(long)]
    pub start_checkpoint: Option<u64>,

    #[arg(long)]
    pub end_checkpoint: Option<u64>,

    #[arg(long, default_value_t = 50)]
    pub page_size: i32,

    #[arg(long, default_value_t = 2000)]
    pub poll_interval_ms: u64,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub include_failed_txs: bool,

    #[arg(long, help = "Transaction function filter e.g. 0x2::module::function")]
    pub tx_function: Option<String>,

    #[arg(long, help = "Transaction signer address filter")]
    pub tx_sender: Option<String>,

    #[arg(long, help = "Event type filter e.g. 0x2::module::EventName")]
    pub event_type: Option<String>,

    #[arg(long)]
    pub event_module: Option<String>,

    #[arg(long)]
    pub event_package_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
    Custom(String),
}

impl Network {
    pub fn graphql_url(&self) -> &str {
        match self {
            Self::Mainnet => "https://graphql.mainnet.iota.cafe",
            Self::Testnet => "https://graphql.testnet.iota.cafe",
            Self::Devnet => "https://graphql.devnet.iota.cafe",
            Self::Localnet => "http://localhost:9125/graphql",
            Self::Custom(url) => url,
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
            Self::Custom(url) => write!(f, "custom:{url}"),
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
            _ => {
                let Some((prefix, url)) = s.split_once(':') else {
                    anyhow::bail!(
                        "invalid network '{s}'. Expected one of mainnet|testnet|devnet|localnet or custom:<graphql_url>"
                    );
                };

                if !prefix.eq_ignore_ascii_case("custom") {
                    anyhow::bail!(
                        "invalid network '{s}'. Expected one of mainnet|testnet|devnet|localnet or custom:<graphql_url>"
                    );
                }

                if url.trim().is_empty() {
                    anyhow::bail!("custom network requires a non-empty GraphQL URL");
                }

                Ok(Self::Custom(url.to_owned()))
            }
        }
    }
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
