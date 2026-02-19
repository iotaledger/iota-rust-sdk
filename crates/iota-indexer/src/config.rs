use std::str::FromStr;

use clap::{Parser, ValueEnum};
use iota_sdk::{
    graphql_client::{Client, query_types::TransactionBlockKindInput},
    types::Address,
};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Parser)]
#[command(name = "iota-indexer")]
#[command(about = "Index checkpoints, transactions, and events into PostgreSQL")]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = Network::Testnet)]
    pub network: Network,

    #[arg(long)]
    pub rpc_url: Option<String>,

    #[arg(
        long,
        default_value = "postgres://postgres:postgres@localhost:5432/iota_indexer"
    )]
    pub db_url: String,

    #[arg(long)]
    pub start_checkpoint: Option<u64>,

    #[arg(long)]
    pub end_checkpoint: Option<u64>,

    #[arg(long, default_value_t = 50)]
    pub page_size: i32,

    #[arg(long, default_value_t = false)]
    pub continuous: bool,

    #[arg(long, default_value_t = 5000)]
    pub poll_interval_ms: u64,

    #[arg(long, default_value_t = 3)]
    pub max_retries: u32,

    #[arg(long, default_value_t = 500)]
    pub retry_base_ms: u64,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub include_failed_txs: bool,

    #[arg(long)]
    pub tx_sender: Option<String>,

    #[arg(long)]
    pub tx_function: Option<String>,

    #[arg(long)]
    pub tx_kind: Option<String>,

    #[arg(long)]
    pub event_sender: Option<String>,

    #[arg(long)]
    pub event_type: Option<String>,

    #[arg(long)]
    pub event_emitting_module: Option<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Localnet,
    Custom,
}

#[derive(Debug, Clone)]
pub struct TxFilterConfig {
    pub sender: Option<Address>,
    pub function: Option<String>,
    pub kind: Option<TransactionBlockKindInput>,
}

#[derive(Debug, Clone)]
pub struct EventFilterConfig {
    pub sender: Option<Address>,
    pub event_type: Option<String>,
    pub emitting_module: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub db_url: String,
    pub start_checkpoint: Option<u64>,
    pub end_checkpoint: Option<u64>,
    pub page_size: i32,
    pub continuous: bool,
    pub poll_interval_ms: u64,
    pub max_retries: u32,
    pub retry_base_ms: u64,
    pub include_failed_txs: bool,
    pub tx_filter: TxFilterConfig,
    pub event_filter: EventFilterConfig,
    pub network: Network,
    pub rpc_url: Option<String>,
}

impl TryFrom<Cli> for AppConfig {
    type Error = AppError;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        if value.page_size <= 0 {
            return Err(AppError::validation("page_size", "must be > 0"));
        }

        if value.continuous && value.end_checkpoint.is_some() {
            return Err(AppError::validation(
                "end_checkpoint",
                "cannot be set in continuous mode",
            ));
        }

        if value.max_retries > 10 {
            return Err(AppError::validation("max_retries", "must be <= 10"));
        }

        if value.retry_base_ms == 0 {
            return Err(AppError::validation("retry_base_ms", "must be > 0"));
        }

        let tx_sender = parse_address_opt(value.tx_sender.as_deref(), "tx_sender")?;
        let event_sender = parse_address_opt(value.event_sender.as_deref(), "event_sender")?;
        let tx_kind = parse_tx_kind_opt(value.tx_kind.as_deref())?;

        if value.network == Network::Custom && value.rpc_url.is_none() {
            return Err(AppError::validation(
                "rpc_url",
                "is required when network=custom",
            ));
        }

        Ok(Self {
            db_url: value.db_url,
            start_checkpoint: value.start_checkpoint,
            end_checkpoint: value.end_checkpoint,
            page_size: value.page_size,
            continuous: value.continuous,
            poll_interval_ms: value.poll_interval_ms,
            max_retries: value.max_retries,
            retry_base_ms: value.retry_base_ms,
            include_failed_txs: value.include_failed_txs,
            tx_filter: TxFilterConfig {
                sender: tx_sender,
                function: value.tx_function,
                kind: tx_kind,
            },
            event_filter: EventFilterConfig {
                sender: event_sender,
                event_type: value.event_type,
                emitting_module: value.event_emitting_module,
            },
            network: value.network,
            rpc_url: value.rpc_url,
        })
    }
}

impl AppConfig {
    pub fn build_client(&self) -> AppResult<Client> {
        let client = match self.network {
            Network::Mainnet => Client::new_mainnet(),
            Network::Testnet => Client::new_testnet(),
            Network::Devnet => Client::new_devnet(),
            Network::Localnet => Client::new_localnet(),
            Network::Custom => {
                let rpc_url = self
                    .rpc_url
                    .as_deref()
                    .ok_or_else(|| AppError::validation("rpc_url", "missing custom URL"))?;
                Client::new(rpc_url)?
            }
        };

        Ok(client)
    }
}

fn parse_address_opt(input: Option<&str>, field: &'static str) -> AppResult<Option<Address>> {
    match input {
        Some(raw) => Address::from_str(raw)
            .map(Some)
            .map_err(|e| AppError::validation(field, e.to_string())),
        None => Ok(None),
    }
}

fn parse_tx_kind_opt(input: Option<&str>) -> AppResult<Option<TransactionBlockKindInput>> {
    let Some(raw_kind) = input else {
        return Ok(None);
    };

    let normalized = raw_kind.to_ascii_lowercase();
    let parsed = match normalized.as_str() {
        "system_tx" | "system" => TransactionBlockKindInput::SystemTx,
        "programmable_tx" | "programmable" => TransactionBlockKindInput::ProgrammableTx,
        "genesis" => TransactionBlockKindInput::Genesis,
        "consensus_commit_prologue_v1" | "consensus_v1" => {
            TransactionBlockKindInput::ConsensusCommitPrologueV1
        }
        "authenticator_state_update_v1" | "authenticator_v1" => {
            TransactionBlockKindInput::AuthenticatorStateUpdateV1
        }
        "randomness_state_update" | "randomness" => {
            TransactionBlockKindInput::RandomnessStateUpdate
        }
        "end_of_epoch_tx" | "end_of_epoch" => TransactionBlockKindInput::EndOfEpochTx,
        _ => {
            return Err(AppError::validation(
                "tx_kind",
                format!("unsupported value: {raw_kind}"),
            ));
        }
    };

    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, Cli, Network};

    fn base_cli() -> Cli {
        Cli {
            network: Network::Testnet,
            rpc_url: None,
            db_url: "postgres://postgres:postgres@localhost:5432/iota_indexer".to_owned(),
            start_checkpoint: None,
            end_checkpoint: None,
            page_size: 50,
            continuous: false,
            poll_interval_ms: 5000,
            max_retries: 3,
            retry_base_ms: 500,
            include_failed_txs: true,
            tx_sender: None,
            tx_function: None,
            tx_kind: None,
            event_sender: None,
            event_type: None,
            event_emitting_module: None,
        }
    }

    #[test]
    fn rejects_custom_without_rpc_url() {
        let mut cli = base_cli();
        cli.network = Network::Custom;

        let config = AppConfig::try_from(cli);
        assert!(config.is_err());
    }

    #[test]
    fn rejects_too_many_retries() {
        let mut cli = base_cli();
        cli.max_retries = 42;

        let config = AppConfig::try_from(cli);
        assert!(config.is_err());
    }

    #[test]
    fn rejects_zero_retry_base() {
        let mut cli = base_cli();
        cli.retry_base_ms = 0;

        let config = AppConfig::try_from(cli);
        assert!(config.is_err());
    }
}
