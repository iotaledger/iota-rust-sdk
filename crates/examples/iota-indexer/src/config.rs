use clap::{Parser, ValueEnum};
use iota_data_ingestion_core::reader::v2::RemoteUrl;

#[derive(Debug, Clone, Parser)]
#[command(name = "iota-indexer")]
#[command(
    about = "Index checkpoints, transactions, and events into PostgreSQL using iota-data-ingestion-core"
)]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = Network::Testnet)]
    pub network: Network,

    #[arg(
        long,
        default_value = "postgres://postgres:postgres@localhost:5432/iota_indexer"
    )]
    pub db_url: String,

    #[arg(long, default_value = ".iota_indexer_progress.json")]
    pub progress_file: String,

    #[arg(long)]
    pub start_checkpoint: Option<u64>,

    #[arg(long)]
    pub end_checkpoint: Option<u64>,

    #[arg(long, default_value_t = 1)]
    pub worker_concurrency: usize,

    #[arg(long, default_value_t = 10)]
    pub batch_size: usize,

    #[arg(long, default_value_t = 100)]
    pub tick_interval_ms: u64,

    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,

    #[arg(long)]
    pub remote_fullnode_url: Option<String>,

    #[arg(long)]
    pub remote_historical_url: Option<String>,

    #[arg(long)]
    pub remote_live_url: Option<String>,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub include_failed_txs: bool,

    #[arg(long)]
    pub tx_sender: Option<String>,

    #[arg(long)]
    pub event_package_id: Option<String>,

    #[arg(long)]
    pub event_module: Option<String>,

    #[arg(long)]
    pub event_type: Option<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
    Custom,
}

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub include_failed_txs: bool,
    pub tx_sender: Option<String>,
    pub event_package_id: Option<String>,
    pub event_module: Option<String>,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub db_url: String,
    pub progress_file: String,
    pub start_checkpoint: Option<u64>,
    pub end_checkpoint: Option<u64>,
    pub worker_concurrency: usize,
    pub batch_size: usize,
    pub tick_interval_ms: u64,
    pub timeout_secs: u64,
    pub remote_url: RemoteUrl,
    pub task_name: String,
    pub filters: FilterConfig,
}

impl TryFrom<Cli> for AppConfig {
    type Error = anyhow::Error;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        if value.worker_concurrency == 0 {
            anyhow::bail!("worker_concurrency must be > 0");
        }
        if value.batch_size == 0 {
            anyhow::bail!("batch_size must be > 0");
        }

        let remote_url = if let Some(fullnode) = value.remote_fullnode_url {
            RemoteUrl::Fullnode(fullnode)
        } else if let Some(historical_url) = value.remote_historical_url {
            RemoteUrl::HybridHistoricalStore {
                historical_url,
                live_url: value.remote_live_url,
            }
        } else {
            default_remote_url(value.network)
        };

        Ok(Self {
            db_url: value.db_url,
            progress_file: value.progress_file,
            start_checkpoint: value.start_checkpoint,
            end_checkpoint: value.end_checkpoint,
            worker_concurrency: value.worker_concurrency,
            batch_size: value.batch_size,
            tick_interval_ms: value.tick_interval_ms,
            timeout_secs: value.timeout_secs,
            remote_url,
            task_name: "iota_pg_indexer".to_owned(),
            filters: FilterConfig {
                include_failed_txs: value.include_failed_txs,
                tx_sender: value.tx_sender,
                event_package_id: value.event_package_id,
                event_module: value.event_module,
                event_type: value.event_type,
            },
        })
    }
}

fn default_remote_url(network: Network) -> RemoteUrl {
    match network {
        Network::Mainnet => RemoteUrl::HybridHistoricalStore {
            historical_url: "https://checkpoints.mainnet.iota.cafe/ingestion/historical".into(),
            live_url: Some("https://checkpoints.mainnet.iota.cafe/ingestion/live".into()),
        },
        Network::Testnet => RemoteUrl::HybridHistoricalStore {
            historical_url: "https://checkpoints.testnet.iota.cafe/ingestion/historical".into(),
            live_url: Some("https://checkpoints.testnet.iota.cafe/ingestion/live".into()),
        },
        Network::Devnet => RemoteUrl::HybridHistoricalStore {
            historical_url: "https://checkpoints.devnet.iota.cafe/ingestion/historical".into(),
            live_url: Some("https://checkpoints.devnet.iota.cafe/ingestion/live".into()),
        },
        Network::Custom => RemoteUrl::HybridHistoricalStore {
            historical_url: "https://checkpoints.testnet.iota.cafe/ingestion/historical".into(),
            live_url: Some("https://checkpoints.testnet.iota.cafe/ingestion/live".into()),
        },
    }
}
