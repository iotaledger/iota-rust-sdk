use std::path::PathBuf;

use clap::Parser;
use iota_data_ingestion_core::{
    DataIngestionMetrics, FileProgressStore, IndexerExecutor, IngestionLimit, ReaderOptions,
    WorkerPool, reader::v2::CheckpointReaderConfig,
};
use iota_indexer::{config::AppConfig, db, worker::DbWorker};
use prometheus::Registry;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = iota_indexer::config::Cli::parse();
    let config = AppConfig::try_from(cli)?;

    let pool = db::connect(&config.db_url).await?;
    db::init(&pool).await?;

    let worker = DbWorker::new(pool, config.filters.clone());
    let worker_pool = WorkerPool::new(
        worker,
        config.task_name.clone(),
        config.worker_concurrency,
        Default::default(),
    );

    let progress_store = FileProgressStore::new(config.progress_file.clone()).await?;
    let metrics = DataIngestionMetrics::new(&Registry::new());

    let mut executor = IndexerExecutor::new(progress_store, 1, metrics, CancellationToken::new());
    executor.register(worker_pool).await?;

    if let Some(start_checkpoint) = config.start_checkpoint {
        let current = executor.read_watermark(config.task_name.clone()).await?;
        let target = start_checkpoint.saturating_sub(1);
        if target > current {
            executor
                .update_watermark(config.task_name.clone(), target)
                .await?;
        }
    }

    if let Some(end_checkpoint) = config.end_checkpoint {
        executor.with_ingestion_limit(IngestionLimit::MaxCheckpoint(end_checkpoint));
    }

    let reader_config = CheckpointReaderConfig {
        ingestion_path: Some(PathBuf::from("./chk")),
        remote_store_url: Some(config.remote_url.clone()),
        reader_options: ReaderOptions {
            tick_interval_ms: config.tick_interval_ms,
            timeout_secs: config.timeout_secs,
            batch_size: config.batch_size,
            data_limit: 0,
        },
    };

    info!(
        db_url = %config.db_url,
        progress_file = %config.progress_file,
        task = %config.task_name,
        "Starting ingestion executor"
    );

    executor.run_with_config(reader_config).await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
