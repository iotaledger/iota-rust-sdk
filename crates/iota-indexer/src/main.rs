use clap::Parser;
use iota_indexer::{
    config::{AppConfig, Cli},
    db,
    error::AppResult,
    services::Indexer,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> AppResult<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = AppConfig::try_from(cli)?;

    let client = config.build_client()?;
    let pool = db::connect(&config.db_url).await?;
    db::init(&pool).await?;

    info!(
        db_url = %config.db_url,
        continuous = config.continuous,
        "Indexer started"
    );

    let indexer = Indexer::new(client, pool, config);
    indexer.run().await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
