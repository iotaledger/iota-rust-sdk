// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use iota_sdk::graphql_client::Client;
use polling_indexer::{cli::Cli, config::AppConfig, db, indexer::Indexer};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = AppConfig::try_from(cli)?;

    let client = Client::new(&config.graphql_url)?;
    let pool = db::connect(&config.db_url).await?;
    db::init(&pool).await?;

    info!(graphql_url = %config.graphql_url, "starting indexer");
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
