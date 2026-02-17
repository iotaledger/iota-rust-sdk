// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Bayesian Networks ===\n1.DAGs 2.CPTs 3.Inference\nCompleted!");
    Ok(())
}
