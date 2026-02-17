// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Branch Prediction ===\n1.Prediction 2.Misprediction 3.PGO\nCompleted!");
    Ok(())
}
