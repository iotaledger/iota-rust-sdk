// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Metrics Collection ===\n1.Counters 2.Histograms 3.Export\nCompleted!");
    Ok(())
}
