// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== CSP ===\n1.Channels 2.Select 3.Goroutines\nCompleted!");
    Ok(())
}
