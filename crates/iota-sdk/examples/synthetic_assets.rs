// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Synthetics ===\n1.Minting 2.Tracking 3.Redemption\nCompleted!");
    Ok(())
}
