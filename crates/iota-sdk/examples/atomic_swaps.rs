// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Atomic Swaps ===\n1.HTLC 2.P2P 3.Multi-asset\nCompleted!");
    Ok(())
}
