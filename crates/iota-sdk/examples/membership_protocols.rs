// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Membership ===\n1.SWIM 2.Failure-detectors 3.Gossip\nCompleted!");
    Ok(())
}
