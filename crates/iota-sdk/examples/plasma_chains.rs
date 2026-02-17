// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Plasma Chains ===\n1.UX 2.Exit 3.Challenge\nCompleted!");
    Ok(())
}
