// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Hexagonal Arch ===\n1.Ports 2.Adapters 3.Domain\nCompleted!");
    Ok(())
}
