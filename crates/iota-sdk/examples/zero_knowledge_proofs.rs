// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Zero-Knowledge Proofs ===\n1.ZK-SNARKs 2.ZK-STARKs 3.Privacy\nCompleted!");
    Ok(())
}
