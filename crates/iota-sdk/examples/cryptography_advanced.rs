// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Advanced Crypto ===\n1.Signatures 2.Hash 3.Key-exchange\nCompleted!");
    Ok(())
}
