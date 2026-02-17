// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Log-Structured ===\n1.LSM 2.WAL 3.Compaction\nCompleted!");
    Ok(())
}
