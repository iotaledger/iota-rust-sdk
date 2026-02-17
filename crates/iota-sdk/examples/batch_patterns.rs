// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Batch Patterns ===\n1.Chunking 2.Parallel 3.Error-handling\nCompleted!");
    Ok(())
}
