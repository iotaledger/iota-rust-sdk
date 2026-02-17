// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Indexing Strategies ===\n1.B-tree 2.Hash 3.Bitmap\nCompleted!");
    Ok(())
}
