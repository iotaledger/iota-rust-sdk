// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Database Internals ===\n1.B-trees 2.LSM 3.Buffers\nCompleted!");
    Ok(())
}
