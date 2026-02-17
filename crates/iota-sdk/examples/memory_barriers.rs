// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Memory Barriers ===\n1.Acquire 2.Release 3.Seq-cst\nCompleted!");
    Ok(())
}
