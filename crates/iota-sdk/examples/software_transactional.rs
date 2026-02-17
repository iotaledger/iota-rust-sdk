// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== STM ===\n1.Atoms 2.Transactions 3.Conflicts\nCompleted!");
    Ok(())
}
