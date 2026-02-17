// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Divide & Conquer ===\n1.Split 2.Recurrence 3.Combination\nCompleted!");
    Ok(())
}
