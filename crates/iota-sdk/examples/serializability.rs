// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Serializability ===\n1.Isolation 2.Conflict 3.Schedules\nCompleted!");
    Ok(())
}
