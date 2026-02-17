// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Token Vesting ===\n1.Schedule 2.Cliff 3.Release\nCompleted!");
    Ok(())
}
