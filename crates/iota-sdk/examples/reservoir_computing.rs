// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Reservoir ===\n1.RC 2.Liquid-state 3.Echo-state\nCompleted!");
    Ok(())
}
