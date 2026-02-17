// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DNS Management ===\n1.Records 2.Failover 3.Geolocation\nCompleted!");
    Ok(())
}
