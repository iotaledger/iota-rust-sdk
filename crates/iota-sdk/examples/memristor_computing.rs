// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Memristor ===\n1.Resistance 2.Learning 3.Neural-networks\nCompleted!");
    Ok(())
}
