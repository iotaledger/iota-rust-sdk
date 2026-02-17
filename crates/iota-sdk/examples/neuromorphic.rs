// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Neuromorphic ===\n1.SNNs 2.Neuromorphic-chips 3.Event-driven\nCompleted!");
    Ok(())
}
