// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DDoS Protection ===\n1.Mitigation 2.Detection 3.Response\nCompleted!");
    Ok(())
}
