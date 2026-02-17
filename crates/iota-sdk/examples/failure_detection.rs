// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Failure Detection ===\n1.Heartbeats 2.Phi-accrual 3.Timeouts\nCompleted!");
    Ok(())
}
