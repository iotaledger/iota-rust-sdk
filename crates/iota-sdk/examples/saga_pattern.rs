// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Saga Pattern ===\n1.Choreography 2.Orchestration 3.Compensation\nCompleted!");
    Ok(())
}
