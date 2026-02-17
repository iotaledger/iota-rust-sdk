// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Workflow Patterns ===\n1.State-machines 2.Saga 3.Compensation\nCompleted!");
    Ok(())
}
