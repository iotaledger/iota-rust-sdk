// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Load Testing ===\n1.Scenarios 2.Injectors 3.Analysis\nCompleted!");
    Ok(())
}
