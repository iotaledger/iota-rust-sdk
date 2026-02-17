// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Clean Architecture ===\n1.Entities 2.Use-cases 3.Frameworks\nCompleted!");
    Ok(())
}
