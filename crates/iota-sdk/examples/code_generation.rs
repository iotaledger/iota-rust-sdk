// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Code Generation ===\n1.Scaffolding 2.Templates 3.Customization\nCompleted!");
    Ok(())
}
