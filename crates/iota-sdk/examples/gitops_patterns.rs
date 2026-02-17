// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== GitOps Patterns ===\n1.Declarative 2.Versioned 3.Automated\nCompleted!");
    Ok(())
}
