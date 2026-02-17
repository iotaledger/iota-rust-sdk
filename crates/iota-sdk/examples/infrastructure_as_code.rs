// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== IaC ===\n1.Terraform 2.Pulumi 3.ARM\nCompleted!");
    Ok(())
}
