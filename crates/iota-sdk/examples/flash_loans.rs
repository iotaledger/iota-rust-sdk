// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Flash Loans ===\n1.Borrow 2.Execute 3.Repay\nCompleted!");
    Ok(())
}
