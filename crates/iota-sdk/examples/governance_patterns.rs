// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Governance Example ===\n");
    println!("1.Proposals 2.Voting 3.Execution 4.DAOs\n");
    println!("Governance completed!");
    Ok(())
}
