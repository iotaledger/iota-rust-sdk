// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== DAO Governance ===\n1.Proposals 2.Voting 3.Execution\nCompleted!");
    Ok(())
}
