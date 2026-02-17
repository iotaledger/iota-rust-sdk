// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Linear Algebra ===\n1.Matrices 2.Eigenvalues 3.Decomposition\nCompleted!");
    Ok(())
}
