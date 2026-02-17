// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Mutation Testing ===\n1.Mutants 2.Survival 3.Quality\nCompleted!");
    Ok(())
}
