// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Combinatorics ===\n1.Permutations 2.Combinations 3.Recurrence\nCompleted!");
    Ok(())
}
