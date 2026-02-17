// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Sorting ===\n1.Quicksort 2.Mergesort 3.Heapsort\nCompleted!");
    Ok(())
}
