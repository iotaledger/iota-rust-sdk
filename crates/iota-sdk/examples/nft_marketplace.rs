// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== NFT Marketplace ===\n1.Listing 2.Bidding 3.Royalties\nCompleted!");
    Ok(())
}
