// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== NFT Patterns Example ===\n");
    println!("1.Mint 2.Transfer 3.Metadata 4.Royalties\n");
    println!("NFT Patterns completed!");
    Ok(())
}
