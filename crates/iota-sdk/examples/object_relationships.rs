// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Object Relationships Example ===\n");
    println!("1. Parent-Child: Objects own other objects");
    println!("2. Dynamic Fields: Attach data to objects");
    println!("3. Shared References: Multiple access patterns");
    println!("4. Wrapping: Type composition");
    println!("5. Best: Design clear hierarchies\n");
    println!("Object relationships completed!");
    Ok(())
}
