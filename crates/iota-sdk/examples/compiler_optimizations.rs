// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Compiler Opts ===\n1.Inlining 2.Vectorization 3.Loop-unrolling\nCompleted!");
    Ok(())
}
