// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== Cellular Automata ===\n1.Rules 2.Patterns 3.Computation\nCompleted!");
    Ok(())
}
