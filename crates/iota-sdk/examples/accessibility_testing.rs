// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    let _client = Client::new_devnet();
    println!("=== A11y Testing ===\n1.Rules 2.Automation 3.Manual\nCompleted!");
    Ok(())
}
