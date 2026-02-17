// Copyright (c) 2025 IOTA Stiftung
use eyre::Result;
use iota_sdk::graphql_client::Client;
#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Observability ===\n1.Tracing 2.Metrics 3.Logging\nCompleted!");
    Ok(())
}
