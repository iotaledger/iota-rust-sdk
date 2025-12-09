// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{Client, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let chain_id = client.chain_id().await?;
    println!("Chain ID: {chain_id}");

    Ok(())
}
