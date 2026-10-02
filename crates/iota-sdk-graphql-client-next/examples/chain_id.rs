// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk_graphql_client_next::{GraphQLClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let chain_id = client.chain_id().await?;
    println!("Chain ID: {chain_id}");

    Ok(())
}
