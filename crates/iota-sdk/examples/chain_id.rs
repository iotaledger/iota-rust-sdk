// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::GraphQLResult};

#[tokio::main]
async fn main() -> GraphQLResult<()> {
    let client = Client::new_testnet();

    let chain_id = client.chain_id().await?;
    println!("Chain ID: {chain_id}");

    Ok(())
}
