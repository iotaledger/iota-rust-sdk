// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk_graphql_client_next::{
    FunctionFilter, GraphQLClient, Result,
    iota_types::{Address, Identifier},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let transactions = client
        .transactions()
        .function(FunctionFilter::Function(
            Address::SYSTEM,
            Identifier::from_static("iota_system"),
            Identifier::from_static("request_add_stake"),
        ))
        .await?;

    for transaction in transactions {
        println!("Digest: {}", transaction.transaction.digest());
    }

    Ok(())
}
