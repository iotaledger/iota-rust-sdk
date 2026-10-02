// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk_graphql_client_next::GraphQLClient;

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let latest = client.transactions().last(1).await?;
    let digest = latest
        .items()
        .first()
        .ok_or_eyre("no transactions found")?
        .transaction
        .digest();

    let signed_transaction = client
        .transaction(digest)
        .await?
        .ok_or_eyre("tx not found")?;
    println!("Signed Transaction: {signed_transaction:#?}\n");

    let transaction_effects = client
        .transaction(digest)
        .effects()
        .await?
        .ok_or_eyre("tx not found")?;
    println!("Transaction Effects: {transaction_effects:#?}\n");

    let executed_transaction = client
        .transaction(digest)
        .with_effects()
        .await?
        .ok_or_eyre("tx not found")?;
    println!("Transaction with Effects: {executed_transaction:#?}");

    Ok(())
}
