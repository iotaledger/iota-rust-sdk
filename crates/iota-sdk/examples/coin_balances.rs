// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::GraphQLResult};

#[tokio::main]
async fn main() -> GraphQLResult<()> {
    let client = Client::new_testnet();
    let address = "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    for coin in client
        .coins(address, None, Default::default())
        .await?
        .data()
    {
        println!(
            "Coin = {}, Coin Type = {}, Balance = {}",
            coin.id(),
            coin.coin_type().as_struct_tag(),
            coin.balance()
        );
    }

    let balance = client.balance(address, None).await?.unwrap_or_default();
    println!("Total balance = {balance}");

    Ok(())
}
