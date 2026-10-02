// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;
    let address: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    for coin in client.coins(address).await? {
        println!(
            "Coin = {}, Coin Type = {}, Balance = {}",
            coin.id(),
            coin.coin_type().as_struct_tag(),
            coin.balance()
        );
    }

    let balance = client.balance(address).await?;
    println!(
        "Total balance = {} in {} coin(s)",
        balance.total_balance, balance.coin_object_count
    );

    for balance in client.balances(address).await? {
        println!("{} = {}", balance.coin_type, balance.total_balance);
    }

    Ok(())
}
