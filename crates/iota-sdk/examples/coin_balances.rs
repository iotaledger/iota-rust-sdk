// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{Client, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();
    let address = "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f".parse()?;

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
