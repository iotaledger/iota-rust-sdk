// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{
    Client,
    error::Result,
    pagination::{Direction, PaginationFilter},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();
    let address = "0xb14f13f5343641e5b52d144fd6f106a7058efe2f1ad44598df5cda73acf0101f".parse()?;
    let (_, coins) = client
        .coins(
            address,
            None,
            PaginationFilter {
                direction: Direction::Forward,
                ..Default::default()
            },
        )
        .await?
        .into_parts();

    for coin in &coins {
        println!("Coin = {}, Balance = {}", coin.id(), coin.balance());
    }

    let balance = client.balance(address, None).await?.unwrap_or_default();
    println!("Total balance = {balance}");

    Ok(())
}
