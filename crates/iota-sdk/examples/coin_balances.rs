// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::graphql_client::{Client, faucet::FaucetClient};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let address = "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522".parse()?;
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(address, &client)
        .await?;

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
