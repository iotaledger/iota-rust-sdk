// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{Result, eyre};
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let sender =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender, &client)
        .await?;

    let coins = client.coins(sender, None, Default::default()).await?;
    let mut coin_ids = coins.data().iter().map(|c| *c.id());
    let coin_0 = coin_ids
        .next()
        .ok_or_else(|| eyre!("sender has no coins to merge"))?;
    let coin_1 = coin_ids
        .next()
        .ok_or_else(|| eyre!("sender has only one coin, need two to merge"))?;

    let mut builder = TransactionBuilder::new(sender).with_client(&client);

    builder.merge_coins(coin_0, [coin_1]);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to merge coin: {err}");
    }

    println!("Merge coin dry run was successful!");

    Ok(())
}
