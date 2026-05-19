// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::{TransactionBuilder, assigned},
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

    let coin = *client
        .coins(sender, None, Default::default())
        .await?
        .data()
        .first()
        .ok_or_eyre("sender has no coins")?
        .id();

    let mut builder = TransactionBuilder::new(sender).with_client(&client);

    builder
        .split_coins(coin, [1000u64, 2000, 3000])
        .assign(("coin1", "coin2", "coin3"))
        .transfer_objects(
            sender,
            (assigned("coin1"), assigned("coin2"), assigned("coin3")),
        );

    let txn = builder.clone().finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to split coin: {err}");
    }

    println!("Split coin dry run was successful!");

    Ok(())
}
