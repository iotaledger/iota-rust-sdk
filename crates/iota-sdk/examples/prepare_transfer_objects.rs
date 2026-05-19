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

    let from_address =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(from_address, &client)
        .await?;

    let coins = client.coins(from_address, None, Default::default()).await?;
    let objs_to_transfer: [_; 3] = coins
        .data()
        .iter()
        .map(|c| *c.id())
        .take(3)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| eyre!("sender does not own at least 3 coin objects to transfer"))?;

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);

    builder.transfer_objects(to_address, objs_to_transfer);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to transfer objects: {err}");
    }

    println!("Transfer objects dry run was successful!");

    Ok(())
}
