// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let coin_0 =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;
    let coin_1 =
        ObjectId::from_str("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")?;

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
