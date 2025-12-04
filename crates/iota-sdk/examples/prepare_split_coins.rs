// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::{TransactionBuilder, res};
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let coin =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;

    let mut builder = TransactionBuilder::new(sender).with_client(&client);

    builder
        .split_coins(coin, [1000u64, 2000, 3000])
        .name(("coin1", "coin2", "coin3"))
        .transfer_objects(sender, (res("coin1"), res("coin2"), res("coin3")));

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
