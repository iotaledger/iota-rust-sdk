// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use base64ct::Encoding;
use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let from_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let coin =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;

    let mut builder = TransactionBuilder::new(from_address).with_client(client.clone());

    builder.split_coins(coin, [1000, 2000, 3000]);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", hex::encode(txn.signing_digest()));
    println!(
        "Txn Bytes: {}",
        base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?)
    );

    let res = client.dry_run_tx(&txn, true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to split coin: {err}");
    }

    println!("Split coin dry run was successful!");

    Ok(())
}
