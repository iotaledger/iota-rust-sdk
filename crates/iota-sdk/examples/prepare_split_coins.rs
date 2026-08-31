// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::assigned,
    types::{Address, ObjectId},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let sender =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    let coin =
        ObjectId::from_str("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;

    let mut builder = client.transaction_builder(sender);

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
