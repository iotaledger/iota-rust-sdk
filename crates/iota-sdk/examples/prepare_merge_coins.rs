// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    types::{Address, ObjectId},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let sender =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    let coin_0 =
        ObjectId::from_str("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;
    let coin_1 =
        ObjectId::from_str("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")?;

    let mut builder = client.transaction_builder(sender);

    builder.merge_coins(coin_0, [coin_1]);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_transaction(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to merge coin: {err}");
    }

    println!("Merge coin dry run was successful!");

    Ok(())
}
