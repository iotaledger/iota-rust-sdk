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

    let from_address =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // This is a coin of type
    // 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
    let coin =
        ObjectId::from_str("0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2")?;

    let mut builder = client.transaction_builder(from_address);

    builder.send_coins([coin], to_address, 50000000000u64);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send coins: {err}");
    }

    println!("Send coins dry run was successful!");

    Ok(())
}
