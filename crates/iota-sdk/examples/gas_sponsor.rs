// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{graphql_client::Client, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let sender_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let sponsor_address =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;

    let mut builder = client.transaction_builder(sender_address);
    let tx = builder
        .move_call(Address::STD, "u8", "max")
        .arguments((0u8, 1u8))
        .sponsor(sponsor_address)
        .to_owned()
        .finish()
        .await?;

    println!("Signing Digest: {}", tx.signing_digest_hex());
    println!("Tx Bytes: {}", tx.to_base64());

    let res = client.dry_run_transaction(&tx, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send gas sponsor tx: {err}");
    }

    println!("Gas sponsor tx dry run was successful!");

    Ok(())
}
