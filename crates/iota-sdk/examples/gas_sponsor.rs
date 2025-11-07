// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let sponsor_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(&client);
    let tx = builder
        .move_call(Address::STD_LIB, "u8", "max")
        .arguments((0u8, 1u8))
        .sponsor(sponsor_address)
        .to_owned()
        .finish()
        .await?;

    println!("Signing Digest: {}", tx.signing_digest_hex());
    println!("Tx Bytes: {}", tx.to_base64());

    let res = client.dry_run_tx(&tx, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send gas sponsor tx: {err}");
    }

    println!("Gas sponsor tx dry run was successful!");

    Ok(())
}
