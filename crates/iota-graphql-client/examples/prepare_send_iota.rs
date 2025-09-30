// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use base64ct::Encoding;
use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::{TransactionBuilder, unresolved::Input};
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let from_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let coin = client
        .object(
            ObjectId::from_str(
                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699",
            )?,
            None,
        )
        .await?
        .expect("missing object");
    let gas_coin = client
        .object(
            ObjectId::from_str(
                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
            )?,
            None,
        )
        .await?
        .expect("missing gas coin");

    let mut builder = TransactionBuilder::new();

    let coin = builder.input(Input::from(&coin).with_owned_kind());
    let to_address_arg = builder.input(Input::pure(&to_address)?);

    builder.transfer_objects(vec![coin], to_address_arg);
    builder.set_sender(from_address);
    builder.set_gas_budget(50000000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .expect("missing ref gas price"),
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);
    let txn = builder.finish()?;

    println!("Signing Digest: {}", hex::encode(txn.signing_digest()));
    println!(
        "Txn Bytes: {}",
        base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?)
    );

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send IOTA: {err}");
    }

    println!("Send IOTA dry run was successful!");

    Ok(())
}
