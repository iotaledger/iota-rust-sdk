// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::Result;
use base64ct::Encoding;
use iota_graphql_client::Client;
use iota_transaction_builder::{TransactionBuilder, res};
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let gas_coin =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;

    let sender_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(client.clone());

    builder
        .split_coins(gas_coin, [1_000_000_000, 2_000_000_000], ("coin1", "coin2"))
        .transfer_objects(
            Address::from_str(
                "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
            )?,
            res("coin1"),
        )
        .transfer_objects(
            Address::from_str(
                "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
            )?,
            res("coin2"),
        )
        .gas(gas_coin)
        .gas_budget(1000000000);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", hex::encode(txn.signing_digest()));
    println!(
        "Txn Bytes: {}",
        base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?)
    );

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to send IOTA: {err}");
    }

    println!("Send IOTA dry run was successful!");

    Ok(())
}
