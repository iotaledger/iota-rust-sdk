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

    let coin =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;

    let sender =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    // Recipients and amounts
    let recipients = [
        (
            "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
            1_000_000_000u64,
        ),
        (
            "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
            2_000_000_000u64,
        ),
    ];

    let mut builder = TransactionBuilder::new(sender).with_client(&client);

    // Extract amounts from recipients
    let amounts: Vec<u64> = recipients.iter().map(|(_, amt)| *amt).collect();

    let labels: Vec<String> = (0..recipients.len()).map(|i| format!("coin{i}")).collect();

    builder.split_coins(coin, amounts).name(labels.clone());

    // Transfer each split coin to the corresponding recipient
    for (i, (address, _)) in recipients.iter().enumerate() {
        builder.transfer_objects(Address::from_str(address)?, [res(&labels[i])]);
    }

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send IOTA: {err}");
    }

    println!("Send IOTA dry run was successful!");

    Ok(())
}
