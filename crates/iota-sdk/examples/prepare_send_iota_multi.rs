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

    let coin =
        ObjectId::from_str("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")?;

    let sender =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;

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

    let mut builder = client.transaction_builder(sender);

    // Extract amounts from recipients
    let amounts: Vec<u64> = recipients.iter().map(|(_, amt)| *amt).collect();

    let labels: Vec<String> = (0..recipients.len()).map(|i| format!("coin{i}")).collect();

    builder.split_coins(coin, amounts).assign(labels.clone());

    // Transfer each split coin to the corresponding recipient
    for (i, (address, _)) in recipients.iter().enumerate() {
        builder.transfer_objects(Address::from_str(address)?, [assigned(&labels[i])]);
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
