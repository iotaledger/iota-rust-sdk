// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: build a single transaction that batches multiple operations.
//!
//! This demonstrates the common pattern of:
//! 1. split one coin into multiple outputs,
//! 2. transfer each output to a different recipient,
//! 3. produce one atomic transaction payload.

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::{TransactionBuilder, assigned},
    types::{Address, ObjectId},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    // Source coin used for batching operations.
    let source_coin =
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?;

    // Batched transfers (recipient, amount)
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

    // Split the source coin into N parts, then transfer each part.
    let amounts: Vec<u64> = recipients.iter().map(|(_, amount)| *amount).collect();
    let labels: Vec<String> = (0..recipients.len()).map(|i| format!("batch_coin_{i}")).collect();

    builder.split_coins(source_coin, amounts).assign(labels.clone());

    for (i, (recipient, _)) in recipients.iter().enumerate() {
        builder.transfer_objects(Address::from_str(recipient)?, [assigned(&labels[i])]);
    }

    // Build one atomic transaction with all operations above.
    let tx = builder.finish().await?;

    println!("Signing Digest: {}", tx.signing_digest_hex());
    println!("Transaction Bytes (base64): {}", tx.to_base64());

    // Optional validation before signing/submitting.
    let dry_run = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run.error {
        eyre::bail!("Batched transaction dry run failed: {err}");
    }

    println!("Batched transaction dry run succeeded");
    Ok(())
}
