// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;
use eyre::{Result, bail};
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender = "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c".parse()?;
    let recipient = "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900".parse()?;

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    builder.send_iota(recipient, 1_000_000_000);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", hex::encode(txn.signing_digest()));
    println!(
        "Txn Bytes: {}",
        base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?)
    );

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        bail!("Dry run failed: {err}");
    }

    println!("Dry run successful!");

    Ok(())
}
