// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let from_address =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(from_address, &client)
        .await?;

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);

    builder.send_iota(to_address, 5000000000u64);

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
