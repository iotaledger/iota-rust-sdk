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

    let sender_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let sponsor_address =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sponsor_address, &client)
        .await?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(&client);
    let tx = builder
        .move_call(Address::STD, "u8", "max")
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
