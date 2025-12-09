// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_graphql_client::{Client, faucet::FaucetClient};
use iota_transaction_builder::TransactionBuilder;
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    // Amount to send in nanos
    let amount = 1_000u64;
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let private_key = Ed25519PrivateKey::new([0; Ed25519PrivateKey::LENGTH]);
    let public_key = private_key.public_key();
    let sender_address = public_key.derive_address();
    println!("Sender address: {sender_address}");

    // Request funds from faucet
    FaucetClient::new_localnet()
        .request_and_wait(sender_address)
        .await?;

    let client = Client::new_localnet();

    let mut builder = TransactionBuilder::new(sender_address).with_client(&client);
    builder.send_iota(recipient_address, amount);
    let tx = builder.finish().await?;

    let dry_run_result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run_result.error {
        eyre::bail!("Dry run failed: {err}");
    }

    let signature = private_key.sign_transaction(&tx)?;

    let effects = client.execute_tx(&[signature], &tx, None).await?;

    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.status());
    println!("Effects: {effects:#?}");

    Ok(())
}
