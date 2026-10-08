// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Build, dry run, sign and execute a transfer on a local network, then wait
//! until it is finalized.
//!
//! The sender needs funds first, e.g. from `iota client faucet`.

use eyre::Result;
use iota_crypto::{IotaSigner, ed25519::Ed25519PrivateKey};
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Address};
use iota_transaction_builder::TransactionBuilder;

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

    let client = GraphQLClient::localnet()?;

    let balance = client.balance(sender_address).await?;
    if balance.total_balance == 0 {
        eyre::bail!("fund {sender_address} first, e.g. with `iota client faucet`");
    }

    let mut builder = TransactionBuilder::new(sender_address).with_client(client.clone());
    builder.send_iota(recipient_address, amount);
    let tx = builder.finish().await?;

    let dry_run_result = client.dry_run(&tx).await?;
    if let Some(err) = dry_run_result.error {
        eyre::bail!("Dry run failed: {err}");
    }

    let sig = private_key.sign_transaction(&tx)?;
    let effects = client.execute(&tx, &[sig]).await?;
    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.as_v1().status);

    client.wait_for_transaction(tx.digest()).await?;
    println!("Finalized");

    Ok(())
}
