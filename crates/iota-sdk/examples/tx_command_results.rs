// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::{TransactionBuilder, assigned, unresolved::Argument},
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let private_key = Ed25519PrivateKey::random();
    let sender_address = private_key.public_key().derive_address();

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender_address, &client)
        .await?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(client.clone());
    builder
        .move_call(Address::STD, "u64", "max")
        .arguments((0u64, 1000u64))
        // Assign a name to the result of this command
        .assign("res0");
    builder
        .move_call(Address::STD, "u64", "max")
        .arguments((1000u64, 2000u64))
        .assign("res1");

    builder
        // Use the assigned results of previous commands to use as arguments
        .split_coins(Argument::Gas, [assigned("res0"), assigned("res1")])
        // For nested results, a tuple or vec can be used to name them
        .assign(vec!["coin0", "coin1"]);

    // Use assigned results as arguments
    builder.transfer_objects(sender_address, [assigned("coin0"), assigned("coin1")]);

    let tx = builder.finish().await?;

    println!("Signing Digest: {}", tx.signing_digest_hex());
    println!("Txn Bytes: {}", tx.to_base64());

    let res = client.dry_run_transaction(&tx, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send tx: {err}");
    }

    println!("Tx dry run was successful!");

    Ok(())
}
