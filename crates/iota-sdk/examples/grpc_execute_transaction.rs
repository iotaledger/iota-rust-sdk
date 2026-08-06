// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Build, sign, and execute a transaction over gRPC.

use eyre::Result;
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey},
    graphql_client::{Client as GraphQlClient, faucet::FaucetClient},
    grpc_client::{Client, read_mask_fields::TransactionReadMask},
    transaction_builder::TransactionBuilder,
    types::{Address, SignedTransaction},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Amount to send in nanos
    let amount = 1_000u64;
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let private_key = Ed25519PrivateKey::new([0; Ed25519PrivateKey::LENGTH]);
    let sender_address = private_key.public_key().derive_address();
    println!("Sender address: {sender_address}");

    // Request funds from faucet (the faucet client relies on GraphQL to await
    // finalization)
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender_address, &GraphQlClient::new_localnet())
        .await?;

    let client = Client::new_localnet()?;

    // Resolve gas and build the transaction via gRPC
    let mut builder = TransactionBuilder::new(sender_address).with_client(&client);
    builder.send_iota(recipient_address, amount);
    let tx = builder.finish().await?;

    let signature = private_key.sign_transaction(&tx)?;
    let signed_transaction = SignedTransaction {
        transaction: tx,
        signatures: vec![signature],
    };

    let executed = client
        .execute_transaction(signed_transaction, None, TransactionReadMask::default())
        .await?
        .into_inner();

    let effects = executed.effects()?.effects()?;
    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.as_v1().status);

    Ok(())
}
