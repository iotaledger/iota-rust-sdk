// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    crypto::{IotaSigner, SignatureError, ed25519::Ed25519PrivateKey},
    graphql_client::{Client, WaitForTx, faucet::FaucetClient},
    transaction_builder::{TransactionBuilder, TransactionSigner},
    types::{Address, Transaction, UserSignature},
};

struct AsyncSigner(Ed25519PrivateKey);

impl TransactionSigner for AsyncSigner {
    type Error = SignatureError;

    async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
        self.0.sign_transaction(transaction)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let amount = 1_000u64;
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let private_key = Ed25519PrivateKey::new([0; Ed25519PrivateKey::LENGTH]);
    let public_key = private_key.public_key();
    let sender_address = public_key.derive_address();
    println!("Sender address: {sender_address}");

    let client = Client::new_localnet();

    // Request funds from faucet
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender_address, &client)
        .await?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(&client);
    builder.send_iota(recipient_address, amount);

    let signer = AsyncSigner(private_key);
    let effects = builder.execute(&signer, WaitForTx::Finalized).await?;
    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.as_v1().status);
    println!("Effects: {effects:#?}");

    Ok(())
}
