// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    crypto::{
        IotaSigner,
        ed25519::Ed25519PrivateKey,
        multisig::MultisigAggregator,
    },
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::{
        Address,
        MultisigCommittee,
        MultisigMember,
        MultisigMemberPublicKey,
        UserSignature,
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    // Recipient for demo transfer (amount is in nanos).
    let amount = 1_000u64;
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // Demo keys. Do not use fixed keys like this in production.
    let key_1 = Ed25519PrivateKey::new([1; Ed25519PrivateKey::LENGTH]);
    let key_2 = Ed25519PrivateKey::new([2; Ed25519PrivateKey::LENGTH]);

    // 2-of-2 multisig committee (weight 1 each, threshold 2).
    let members = vec![
        MultisigMember::new(MultisigMemberPublicKey::Ed25519(key_1.public_key()), 1),
        MultisigMember::new(MultisigMemberPublicKey::Ed25519(key_2.public_key()), 1),
    ];
    let committee = MultisigCommittee::new(members, 2);
    let multisig_address = committee.derive_address();
    println!("Multisig address: {multisig_address}");

    let client = Client::new_localnet();

    // Fund the multisig address.
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(multisig_address, &client)
        .await?;

    // Build a transaction from the multisig address.
    let mut builder = TransactionBuilder::new(multisig_address).with_client(&client);
    builder.send_iota(recipient_address, amount);
    let tx = builder.finish().await?;

    let dry_run_result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run_result.error {
        eyre::bail!("Dry run failed: {err}");
    }

    // Each committee member signs the transaction, then the signatures are aggregated.
    let sig_1 = key_1.sign_transaction(&tx)?;
    let sig_2 = key_2.sign_transaction(&tx)?;

    let mut aggregator = MultisigAggregator::new_with_transaction(committee, &tx);
    aggregator.add_signature(sig_1)?;
    aggregator.add_signature(sig_2)?;
    let multisig_signature = aggregator.finish()?;

    let effects = client
        .execute_tx(&[UserSignature::Multisig(multisig_signature)], &tx, None)
        .await?;

    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.status());
    println!("Effects: {effects:#?}");

    Ok(())
}

