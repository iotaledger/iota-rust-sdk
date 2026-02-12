// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    crypto::{IotaSigner, ed25519::Ed25519PrivateKey, multisig::MultisigAggregator},
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::{Address, MultisigCommittee, MultisigMember, MultisigMemberPublicKey, UserSignature},
};

#[tokio::main]
async fn main() -> Result<()> {
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let signer_1 = Ed25519PrivateKey::new([0; Ed25519PrivateKey::LENGTH]);
    let signer_2 = Ed25519PrivateKey::new([1; Ed25519PrivateKey::LENGTH]);

    let committee = MultisigCommittee::new(
        vec![
            MultisigMember::new(MultisigMemberPublicKey::Ed25519(signer_1.public_key()), 1),
            MultisigMember::new(MultisigMemberPublicKey::Ed25519(signer_2.public_key()), 1),
        ],
        2,
    );

    if !committee.is_valid() {
        eyre::bail!("multisig committee is invalid")
    }

    let multisig_address = committee.derive_address();
    println!("Multisig sender address: {multisig_address}");

    let client = Client::new_localnet();

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(multisig_address, &client)
        .await?;

    let mut builder = TransactionBuilder::new(multisig_address).with_client(&client);
    builder.send_iota(recipient_address, 1_000);
    let tx = builder.finish().await?;

    let dry_run_result = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run_result.error {
        eyre::bail!("Dry run failed: {err}");
    }

    let sig_1 = signer_1.sign_transaction(&tx)?;
    let sig_2 = signer_2.sign_transaction(&tx)?;

    let mut aggregator = MultisigAggregator::new_with_transaction(committee, &tx);
    aggregator.add_signature(sig_1)?;
    aggregator.add_signature(sig_2)?;

    let multisig_signature = UserSignature::Multisig(aggregator.finish()?);
    let effects = client.execute_tx(&[multisig_signature], &tx, None).await?;

    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.status());
    println!("Effects: {effects:#?}");

    Ok(())
}
