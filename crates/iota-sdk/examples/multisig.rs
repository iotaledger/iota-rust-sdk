// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! 2-of-3 Ed25519 multisig example.
//!
//! Derives 3 keypairs from a mnemonic at indices 0, 1, 2, creates a multisig
//! committee with threshold 2, funds the multisig address via faucet, builds
//! a `send_iota` transaction, signs with only 2 of the 3 keys, aggregates,
//! and executes.
//!
//! Requires a running localnet (`iota start --force-regenesis`).

use eyre::Result;
use iota_sdk::{
    crypto::{FromMnemonic, IotaSigner, ed25519::Ed25519PrivateKey, multisig::MultisigAggregator},
    graphql_client::{Client, faucet::FaucetClient},
    types::{Address, MultisigCommittee, MultisigMember, PublicKey, UserSignature},
};

const MNEMONIC: &str = "round attack kitchen wink winter music trip tiny nephew hire orange what";

#[tokio::main]
async fn main() -> Result<()> {
    let amount = 1_000u64;
    let recipient =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // 1. Derive 3 Ed25519 keypairs from mnemonic at indices 0, 1, 2
    let key0 = Ed25519PrivateKey::from_mnemonic(MNEMONIC, 0, None)?;
    let key1 = Ed25519PrivateKey::from_mnemonic(MNEMONIC, 1, None)?;
    let key2 = Ed25519PrivateKey::from_mnemonic(MNEMONIC, 2, None)?;

    // 2. Build multisig committee: threshold=2, each member weight=1
    let members = vec![
        MultisigMember::new(PublicKey::Ed25519(key0.public_key()), 1),
        MultisigMember::new(PublicKey::Ed25519(key1.public_key()), 1),
        MultisigMember::new(PublicKey::Ed25519(key2.public_key()), 1),
    ];
    let committee = MultisigCommittee::new(members, 2)?;

    // 3. Derive the multisig address
    let multisig_address = committee.derive_address();
    println!("Multisig address: {multisig_address}");

    let client = Client::new_localnet();

    // 4. Fund the multisig address
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(multisig_address, &client)
        .await?;

    // 5. Build a send_iota transaction
    let mut builder = client.transaction_builder(multisig_address);
    builder.send_iota(recipient, amount);
    let tx = builder.finish().await?;

    let dry_run = client.dry_run_transaction(&tx, false).await?;
    if let Some(err) = dry_run.error {
        eyre::bail!("Dry run failed: {err}");
    }

    // 6. Sign with key0 and key1 (2-of-3 threshold)
    let sig0 = key0.sign_transaction(&tx)?;
    let sig1 = key1.sign_transaction(&tx)?;

    // 7. Aggregate signatures
    let mut aggregator = MultisigAggregator::new_with_transaction(committee, &tx);
    aggregator.add_signature(sig0)?;
    aggregator.add_signature(sig1)?;
    let multisig_sig = aggregator.finish()?;

    // 8. Execute
    let user_sig = UserSignature::Multisig(multisig_sig);
    let effects = client.execute_transaction(&[user_sig], &tx, None).await?;
    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.as_v1().status);
    println!("Effects: {effects:#?}");

    Ok(())
}
