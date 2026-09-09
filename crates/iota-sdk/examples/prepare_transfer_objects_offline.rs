// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey,
    graphql_client::{Client, faucet::FaucetClient, query_types::ObjectFilter},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let private_key = Ed25519PrivateKey::random();
    let from_address = private_key.public_key().derive_address();
    let to_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(from_address, &client)
        .await?;

    let coins = client
        .objects(
            ObjectFilter::default().with_owner(from_address),
            Default::default(),
        )
        .await?
        .data;
    let (gas_coin, to_transfer) = coins.split_first().ok_or_eyre("no coins found")?;
    let gas_coin = gas_coin.object_ref();
    let objs_to_transfer = to_transfer
        .iter()
        .map(|obj| obj.object_ref())
        .collect::<Vec<_>>();
    let gas_price = client.reference_gas_price(None).await?.unwrap_or(100);

    let mut builder = TransactionBuilder::new(from_address);

    builder
        .transfer_objects(to_address, objs_to_transfer)
        .gas([gas_coin])
        .gas_price(gas_price)
        .gas_budget(500000000);

    let txn = builder.finish()?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_transaction(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to transfer objects: {err}");
    }

    println!("Transfer objects dry run was successful!");

    Ok(())
}
