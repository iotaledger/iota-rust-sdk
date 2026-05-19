// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient, query_types::ObjectFilter},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let from_address =
        Address::from_str("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    // Prefetch object refs and gas price online so the rest of the example can
    // be assembled offline.
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(from_address, &client)
        .await?;
    let owned = client
        .objects(
            ObjectFilter {
                owner: Some(from_address),
                type_: Some("0x2::coin::Coin<0x2::iota::IOTA>".to_owned()),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;
    let mut obj_iter = owned.data.iter();
    let gas_coin = obj_iter
        .next()
        .ok_or_eyre("sender has no coins")?
        .object_ref();
    let objs_to_transfer: Vec<_> = obj_iter.take(3).map(|o| o.object_ref()).collect();
    if objs_to_transfer.len() < 3 {
        eyre::bail!("sender does not own at least 4 coins (1 for gas + 3 to transfer)");
    }
    let gas_price = client.reference_gas_price(None).await?.unwrap_or(100);

    // From here on, no further network calls are made; the transaction is
    // assembled entirely from the prefetched object refs.
    let mut builder = TransactionBuilder::new(from_address);

    builder
        .transfer_objects(to_address, objs_to_transfer)
        .gas([gas_coin])
        .gas_price(gas_price)
        .gas_budget(500000000);

    let txn = builder.finish()?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to transfer objects: {err}");
    }

    println!("Transfer objects dry run was successful!");

    Ok(())
}
