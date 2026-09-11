// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Query objects by their Move type, decoded into Rust mirrors.
//!
//! `objects` takes a type string and hands back raw objects you then decode
//! yourself (see `decode_staked_iota.rs`). `move_objects` takes the Move type
//! from its type parameter instead: the filter is derived from the mirror and
//! every object in the page arrives decoded, so neither the type string nor
//! the decode step appears here.
//!
//! Because the type comes from `T`, [`MoveObjectFilter`] has no type field —
//! there is no second place to set it and nothing to disagree about.
//!
//! A decode failure fails the whole page rather than skipping the object: the
//! query filtered on `T`'s exact type, so a failure means the on-chain type
//! has moved out from under the mirror.

use eyre::Result;
use futures::StreamExt;
use iota_sdk::{
    graphql_client::{Client, MoveObjectFilter},
    move_types::{
        iota_framework::{coin::Coin, iota::IOTA},
        iota_system::staking_pool::StakedIota,
    },
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let owner: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    // A page of `0x2::coin::Coin<0x2::iota::IOTA>`, decoded.
    let coins = client
        .move_objects::<Coin<IOTA>>(
            MoveObjectFilter::default().with_owner(owner),
            Default::default(),
        )
        .await?;

    println!("{} IOTA coin object(s):", coins.data().len());
    let mut total: u64 = 0;
    for coin in coins.data() {
        total += coin.balance.value();
        println!("  {}  {} nanos", coin.id.object_id(), coin.balance.value());
    }
    println!("Total: {total} nanos");

    // Same query for a different mirror, paginated as a stream. Only the type
    // parameter changes.
    println!("---");
    let mut staked = Box::pin(client.move_objects_stream::<StakedIota>(
        MoveObjectFilter::default().with_owner(owner),
        Default::default(),
    ));
    while let Some(stake) = staked.next().await {
        let stake = stake?;
        println!(
            "  staked {}  {} nanos, active from epoch {}",
            stake.id(),
            stake.principal(),
            stake.stake_activation_epoch()
        );
    }

    Ok(())
}
