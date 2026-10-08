// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Query objects by their Move type, decoded into Rust mirrors.
//!
//! `decode::<T>()` filters the objects by `T`'s Move type and decodes every
//! object of the page into `T`.

use std::pin::pin;

use eyre::Result;
use futures::StreamExt;
use iota_move_types::{
    iota_framework::{coin::Coin, iota::IOTA},
    iota_system::staking_pool::StakedIota,
};
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let owner: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    // A page of `0x2::coin::Coin<0x2::iota::IOTA>`, decoded.
    let coins = client.objects().owner(owner).decode::<Coin<IOTA>>().await?;

    println!("{} IOTA coin object(s):", coins.len());
    let mut total: u64 = 0;
    for coin in coins.items() {
        total += coin.value.balance.value();
        println!(
            "  {}  v{}  {} nanos",
            coin.reference.object_id,
            coin.reference.version,
            coin.value.balance.value()
        );
    }
    println!("Total: {total} nanos");

    // The same query for a different mirror, as a stream over every page.
    println!("---");
    let mut staked = pin!(client.objects().owner(owner).decode::<StakedIota>().items());
    while let Some(stake) = staked.next().await {
        let stake = stake?;
        println!(
            "  staked {}  v{}  {} nanos, active from epoch {}",
            stake.reference.object_id,
            stake.reference.version,
            stake.value.principal(),
            stake.value.stake_activation_epoch()
        );
    }

    Ok(())
}
