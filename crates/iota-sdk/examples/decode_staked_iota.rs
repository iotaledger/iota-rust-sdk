// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Fetch `StakedIota` objects as typed Rust structs using
//! `iota-sdk-move-types`.
//!
//! The GraphQL client returns each object's `contents` as a raw BCS byte
//! buffer. Without a Rust mirror of the Move type you would have to walk
//! those bytes by hand — 32 bytes for the `UID`, 32 bytes for the pool's
//! `ID`, 8 little-endian bytes for the activation epoch, 8 more for the
//! principal — and you'd be on the hook for keeping that decoder in sync
//! with every Move-side change.
//!
//! `move_objects` takes the Move type from its type parameter: it derives the
//! type filter from `StakedIota` and decodes the page, so neither the type
//! string nor the decode step appears here. That leaves typed, named-field
//! access:
//!
//! - `staked.id()` — the staked object's [`ObjectId`]
//! - `staked.pool_id()` — the staking pool the stake belongs to
//! - `staked.stake_activation_epoch()` — the epoch the stake activates at
//! - `staked.principal()` — the staked amount in nanos
//!
//! [`ObjectId`]: iota_types::ObjectId

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, MoveObjectFilter},
    move_types::iota_system::staking_pool::StakedIota,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let owner: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    let page = client
        .move_objects::<StakedIota>(
            MoveObjectFilter::default().with_owner(owner),
            Default::default(),
        )
        .await?;

    if page.data().is_empty() {
        println!("No StakedIota objects owned by {owner} right now.");
        return Ok(());
    }

    println!("Decoded {} StakedIota object(s):\n", page.data().len());

    let mut total_principal: u64 = 0;
    for staked in page.data() {
        total_principal += staked.principal();

        println!("- id:               {}", staked.id());
        println!("  pool_id:          {}", staked.pool_id());
        println!(
            "  stake_activation_epoch: {}",
            staked.stake_activation_epoch()
        );
        println!("  principal (nanos): {}", staked.principal());
        println!();
    }

    println!("Total principal across page: {total_principal} nanos");
    Ok(())
}
