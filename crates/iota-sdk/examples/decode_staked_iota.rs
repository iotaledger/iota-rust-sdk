// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Decode `StakedIota` objects into typed Rust structs using
//! `iota-sdk-move-system-types`.
//!
//! The GraphQL client returns each object's `contents` as a raw BCS byte
//! buffer. Without a Rust mirror of the Move type you would have to walk
//! those bytes by hand — 32 bytes for the `UID`, 32 bytes for the pool's
//! `ID`, 8 little-endian bytes for the activation epoch, 8 more for the
//! principal — and you'd be on the hook for keeping that decoder in sync
//! with every Move-side change.
//!
//! With the move-system-types crate, a single `bcs::from_bytes::<StakedIota>`
//! gives you typed, named-field access:
//!
//! - `staked.id()` — the staked object's [`ObjectId`]
//! - `staked.pool_id()` — the staking pool the stake belongs to
//! - `staked.activation_epoch()` — the epoch the stake activates at
//! - `staked.principal()` — the staked amount in nanos
//!
//! [`ObjectId`]: iota_types::ObjectId

use eyre::Result;
use iota_move_system_types::system::StakedIota;
use iota_sdk::graphql_client::{Client, query_types::ObjectFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let page = client
        .objects(
            ObjectFilter {
                type_: Some("0x3::staking_pool::StakedIota".to_owned()),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;

    if page.data().is_empty() {
        println!("No StakedIota objects on testnet right now.");
        return Ok(());
    }

    println!("Decoded {} StakedIota object(s):\n", page.data().len());

    let mut total_principal: u128 = 0;
    for object in page.data() {
        let staked: StakedIota = bcs::from_bytes(&object.as_struct().contents)?;
        total_principal += u128::from(staked.principal());

        println!("- id:               {}", staked.id());
        println!("  pool_id:          {}", staked.pool_id());
        println!("  activation_epoch: {}", staked.activation_epoch());
        println!("  principal (nanos):{}", staked.principal());
        println!();
    }

    println!("Total principal across page: {total_principal} nanos");
    Ok(())
}
