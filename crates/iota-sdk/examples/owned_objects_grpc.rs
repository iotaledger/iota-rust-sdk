// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! gRPC counterpart to `owned_objects.rs`.
//!
//! Demonstrates the gRPC pagination builder: the query is *lazy* until
//! awaited or `.collect()`-ed. Awaiting returns a single `Page` with a
//! continuation token; `.collect(limit)` auto-paginates up to `limit`
//! items (or all of them if `limit` is `None`).

use eyre::Result;
use iota_sdk::{
    grpc_client::{Client, read_mask_fields::OwnedObjectReadMask},
    types::{Address, StructTag},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    let owner: Address =
        "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151".parse()?;

    // First page: 10 results, no filter on type. The returned page includes
    // a `next_page_token` to feed back in for the following page.
    let page = client
        .list_owned_objects(owner, None, 10, None, OwnedObjectReadMask::default())
        .await?;
    println!("First page: {} objects", page.body().items.len());
    for obj in &page.body().items {
        println!("  {}", obj.object_reference()?.object_id);
    }
    if page.body().next_page_token.is_some() {
        println!("  ...more pages available");
    }

    // Auto-paginate: only IOTA coins, capped at 50 across all pages.
    let iota_coin: StructTag = "0x2::coin::Coin<0x2::iota::IOTA>".parse()?;
    let coins = client
        .list_owned_objects(owner, iota_coin, 25, None, OwnedObjectReadMask::default())
        .collect(Some(50))
        .await?;
    println!("---");
    println!(
        "Up to 50 IOTA coin objects ({} returned):",
        coins.body().len()
    );
    for obj in coins.body() {
        let r = obj.object_reference()?;
        println!("  {}  v{}", r.object_id, r.version);
    }

    Ok(())
}
