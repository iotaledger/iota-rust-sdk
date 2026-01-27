// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_sdk::{
    graphql_client::{Client, error::Result},
    types::ObjectId,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    // ===========================================================================
    // Example 1: Using move_view_call() with typed arguments (blake2b256)
    // ===========================================================================
    println!("=== Example 1: move_view_call() with typed arguments (blake2b256) ===\n");

    let result = client
        .move_view_call("0x2::hash::blake2b256", None, (vec![0u8, 1, 2],))
        .await?;

    if let Some(error) = result.error {
        println!("Error: {error}");
    } else if let Some(results) = result.results {
        println!("Results: {results:?}");
    } else {
        println!("No results");
    }

    // ===========================================================================
    // Example 2: Using move_view_call_json() with JSON values (blake2b256)
    // ===========================================================================
    println!("\n=== Example 2: move_view_call_json() with JSON values (blake2b256) ===\n");

    let result = client
        .move_view_call_json(
            "0x2::hash::blake2b256",
            None,
            Some(vec![serde_json::json!([0, 1, 2])]),
        )
        .await?;

    if let Some(error) = result.error {
        println!("JSON Error: {error}");
    } else if let Some(results) = result.results {
        println!("JSON Results: {results:?}");
    } else {
        println!("No JSON results");
    }

    // ===========================================================================
    // Example 3: Using move_view_call() with typed arguments (auction)
    // ===========================================================================
    println!("\n=== Example 3: move_view_call() with typed arguments (auction) ===\n");

    let result = client
        .move_view_call(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
            None,
            (ObjectId::from_str("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b")?, "auc.iota"),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Auction Error: {error}");
    } else if let Some(results) = result.results {
        println!("Auction Results: {results:?}");
    } else {
        println!("No auction results");
    }

    // ===========================================================================
    // Example 4: Using move_view_call_json() with JSON values (auction)
    // ===========================================================================
    println!("\n=== Example 4: move_view_call_json() with JSON values (auction) ===\n");

    let result = client
        .move_view_call_json(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
            None,
            Some(vec![
                serde_json::json!("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b"),
                serde_json::json!("auc.iota"),
            ]),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Auction JSON Error: {error}");
    } else if let Some(results) = result.results {
        println!("Auction JSON Results: {results:?}");
    } else {
        println!("No auction JSON results");
    }

    Ok(())
}
