// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_sdk::{
    graphql_client::{Client, error::GraphQLResult},
    types::ObjectId,
};

/// The `view_demo` package published on testnet.
const PACKAGE: &str = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";
/// A shared `view_demo::shop::Shop` created when the package was published.
const SHOP: &str = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20";

#[tokio::main]
async fn main() -> GraphQLResult<()> {
    let client = Client::new_testnet();

    // ===========================================================================
    // Example 1: Using move_view_call() with typed arguments (primitives)
    // ===========================================================================
    println!("=== Example 1: move_view_call() with typed arguments (primitives) ===\n");

    let result = client
        .move_view_call(
            format!("{PACKAGE}::shop::discounted_price"),
            None,
            (100u64, 25u64),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Error: {error}");
    } else if let Some(results) = result.results {
        println!("Results: {results:?}");
    } else {
        println!("No results");
    }

    // ===========================================================================
    // Example 2: Using move_view_call_json() with JSON values (primitives)
    // ===========================================================================
    println!("\n=== Example 2: move_view_call_json() with JSON values (primitives) ===\n");

    let result = client
        .move_view_call_json(
            format!("{PACKAGE}::shop::discounted_price"),
            None,
            // `u64` is passed as a string so large values survive JSON.
            Some(vec![serde_json::json!("100"), serde_json::json!("25")]),
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
    // Example 3: Using move_view_call() with typed arguments (shared object)
    // ===========================================================================
    println!("\n=== Example 3: move_view_call() with typed arguments (shared object) ===\n");

    let result = client
        .move_view_call(
            format!("{PACKAGE}::shop::sale_at"),
            None,
            (ObjectId::from_str(SHOP)?, 1u64),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Shop Error: {error}");
    } else if let Some(results) = result.results {
        println!("Shop Results: {results:?}");
    } else {
        println!("No shop results");
    }

    // ===========================================================================
    // Example 4: Using move_view_call_json() with JSON values (shared object)
    // ===========================================================================
    println!("\n=== Example 4: move_view_call_json() with JSON values (shared object) ===\n");

    let result = client
        .move_view_call_json(
            format!("{PACKAGE}::shop::sale_at"),
            None,
            Some(vec![serde_json::json!(SHOP), serde_json::json!("1")]),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Shop JSON Error: {error}");
    } else if let Some(results) = result.results {
        println!("Shop JSON Results: {results:?}");
    } else {
        println!("No shop JSON results");
    }

    Ok(())
}
