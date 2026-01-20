// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let result = client
        .move_view_call(
            "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata".to_string(),
            None::<Vec<String>>,
            Some(vec![
                serde_json::json!("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b"),
                serde_json::json!("auc.iota"),
            ]),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Error: {error}");
    } else if let Some(results) = result.results {
        println!("Results: {results:?}");
    } else {
        println!("No results");
    }

    let result = client
        .move_view_call(
            "0x2::hash::blake2b256".to_string(),
            None::<Vec<String>>,
            Some(vec![serde_json::json!([0, 1, 2])]),
        )
        .await?;

    if let Some(error) = result.error {
        println!("Hash Error: {error}");
    } else if let Some(results) = result.results {
        println!("Hash Results: {results:?}");
    } else {
        println!("No hash results");
    }

    Ok(())
}
