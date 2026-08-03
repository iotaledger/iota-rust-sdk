// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::Result, query_types::ObjectFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let coins = client
        .objects(
            ObjectFilter {
                type_: "0x2::coin::Coin<0x2::iota::IOTA>".to_owned().into(),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;

    if coins.data.is_empty() {
        println!("No IOTA coin objects found");
    } else {
        println!("IOTA coin object IDs:");
        for coin in coins.data {
            println!("{}", coin.id());
        }
    }

    Ok(())
}
