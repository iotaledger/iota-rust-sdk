// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk_graphql_client_next::{GraphQLClient, Result, iota_types::StructTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let coins = client
        .objects()
        .type_filter(StructTag::new_gas_coin())
        .await?;

    if coins.is_empty() {
        println!("No IOTA coin objects found");
    } else {
        println!("IOTA coin object IDs:");
        for coin in coins {
            println!("{}", coin.id());
        }
    }

    Ok(())
}
