// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let address = Address::ZERO;
    let owned_objects = client.objects().owner(address).await?;
    println!("Owned objects ({}):", owned_objects.len());
    for object in owned_objects {
        println!("{}", object.id());
    }

    Ok(())
}
