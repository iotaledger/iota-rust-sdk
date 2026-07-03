// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, pagination::PaginationFilter, query_types::ObjectFilter},
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let address = Address::ZERO;
    let owned_objects_page = client
        .objects(
            Some(ObjectFilter {
                owner: Some(address),
                ..Default::default()
            }),
            PaginationFilter::default(),
        )
        .await?;
    println!("Owned objects ({}):", owned_objects_page.data.len());
    for obj in owned_objects_page.data {
        println!("{}", obj.id());
    }

    Ok(())
}
