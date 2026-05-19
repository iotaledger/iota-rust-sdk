// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{
    graphql_client::{
        Client, faucet::FaucetClient, pagination::PaginationFilter, query_types::ObjectFilter,
    },
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let address =
        Address::from_hex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")?;
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(address, &client)
        .await?;

    let mut all_objects = Vec::new();
    let mut next_cursor = None;
    while let Some(cursor) = Some(next_cursor.clone()) {
        println!("Fetching page with cursor: {cursor:?}");
        let owned_objects_page = client
            .objects(
                Some(ObjectFilter {
                    owner: Some(address),
                    ..Default::default()
                }),
                PaginationFilter {
                    cursor,
                    // Limit to 1 to demonstrate pagination
                    limit: Some(1),
                    ..Default::default()
                },
            )
            .await?;
        let (page_info, data) = owned_objects_page.into_parts();
        all_objects.extend(data);
        if page_info.has_next_page {
            next_cursor = page_info.end_cursor.clone();
        } else {
            break;
        }
    }
    println!("{} objects fetched:", all_objects.len());
    for obj in &all_objects {
        println!("{}", obj.object_id());
    }

    Ok(())
}
