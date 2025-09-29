// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_graphql_client::{Client, pagination::PaginationFilter, query_types::ObjectFilter};
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let address =
        Address::from_hex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

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
