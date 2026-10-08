// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;

use eyre::Result;
use futures::{StreamExt, TryStreamExt};
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let address =
        Address::from_hex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;

    // Page by page, one object per page, following the end cursor.
    let mut all_objects = Vec::new();
    let mut request = client.objects().owner(address).first(1);
    loop {
        let page = request.clone().await?;
        println!("Fetched a page of {} object(s)", page.len());
        let next = page
            .has_next_page()
            .then(|| page.end_cursor().cloned())
            .flatten();
        all_objects.extend(page.into_items());
        match next {
            Some(cursor) => request = request.after(cursor),
            None => break,
        }
    }
    println!("{} objects fetched:", all_objects.len());
    for object in &all_objects {
        println!("{}", object.id());
    }

    // The same walk as a stream of items.
    let streamed = client
        .objects()
        .owner(address)
        .first(1)
        .items()
        .try_collect::<Vec<_>>()
        .await?;
    println!("{} objects streamed", streamed.len());

    // A stream of pages: each page carries the cursor to resume from if a
    // later request fails.
    let mut pages = pin!(client.objects().owner(address).first(1).pages());
    let mut resume_after = None;
    while let Some(page) = pages.next().await {
        match page {
            Ok(page) => resume_after = page.end_cursor().cloned(),
            Err(error) => {
                println!("Stopped: {error}. Resume after {resume_after:?}");
                break;
            }
        }
    }

    Ok(())
}
