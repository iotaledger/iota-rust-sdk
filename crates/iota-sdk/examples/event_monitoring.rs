// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: event monitoring patterns.
//!
//! Demonstrates:
//! 1) filtered event query (latest page)
//! 2) polling-style monitor loop over recent event pages

use eyre::Result;
use iota_sdk::graphql_client::{
    Client,
    pagination::PaginationFilter,
    query_types::EventFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    // 1) Query latest events page.
    let page = client
        .events(
            EventFilter::default(),
            PaginationFilter {
                limit: Some(10),
                ..Default::default()
            },
        )
        .await?;

    println!("Latest events page size: {}", page.data().len());
    for event in page.data().iter().take(5) {
        println!("- type={} sender={:?}", event.type_.repr, event.sender);
    }

    // 2) Polling-style monitor loop over recent pages.
    for tick in 1..=3 {
        let polled = client
            .events(
                EventFilter::default(),
                PaginationFilter {
                    limit: Some(3),
                    ..Default::default()
                },
            )
            .await?;

        println!("[poll #{tick}] events fetched: {}", polled.data().len());
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    Ok(())
}
