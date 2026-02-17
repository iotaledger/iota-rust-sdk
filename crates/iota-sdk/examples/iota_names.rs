// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: monitor IOTA Names registrations via events.

use eyre::Result;
use iota_sdk::graphql_client::{
    Client,
    pagination::PaginationFilter,
    query_types::EventFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let events = client
        .events(
            EventFilter {
                event_type: Some(
                    "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent"
                        .to_string(),
                ),
                ..Default::default()
            },
            PaginationFilter {
                limit: Some(10),
                ..Default::default()
            },
        )
        .await?;

    println!("Fetched {} IOTA Names events", events.data().len());
    for event in events.data() {
        println!("Type: {}", event.type_.repr);
        println!("Sender: {:?}", event.sender.as_ref().map(|s| s.address));
        println!("JSON: {}", event.json);
        println!("---");
    }

    Ok(())
}
