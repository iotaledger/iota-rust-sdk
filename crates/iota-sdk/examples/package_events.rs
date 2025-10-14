// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{
    Client, error::Result, pagination::PaginationFilter, query_types::EventFilter,
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

    for event in events.data() {
        println!("Type: {}", event.type_.repr);
        println!("Sender: {}", event.sender.as_ref().unwrap().address);
        println!("Module: {}", event.sending_module.as_ref().unwrap().name);
        println!("JSON: {}", event.json);
    }

    Ok(())
}
