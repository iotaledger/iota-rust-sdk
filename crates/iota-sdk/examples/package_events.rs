// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{
    Client, error::Result, pagination::PaginationFilter, query_types::EventFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let events = client
        .events(
            EventFilter::default().with_event_type(
                "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"
                    .to_string(),
            ),
            PaginationFilter {
                limit: Some(10),
                ..Default::default()
            },
        )
        .await?;

    for event in events.data() {
        println!("Type: {}", event.move_type.repr);
        println!("Sender: {}", event.sender.as_ref().unwrap().address);
        println!("Module: {}", event.sending_module.as_ref().unwrap().name);
        println!("JSON: {}", event.json);
    }

    Ok(())
}
