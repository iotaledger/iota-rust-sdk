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
            EventFilter {
                event_type: Some(
                    "0x7aec8176867a0c8d2803d758ebf98226d301ef0f00393879ea718f6bd1554f16::registry::NameRecordAddedEvent"
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
