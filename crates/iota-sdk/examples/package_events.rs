// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{
    Client, error::Result, pagination::PaginationFilter, query_types::EventFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    // Query events emitted by the validator-set module in the IOTA system
    // framework (0x3). These fire on every epoch change so they are reliably
    // present on every network including localnet.
    let events = client
        .events(
            EventFilter {
                event_type: Some("0x3::validator::StakingRequestEvent".to_string()),
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
        if let Some(sender) = event.sender.as_ref() {
            println!("Sender: {}", sender.address);
        }
        if let Some(module) = event.sending_module.as_ref() {
            println!("Module: {}", module.name);
        }
        println!("JSON: {}", event.json);
    }

    Ok(())
}
