// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, iota_types::StructTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let event_type: StructTag = "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"
        .parse()?;
    let events = client.events().event_type(event_type).first(10).await?;

    for event in events {
        println!("Type: {}", event.event_type);
        if let Some(sender) = event.sender {
            println!("Sender: {sender}");
        }
        if let Some(module) = &event.module {
            println!("Module: {module}");
        }
        if let Some(digest) = event.transaction_digest {
            println!("Transaction: {digest}");
        }
        println!("JSON: {}", event.json);
    }

    Ok(())
}
