// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Tail live transactions and events over GraphQL subscriptions.
//!
//! Unlike the paginated `transactions` / `events` queries, these streams push
//! data as the network produces it and never end on their own — the consumer
//! decides when to stop. Errors arrive in-band: the stream reconnects behind
//! the scenes and resumes after the last item it handed out, so a yielded
//! error is a hiccup to report, not the end of the stream.

use std::time::Duration;

use eyre::Result;
use futures::StreamExt;
use iota_sdk::graphql_client::{
    Client,
    query_types::{Feature, SubscriptionTransactionFilter, TransactionBlockKindInput},
};

/// How many items to take from each stream before moving on.
const HOW_MANY: usize = 3;
/// How long to wait on a quiet network before giving up.
const PATIENCE: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    // Subscriptions are served over a WebSocket that the node has to have
    // enabled
    let enabled = client
        .service_config()
        .await?
        .supports_feature(Feature::Subscriptions);
    if !enabled {
        println!("this node does not serve subscriptions");
        return Ok(());
    }

    let mut transactions = client.transactions_stream(
        SubscriptionTransactionFilter::default()
            .with_kind(TransactionBlockKindInput::ProgrammableTx),
        None,
    );

    println!("Waiting for {HOW_MANY} programmable transactions");
    let quiet = tokio::time::timeout(PATIENCE, async {
        let mut taken = 0;
        while let Some(item) = transactions.next().await {
            match item {
                Ok(transaction) => {
                    println!("  tx {}", transaction.transaction.digest());
                    taken += 1;
                    if taken == HOW_MANY {
                        break;
                    }
                }
                Err(error) => println!("  transactions stream: {error}"),
            }
        }
    })
    .await
    .is_err();
    if quiet {
        println!("  nothing within {PATIENCE:?}");
    }

    let mut events = client.events_stream(None, None);

    println!("Waiting for {HOW_MANY} events");
    let quiet = tokio::time::timeout(PATIENCE, async {
        let mut taken = 0;
        while let Some(item) = events.next().await {
            match item {
                Ok(event) => {
                    println!("  {}", event.move_type.repr);
                    taken += 1;
                    if taken == HOW_MANY {
                        break;
                    }
                }
                Err(error) => println!("  events stream: {error}"),
            }
        }
    })
    .await
    .is_err();
    if quiet {
        println!("  nothing within {PATIENCE:?}");
    }

    Ok(())
}
