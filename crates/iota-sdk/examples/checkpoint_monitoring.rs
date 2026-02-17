// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: checkpoint monitoring.
//!
//! Polls latest checkpoint sequence and total transaction count,
//! and reports when a new checkpoint is observed.

use std::time::Duration;

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    // How often to poll for new checkpoints.
    let poll_every = Duration::from_secs(5);

    // Number of poll iterations (keep finite for example use).
    let max_iterations = 12;

    let mut last_seen = client.latest_checkpoint_sequence_number().await?.unwrap_or(0);
    println!("Starting monitor from checkpoint: {last_seen}");

    for _ in 0..max_iterations {
        tokio::time::sleep(poll_every).await;

        let latest = client.latest_checkpoint_sequence_number().await?.unwrap_or(last_seen);
        if latest > last_seen {
            let total_tx = client.total_transaction_blocks().await?.unwrap_or(0);
            println!(
                "New checkpoint detected: {} -> {} (network total tx blocks: {})",
                last_seen, latest, total_tx
            );
            last_seen = latest;
        } else {
            println!("No new checkpoint. Latest remains {latest}");
        }
    }

    println!("Checkpoint monitoring finished.");
    Ok(())
}
