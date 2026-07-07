// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stream a range of checkpoints over gRPC.

use futures::StreamExt;
use iota_sdk::grpc_client::{Client, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    // Pick a small range of recent checkpoints to stream.
    let latest = client
        .get_checkpoint_latest(None, None, None)
        .await?
        .into_inner();
    let start = latest.sequence_number.saturating_sub(4);

    let mut stream = client
        .stream_checkpoints(Some(start), Some(latest.sequence_number), None, None, None)
        .await?;

    while let Some(checkpoint) = stream.body_mut().next().await {
        let checkpoint = checkpoint?;
        let summary = checkpoint.summary()?.summary()?;
        println!(
            "Checkpoint {}: epoch {}, {} total transactions, timestamp {}",
            checkpoint.sequence_number,
            summary.epoch,
            summary.network_total_transactions,
            summary.timestamp_ms,
        );
    }

    Ok(())
}
