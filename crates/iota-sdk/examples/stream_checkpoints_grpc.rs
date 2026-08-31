// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Tail recent checkpoints over gRPC.
//!
//! This is one of gRPC's headline features — there's no equivalent in the
//! GraphQL client. We open a server-streaming RPC and pull a handful of
//! checkpoint summaries out of it.

use eyre::Result;
use futures::StreamExt;
use iota_sdk::grpc_client::{
    Client,
    read_mask_fields::{CheckpointResponseField, CheckpointResponseReadMask},
};

const HOW_MANY: u64 = 5;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    // Pick a starting point a few checkpoints behind head so the example
    // returns promptly instead of waiting on new blocks.
    let head = client
        .latest_checkpoint(None, None, CheckpointResponseReadMask::default())
        .await?
        .body()
        .sequence_number();
    let start = head.saturating_sub(HOW_MANY - 1);
    let end = head;

    // Only ask for the summary — keeps the message small. Pass
    // `CheckpointResponseReadMask::default()` (or compose more fields) to
    // pull more data per checkpoint.
    let mut stream = client
        .checkpoints_stream(
            start,
            end,
            None,
            None,
            CheckpointResponseField::CHECKPOINT_SUMMARY,
        )
        .await?;

    println!("Streaming checkpoints {start}..={end}");
    while let Some(checkpoint) = stream.body_mut().next().await {
        let checkpoint = checkpoint?;
        let summary = checkpoint.summary()?;
        println!(
            "  cp {:>6}  epoch {:>3}  txs {:>4}  ts {}",
            checkpoint.sequence_number(),
            summary.summary()?.epoch,
            summary.summary()?.network_total_transactions,
            summary.summary()?.timestamp_ms,
        );
    }

    Ok(())
}
