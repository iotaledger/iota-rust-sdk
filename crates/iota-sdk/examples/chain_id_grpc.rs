// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Same idea as `chain_id.rs`, but over gRPC.
//!
//! Demonstrates two ways to get the chain id: the explicit `get_service_info`
//! RPC, and the `ResponseExt` headers that ride along with *every* gRPC
//! response (so any call already tells you what chain / epoch / checkpoint
//! you observed).

use eyre::{OptionExt, Result};
use iota_sdk::grpc_client::{Client, ResponseExt};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    // Option 1: explicit service info RPC.
    let info = client.get_service_info(None).await?;
    let chain_id = info
        .body()
        .chain_id
        .as_ref()
        .and_then(|d| d.digest().ok())
        .ok_or_eyre("missing chain id")?;
    println!("Chain ID:  {chain_id}");
    if let Some(chain) = &info.body().chain {
        println!("Chain:     {chain}");
    }
    if let Some(epoch) = info.body().epoch {
        println!("Epoch:     {epoch}");
    }

    // Option 2: the same data piggybacks on response headers via
    // `ResponseExt`. Any RPC works — here we reuse the response above.
    println!("---");
    println!("From response headers:");
    if let Some(chain_id) = info.chain_id() {
        println!("Chain ID:  {chain_id}");
    }
    if let Some(epoch) = info.epoch() {
        println!("Epoch:     {epoch}");
    }
    if let Some(height) = info.checkpoint_height() {
        println!("Height:    {height}");
    }

    Ok(())
}
