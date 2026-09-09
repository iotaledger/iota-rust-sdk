// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Reads the chain id, epoch and checkpoint height from the `service_info`
//! RPC, then the current reference gas price.

use eyre::{OptionExt, Result};
use iota_sdk::grpc_client::{Client, read_mask_fields::ServiceInfoReadMask};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet()?;

    let info = client.service_info(ServiceInfoReadMask::default()).await?;
    let chain_id = info
        .body()
        .chain_id
        .as_ref()
        .and_then(|d| d.digest().ok())
        .ok_or_eyre("missing chain id")?;
    println!("Chain ID:  {chain_id}");
    if let Some(epoch) = info.body().epoch {
        println!("Epoch:     {epoch}");
    }
    if let Some(height) = info.body().executed_checkpoint_height {
        println!("Height:    {height}");
    }

    let gas_price = client.reference_gas_price().await?;
    println!("Gas price: {}", gas_price.body());

    Ok(())
}
