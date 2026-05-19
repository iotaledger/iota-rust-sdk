// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let current_epoch = client.epoch(None).await?.unwrap();
    println!("Current epoch: {}", current_epoch.epoch_id);
    println!(
        "Current epoch start time: {}",
        current_epoch.start_timestamp.0
    );

    if let Some(previous_epoch_id) = current_epoch.epoch_id.checked_sub(1) {
        let previous_epoch = client.epoch(Some(previous_epoch_id)).await?.unwrap();
        println!("Previous epoch: {}", previous_epoch.epoch_id);
        if let Some(rewards) = previous_epoch.total_stake_rewards {
            println!("Previous epoch stake rewards: {}", rewards.0);
        } else {
            println!("Previous epoch stake rewards: <none>");
        }
    } else {
        println!("No previous epoch (current is epoch 0)");
    }

    Ok(())
}
