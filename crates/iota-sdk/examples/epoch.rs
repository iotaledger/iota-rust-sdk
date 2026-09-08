// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::graphql_client::{Client, error::GraphQLResult};

#[tokio::main]
async fn main() -> GraphQLResult<()> {
    let client = Client::new_testnet();

    let current_epoch = client.epoch(None).await?.unwrap();
    println!("Current epoch: {}", current_epoch.epoch_id);
    println!(
        "Current epoch start time: {}",
        current_epoch.start_timestamp.0
    );

    let previous_epoch = client
        .epoch(Some(current_epoch.epoch_id - 1))
        .await?
        .unwrap();
    println!("Previous epoch: {}", previous_epoch.epoch_id);
    println!(
        "Previous epoch stake rewards: {}",
        previous_epoch.total_stake_rewards.unwrap().0
    );

    Ok(())
}
