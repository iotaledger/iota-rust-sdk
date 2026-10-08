// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result};
use iota_sdk_graphql_client_next::GraphQLClient;

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let current_epoch = client.epoch().await?.ok_or_eyre("no current epoch")?;
    println!("Current epoch: {}", current_epoch.epoch_id);
    println!(
        "Current epoch start time: {}",
        current_epoch.start_timestamp
    );
    println!(
        "Reference gas price: {:?}",
        current_epoch.reference_gas_price
    );

    let previous_epoch = client
        .epoch()
        .id(current_epoch.epoch_id - 1)
        .await?
        .ok_or_eyre("no previous epoch")?;
    println!("Previous epoch: {}", previous_epoch.epoch_id);
    println!(
        "Previous epoch stake rewards: {:?}",
        previous_epoch.total_stake_rewards
    );

    Ok(())
}
