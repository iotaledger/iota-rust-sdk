// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: gas optimization patterns.
//!
//! Shows two practical optimization checks:
//! 1) detect fragmented gas coin set
//! 2) estimate transfer gas using dry-run before execution
//!
//! Set ADDRESS to inspect a specific account.

use std::{env::var, str::FromStr};

use eyre::{Result, bail};
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::TransactionBuilder,
    types::{Address, Transaction},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let address = Address::from_str(
        &var("ADDRESS").map_err(|_| eyre::eyre!("ADDRESS env var is required"))?,
    )?;

    // 1) Inspect gas coin fragmentation.
    let coins_page = client.coins(address, None, Default::default()).await?;
    let coin_count = coins_page.data().len();
    let total_balance = client.balance(address, None).await?.unwrap_or_default();

    println!("Address: {address}");
    println!("Gas coins: {coin_count}");
    println!("Total balance: {total_balance}");

    if coin_count > 20 {
        println!("Optimization hint: many fragmented gas coins detected; consider merge_coins.");
    } else {
        println!("Gas coin set looks compact.");
    }

    // 2) Estimate gas cost of a tiny self-transfer with dry-run.
    let mut builder = TransactionBuilder::new(address).with_client(&client);
    builder.send_iota(address, 1_u64);
    let tx: Transaction = builder.finish().await?;

    let dry_run = client.dry_run_tx(&tx, false).await?;
    if let Some(err) = dry_run.error {
        bail!("Dry run failed: {err}");
    }

    println!("Dry run succeeded. You can compare estimated effects before sending.");
    println!("Dry-run result summary: {dry_run:#?}");

    Ok(())
}
