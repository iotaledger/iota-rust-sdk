// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: transaction debugging workflow.
//!
//! Demonstrates a practical debug loop:
//! 1) build unsigned transaction bytes
//! 2) dry-run and inspect error/effects
//! 3) fetch an existing transaction by digest for post-mortem analysis
//!
//! Set FROM_ADDRESS, TO_ADDRESS, and optionally TX_DIGEST.

use std::{env::var, str::FromStr};

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::TransactionBuilder,
    types::{Address, Digest},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let from = Address::from_str(
        &var("FROM_ADDRESS").map_err(|_| eyre::eyre!("FROM_ADDRESS env var is required"))?,
    )?;
    let to = Address::from_str(
        &var("TO_ADDRESS").map_err(|_| eyre::eyre!("TO_ADDRESS env var is required"))?,
    )?;

    let mut builder = TransactionBuilder::new(from).with_client(&client);
    builder.send_iota(to, 1_u64);
    let tx = builder.finish().await?;

    println!("Built tx signing digest: {}", tx.signing_digest_hex());

    let dry_run = client.dry_run_tx(&tx, false).await?;
    match dry_run.error.as_ref() {
        Some(err) => println!("Dry-run error: {err}"),
        None => println!("Dry-run ok"),
    }
    println!("Dry-run details: {dry_run:#?}");

    if let Ok(digest_env) = var("TX_DIGEST") {
        let digest = Digest::from_str(&digest_env)?;
        let tx_data = client
            .transaction(digest)
            .await?
            .ok_or_eyre("transaction not found")?;
        println!("Fetched tx digest: {}", tx_data.transaction.digest());
        println!("Fetched tx payload: {:#?}", tx_data.transaction);
    } else {
        println!("Set TX_DIGEST to inspect an already-submitted transaction.");
    }

    Ok(())
}
