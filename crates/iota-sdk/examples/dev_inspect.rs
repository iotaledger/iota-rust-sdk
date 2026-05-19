// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::{TransactionBuilder, assigned},
    types::{Address, TypeTag},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let sender = Address::from_str("0x0")?;

    let mut builder = TransactionBuilder::new(sender).with_client(client);

    // Build a small chain of stdlib Move calls and extract the return value
    // from the final command via dry_run.
    builder
        .move_call(Address::STD, "u64", "max")
        .arguments((100u64, 200u64))
        .assign("max_value");

    builder
        .move_call(Address::STD, "u64", "min")
        .arguments((assigned("max_value"), 150u64))
        .assign("result");

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to dry-run: {err}");
    }

    match res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::U64))
        .and_then(|rv| TryInto::<[u8; 8]>::try_into(rv.bcs.as_slice()).ok())
        .map(u64::from_le_bytes)
    {
        Some(value) => println!("min(max(100, 200), 150) = {value}"),
        None => println!("Failed to extract u64 from results"),
    }

    Ok(())
}
