// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::{TransactionBuilder, res, unresolved::Argument};
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    let mut builder = TransactionBuilder::new(sender_address).with_client(client.clone());
    builder
        .move_call(Address::STD_LIB, "u64", "max")
        .arguments((0u64, 1000u64))
        // Assign a name to the result of this command
        .name("res0");
    builder
        .move_call(Address::STD_LIB, "u64", "max")
        .arguments((1000u64, 2000u64))
        .name("res1");

    builder
        // Use the named results of previous commands to use as arguments
        .split_coins(Argument::Gas, [res("res0"), res("res1")])
        // For nested results, a tuple or vec can be used to name them
        .name(vec!["coin0", "coin1"]);

    // Use named results as arguments
    builder.transfer_objects(sender_address, [res("coin0"), res("coin1")]);

    let tx = builder.finish().await?;

    println!("Signing Digest: {}", tx.signing_digest_hex());
    println!("Tx Bytes: {}", tx.to_base64());

    let res = client.dry_run_tx(&tx, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send tx: {err}");
    }

    println!("Tx dry run was successful!");

    Ok(())
}
