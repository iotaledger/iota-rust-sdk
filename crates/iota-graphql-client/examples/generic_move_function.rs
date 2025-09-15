// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::{Function, TransactionBuilder, unresolved::Input};
use iota_types::{Address, Identifier, TypeTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender = "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e".parse()?;

    let gas_coin = client
        .object(
            "0xa1d009e8dafe20b1cba05e08aea488aafae1f89d892c3eaef6c0994e155e441a".parse()?,
            None,
        )
        .await?
        .context("missing gas coin")?;

    let mut builder = TransactionBuilder::new();

    let address1 =
        Address::from_str("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")?;
    let address2 =
        Address::from_str("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")?;

    let addresses = vec![
        builder.input(Input::pure(&address1)?),
        builder.input(Input::pure(&address2)?),
    ];
    let addresses = builder.make_move_vec(Some(TypeTag::address()), addresses);
    let balances = vec![
        builder.input(Input::pure(&10000000u64)?),
        builder.input(Input::pure(&20000000u64)?),
    ];
    let balances = builder.make_move_vec(Some(TypeTag::u64()), balances);

    builder.move_call(
        Function::new(
            Address::TWO,
            Identifier::new("vec_map")?,
            Identifier::new("from_keys_values")?,
            vec![TypeTag::address(), TypeTag::u64()],
        ),
        vec![addresses, balances],
    );
    builder.set_sender(sender);
    builder.set_gas_budget(50_000_000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .context("missing gas price")?,
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);

    let txn = builder.finish()?;
    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to call generic Move function: {err}");
    }

    println!("Successfully called generic Move function!");

    Ok(())
}
