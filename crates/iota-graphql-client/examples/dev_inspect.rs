// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::{Function, TransactionBuilder, unresolved::Input};
use iota_types::{Address, Identifier, ObjectId, StructTag, TypeTag};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender_address = Address::from_str("0x0")?;

    let iota_names_package_address =
        Address::from_str("0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba")?;
    let iota_names_object_id =
        ObjectId::from_str("0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342")?;
    let name = "name.iota";

    println!("Looking up name: {name}");

    let mut builder = TransactionBuilder::new();

    // Step 1: Get the shared registry object
    let registry_input = builder.input(Input::shared(iota_names_object_id, 365644877, true));
    let iota_names = builder.move_call(
        Function::new(
            iota_names_package_address,
            Identifier::new("iota_names")?,
            Identifier::new("registry")?,
            vec![TypeTag::Struct(Box::new(StructTag {
                address: iota_names_package_address,
                module: Identifier::new("registry")?,
                name: Identifier::new("Registry")?,
                type_params: vec![],
            }))],
        ),
        vec![registry_input],
    );

    // Step 2: Create the name object from the string
    let name_input = builder.input(Input::pure(&name)?);
    let name_result = builder.move_call(
        Function::new(
            iota_names_package_address,
            Identifier::new("name")?,
            Identifier::new("new")?,
            Default::default(),
        ),
        vec![name_input],
    );

    // Step 3: Look up the name record in the registry
    let name_record_option = builder.move_call(
        Function::new(
            iota_names_package_address,
            Identifier::new("registry")?,
            Identifier::new("lookup")?,
            Default::default(),
        ),
        vec![iota_names, name_result],
    );

    // Step 4: Borrow the name record from the option
    let name_record = builder.move_call(
        Function::new(
            Address::from_str("0x1")?,
            Identifier::new("option")?,
            Identifier::new("borrow")?,
            vec![TypeTag::Struct(Box::new(StructTag {
                address: iota_names_package_address,
                module: Identifier::new("name_record")?,
                name: Identifier::new("NameRecord")?,
                type_params: vec![],
            }))],
        ),
        vec![name_record_option],
    );

    // Step 5: Get the target address from the name record
    let target_address_option = builder.move_call(
        Function::new(
            iota_names_package_address,
            Identifier::new("name_record")?,
            Identifier::new("target_address")?,
            Default::default(),
        ),
        vec![name_record],
    );

    // Step 6: Borrow the address from the option (this returns the resolved
    // address)
    let _target_address = builder.move_call(
        Function::new(
            Address::from_str("0x1")?,
            Identifier::new("option")?,
            Identifier::new("borrow")?,
            vec![TypeTag::Address],
        ),
        vec![target_address_option],
    );

    builder.set_sender(sender_address);
    builder.set_gas_budget(50000000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .context("missing ref gas price")?,
    );
    let txn = builder.finish()?;

    let res = client.dry_run_tx(&txn, true).await?;

    if let Some(err) = res.error {
        anyhow::bail!("Failed to lookup name: {err}");
    }

    // Extract the resolved address from the last result
    match res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_, TypeTag::Address))
        .and_then(|rv| TryInto::<[u8; 32]>::try_into(rv.bcs.as_slice()).ok())
        .map(Address::from)
    {
        Some(resolved_address) => println!("Resolved address: {resolved_address}"),
        None => println!("Failed to extract address from results"),
    }

    Ok(())
}
