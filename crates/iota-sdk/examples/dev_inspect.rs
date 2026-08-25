// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::{SharedMut, assigned},
    types::{Address, Identifier, ObjectId, StructTag, TypeTag},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let sender = Address::from_str("0x0")?;

    let iota_names_package_address =
        Address::from_str("0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea")?;
    let iota_names_object_id =
        ObjectId::from_str("0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec")?;
    let name = "name.iota";

    println!("Looking up name: {name}");

    let mut builder = client.transaction_builder(sender);

    // Step 1: Get the shared registry object
    builder
        .move_call(iota_names_package_address, "iota_names", "registry")
        .arguments([SharedMut(iota_names_object_id)])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            iota_names_package_address,
            Identifier::new("registry")?,
            Identifier::new("Registry")?,
            vec![],
        )))])
        .assign("iota_names");

    // Step 2: Create the name object from the string
    builder
        .move_call(iota_names_package_address, "name", "new")
        .arguments([name])
        .assign("name");

    // Step 3: Look up the name record in the registry
    builder
        .move_call(iota_names_package_address, "registry", "lookup")
        .arguments((assigned("iota_names"), assigned("name")))
        .assign("name_record_opt");

    // Step 4: Borrow the name record from the option
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("name_record_opt")])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            iota_names_package_address,
            Identifier::new("name_record")?,
            Identifier::new("NameRecord")?,
            vec![],
        )))])
        .assign("name_record");

    // Step 5: Get the target address from the name record
    builder
        .move_call(iota_names_package_address, "name_record", "target_address")
        .arguments([assigned("name_record")])
        .assign("target_address_opt");

    // Step 6: Borrow the address from the option (this returns the resolved
    // address)
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("target_address_opt")])
        .generics::<Address>()
        .assign("target_address");

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to lookup name: {err}");
    }

    // Extract the resolved address from the last result
    match res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::Address))
        .and_then(|rv| TryInto::<[u8; 32]>::try_into(rv.bcs.as_slice()).ok())
        .map(Address::from)
    {
        Some(resolved_address) => println!("Resolved address: {resolved_address}"),
        None => println!("Failed to extract address from results"),
    }

    Ok(())
}
