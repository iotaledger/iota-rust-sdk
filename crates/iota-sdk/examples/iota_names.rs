// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: IOTA Names Operations
//!
//! This example demonstrates major IOTA Names operations including:
//! - Looking up a name and resolving its address
//! - Checking name availability

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::{SharedMut, TransactionBuilder, assigned},
    types::{Address, Identifier, ObjectId, StructTag, TypeTag},
};

const IOTA_NAMES_PACKAGE: &str = "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba";
const IOTA_NAMES_REGISTRY: &str = "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342";

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let iota_names_package_address = Address::from_str(IOTA_NAMES_PACKAGE)?;
    let iota_names_object_id = ObjectId::from_str(IOTA_NAMES_REGISTRY)?;

    println!("=== IOTA Names Example ===\n");

    // Example 1: Lookup and resolve a name
    let name = "name.iota";
    println!("1. Resolving name '{}'", name);
    match resolve_name(&client, iota_names_package_address, iota_names_object_id, name).await? {
        Some(address) => println!("   Resolved to: {}\n", address),
        None => println!("   Name not found or has no target address\n"),
    }

    // Example 2: Check name availability
    let test_name = "test123.iota";
    println!("2. Checking availability of '{}'", test_name);
    let is_available = check_name_availability(&client, iota_names_package_address, iota_names_object_id, test_name).await?;
    if is_available {
        println!("   Name is available!\n");
    } else {
        println!("   Name is already registered\n");
    }

    Ok(())
}

/// Resolve a name to its target address
async fn resolve_name(
    client: &Client,
    package_address: Address,
    registry_id: ObjectId,
    name: &str,
) -> Result<Option<Address>> {
    let sender = Address::from_str("0x0")?;
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    // Get the shared registry object
    builder
        .move_call(package_address, "iota_names", "registry")
        .arguments([SharedMut(registry_id)])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            package_address,
            Identifier::new("registry")?,
            Identifier::new("Registry")?,
            vec![],
        )))])
        .assign("iota_names");

    // Create the name object
    builder
        .move_call(package_address, "name", "new")
        .arguments([name])
        .assign("name");

    // Look up the name record
    builder
        .move_call(package_address, "registry", "lookup")
        .arguments((assigned("iota_names"), assigned("name")))
        .assign("name_record_opt");

    // Borrow the name record from the option
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("name_record_opt")])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            package_address,
            Identifier::new("name_record")?,
            Identifier::new("NameRecord")?,
            vec![],
        )))])
        .assign("name_record");

    // Get the target address
    builder
        .move_call(package_address, "name_record", "target_address")
        .arguments([assigned("name_record")])
        .assign("target_address_opt");

    // Borrow the address
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("target_address_opt")])
        .generics::<Address>();

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to resolve name: {}", err);
    }

    Ok(res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::Address))
        .and_then(|rv| TryInto::<[u8; 32]>::try_into(rv.bcs.as_slice()).ok())
        .map(Address::from))
}

/// Check if a name is available for registration
async fn check_name_availability(
    client: &Client,
    package_address: Address,
    registry_id: ObjectId,
    name: &str,
) -> Result<bool> {
    let sender = Address::from_str("0x0")?;
    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    builder
        .move_call(package_address, "iota_names", "registry")
        .arguments([SharedMut(registry_id)])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            package_address,
            Identifier::new("registry")?,
            Identifier::new("Registry")?,
            vec![],
        )))])
        .assign("iota_names");

    builder
        .move_call(package_address, "name", "new")
        .arguments([name])
        .assign("name");

    builder
        .move_call(package_address, "registry", "lookup")
        .arguments((assigned("iota_names"), assigned("name")))
        .assign("name_record_opt");

    builder
        .move_call(Address::STD, "option", "is_none")
        .arguments([assigned("name_record_opt")])
        .type_tags([TypeTag::Struct(Box::new(StructTag::new(
            package_address,
            Identifier::new("name_record")?,
            Identifier::new("NameRecord")?,
            vec![],
        )))]);

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to check availability: {}", err);
    }

    Ok(res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::Bool))
        .map(|rv| rv.bcs.first() == Some(&1))
        .unwrap_or(false))
}
