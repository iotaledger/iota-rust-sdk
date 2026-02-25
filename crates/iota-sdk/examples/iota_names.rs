// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example demonstrates the major IOTA Names operations using dev_inspect
//! transactions:
//!
//! 1. **Name lookup**: resolve an IOTA name (e.g. "name.iota") to an address
//! 2. **Reverse lookup**: resolve an address back to its IOTA name
//! 3. **Name record details**: query expiration timestamp and custom data
//! 4. **Check existence**: verify if a name is registered
//!
//! All operations use `dev_inspect` (dry run) so no gas or signing is needed.

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::{SharedMut, TransactionBuilder, assigned},
    types::{Address, Identifier, ObjectId, StructTag, TypeTag},
};

/// IOTA Names package address on devnet.
const IOTA_NAMES_PACKAGE: &str =
    "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba";

/// IOTA Names shared object ID on devnet.
const IOTA_NAMES_OBJECT: &str =
    "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342";

/// Helper to create the Registry type tag.
fn registry_type_tag(pkg: Address) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag::new(
        pkg,
        Identifier::new("registry").unwrap(),
        Identifier::new("Registry").unwrap(),
        vec![],
    )))
}

/// Helper to create the NameRecord type tag.
fn name_record_type_tag(pkg: Address) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag::new(
        pkg,
        Identifier::new("name_record").unwrap(),
        Identifier::new("NameRecord").unwrap(),
        vec![],
    )))
}

/// Example 1: Look up an IOTA name to get the associated address.
///
/// Gets the registry from the IotaNames object, creates a Name from
/// a string, looks up the NameRecord, and extracts the target address.
async fn lookup_name(client: &Client, name: &str) -> Result<Option<Address>> {
    let pkg = Address::from_str(IOTA_NAMES_PACKAGE)?;
    let obj = ObjectId::from_str(IOTA_NAMES_OBJECT)?;
    let sender = Address::from_str("0x0")?;

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    // Step 1: Get the shared registry object
    builder
        .move_call(pkg, "iota_names", "registry")
        .arguments([SharedMut(obj)])
        .type_tags([registry_type_tag(pkg)])
        .assign("iota_names");

    // Step 2: Create the name object from the string
    builder
        .move_call(pkg, "name", "new")
        .arguments([name])
        .assign("name");

    // Step 3: Look up the name record in the registry
    builder
        .move_call(pkg, "registry", "lookup")
        .arguments((assigned("iota_names"), assigned("name")))
        .assign("name_record_opt");

    // Step 4: Borrow the name record from the option
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("name_record_opt")])
        .type_tags([name_record_type_tag(pkg)])
        .assign("name_record");

    // Step 5: Get the target address from the name record
    builder
        .move_call(pkg, "name_record", "target_address")
        .arguments([assigned("name_record")])
        .assign("target_address_opt");

    // Step 6: Borrow the address from the option
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("target_address_opt")])
        .generics::<Address>()
        .assign("target_address");

    let res = builder.dry_run(true).await?;

    if let Some(err) = &res.error {
        if err.contains("None") || err.contains("option") {
            return Ok(None);
        }
        eyre::bail!("Name lookup failed: {err}");
    }

    Ok(res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::Address))
        .and_then(|rv| TryInto::<[u8; 32]>::try_into(rv.bcs.as_slice()).ok())
        .map(Address::from))
}

/// Example 2: Reverse lookup - resolve an address to its IOTA name.
///
/// Gets the registry from the IotaNames object and calls
/// `reverse_lookup` to find the name associated with a given address.
async fn reverse_lookup(client: &Client, address: Address) -> Result<()> {
    let pkg = Address::from_str(IOTA_NAMES_PACKAGE)?;
    let obj = ObjectId::from_str(IOTA_NAMES_OBJECT)?;
    let sender = Address::from_str("0x0")?;

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    // Get the shared registry (mutable access needed)
    builder
        .move_call(pkg, "iota_names", "registry")
        .arguments([SharedMut(obj)])
        .type_tags([registry_type_tag(pkg)])
        .assign("registry");

    // Reverse lookup: address -> Option<Name>
    builder
        .move_call(pkg, "registry", "reverse_lookup")
        .arguments((assigned("registry"), address))
        .assign("name_opt");

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        println!("  Reverse lookup failed (address may not have a name set): {err}");
    } else {
        // The result is an Option<Name>. We can check if it's Some by
        // inspecting the BCS bytes. A non-empty Option in BCS starts with 0x01.
        if let Some(rv) = res
            .results
            .last()
            .and_then(|effect| effect.return_values.first())
        {
            if rv.bcs.first() == Some(&1) {
                println!("  Address {address} has a reverse name record");
            } else {
                println!("  Address {address} does not have a reverse name record");
            }
        }
    }

    Ok(())
}

/// Example 3: Query name record details.
///
/// Retrieves the full NameRecord for a given name, including:
/// - Target address
/// - Expiration timestamp (milliseconds since epoch)
async fn name_record_details(client: &Client, name: &str) -> Result<()> {
    let pkg = Address::from_str(IOTA_NAMES_PACKAGE)?;
    let obj = ObjectId::from_str(IOTA_NAMES_OBJECT)?;
    let sender = Address::from_str("0x0")?;

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    // Get the shared registry (mutable access needed for lookup)
    builder
        .move_call(pkg, "iota_names", "registry")
        .arguments([SharedMut(obj)])
        .type_tags([registry_type_tag(pkg)])
        .assign("registry");

    // Create the name object
    builder
        .move_call(pkg, "name", "new")
        .arguments([name])
        .assign("name");

    // Look up the name record
    builder
        .move_call(pkg, "registry", "lookup")
        .arguments((assigned("registry"), assigned("name")))
        .assign("name_record_opt");

    // Borrow the name record from Option
    builder
        .move_call(Address::STD, "option", "borrow")
        .arguments([assigned("name_record_opt")])
        .type_tags([name_record_type_tag(pkg)])
        .assign("name_record");

    // Get the target address
    builder
        .move_call(pkg, "name_record", "target_address")
        .arguments([assigned("name_record")])
        .assign("target_address_opt");

    // Get the expiration timestamp
    builder
        .move_call(pkg, "name_record", "expiration_timestamp_ms")
        .arguments([assigned("name_record")])
        .assign("expiration");

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("Name record query failed: {err}");
    }

    println!("  Name record details for '{name}':");

    for effect in &res.results {
        for rv in &effect.return_values {
            if let TypeTag::U64 = &rv.type_tag {
                if rv.bcs.len() == 8 {
                    let timestamp =
                        u64::from_le_bytes(rv.bcs.as_slice().try_into().unwrap_or_default());
                    println!("  Expiration timestamp (ms): {timestamp}");
                }
            }
        }
    }

    // Extract the target address from the Option<address> result
    // The target_address_opt result is the 5th move call (index 4)
    if let Some(rv) = res
        .results
        .get(4)
        .and_then(|effect| effect.return_values.first())
    {
        // Option<address> in BCS: 0x01 + 32 bytes if Some, 0x00 if None
        if rv.bcs.first() == Some(&1) && rv.bcs.len() == 33 {
            let addr = Address::from(
                TryInto::<[u8; 32]>::try_into(&rv.bcs[1..33]).unwrap_or_default(),
            );
            println!("  Target address: {addr}");
        } else {
            println!("  Target address: not set");
        }
    }

    Ok(())
}

/// Example 4: Check if a name exists in the registry.
async fn check_name_exists(client: &Client, name: &str) -> Result<bool> {
    let pkg = Address::from_str(IOTA_NAMES_PACKAGE)?;
    let obj = ObjectId::from_str(IOTA_NAMES_OBJECT)?;
    let sender = Address::from_str("0x0")?;

    let mut builder = TransactionBuilder::new(sender).with_client(client.clone());

    // Get the shared registry (mutable access needed)
    builder
        .move_call(pkg, "iota_names", "registry")
        .arguments([SharedMut(obj)])
        .type_tags([registry_type_tag(pkg)])
        .assign("registry");

    // Create the name object
    builder
        .move_call(pkg, "name", "new")
        .arguments([name])
        .assign("name");

    // Check if the name has a record
    builder
        .move_call(pkg, "registry", "has_record")
        .arguments((assigned("registry"), assigned("name")))
        .assign("exists");

    let res = builder.dry_run(true).await?;

    if let Some(err) = res.error {
        eyre::bail!("has_record check failed: {err}");
    }

    Ok(res
        .results
        .last()
        .and_then(|effect| effect.return_values.first())
        .filter(|rv| matches!(rv.type_tag, TypeTag::Bool))
        .map(|rv| rv.bcs.first().copied() == Some(1))
        .unwrap_or(false))
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();
    let name = "name.iota";

    println!("=== IOTA Names Examples ===\n");

    // Example 1: Name lookup (name -> address)
    println!("1. Looking up '{name}'...");
    match lookup_name(&client, name).await? {
        Some(address) => {
            println!("   Resolved to: {address}\n");

            // Example 2: Reverse lookup (address -> name)
            println!("2. Reverse lookup for {address}...");
            reverse_lookup(&client, address).await?;
            println!();
        }
        None => {
            println!("   Name not found or expired\n");
            println!("2. Skipping reverse lookup (no address to look up)\n");
        }
    }

    // Example 3: Name record details
    println!("3. Querying name record details for '{name}'...");
    name_record_details(&client, name).await?;
    println!();

    // Example 4: Check if names exist
    println!("4. Checking name existence...");
    let exists = check_name_exists(&client, name).await?;
    println!("   '{name}' exists: {exists}");

    let fake_name = "this-name-probably-does-not-exist-12345.iota";
    let exists = check_name_exists(&client, fake_name).await?;
    println!("   '{fake_name}' exists: {exists}");

    Ok(())
}
