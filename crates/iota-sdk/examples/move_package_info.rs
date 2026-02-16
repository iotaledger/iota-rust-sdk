// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: Query Move Package Information
//!
//! This example demonstrates how to fetch and display comprehensive information
//! about a Move package, including:
//! - Package versions
//! - Modules and their functions
//! - Dependencies
//! - Types defined in the package
//! - Example objects of those types

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{graphql_client::Client, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    // Example package ID (replace with actual package ID)
    let package_id =
        Address::from_str("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")?;

    println!("Fetching information for package: {}\n", package_id);

    // Fetch the package object
    let Some(package) = client.package(package_id, None).await? else {
        eyre::bail!("Package not found at address: {}", package_id)
    };

    // Display package version
    println!("=== Package Version ===");
    println!("Current version: {}", package.version);
    println!();

    // Display modules and their functions
    println!("=== Modules ===");
    for (module_id, module) in package.modules {
        println!("Module: {}", module_id);

        // Fetch detailed module information
        if let Some(normalized_module) = client
            .normalized_move_module(
                package_id,
                module_id.as_str(),
                None,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await?
        {
            // Display functions
            if let Some(functions) = normalized_module.functions {
                println!("  Functions:");
                for fun in functions.nodes {
                    println!("    - {}", fun.name);
                }
            }

            // Display structs/types
            if let Some(structs) = normalized_module.structs {
                println!("  Types:");
                for struct_def in structs.nodes {
                    println!("    - {}", struct_def.name);

                    // Try to find example objects of this type
                    if let Ok(Some(objects)) = client
                        .objects_by_type(
                            format!("{}::{}::{}", package_id, module_id, struct_def.name),
                            Some(3), // Limit to 3 examples
                            None,
                        )
                        .await
                    {
                        if !objects.is_empty() {
                            println!("      Example objects:");
                            for obj in objects {
                                println!("        - Object ID: {}", obj.object_id());
                            }
                        }
                    }
                }
            }
        }
        println!();
    }

    // Display dependencies (from package's previous transaction)
    if let Some(prev_tx) = package.previous_transaction {
        println!("=== Previous Transaction ===");
        println!("Transaction digest: {}", prev_tx.to_base58());
    }

    println!();
    println!("Package information fetched successfully!");

    Ok(())
}
