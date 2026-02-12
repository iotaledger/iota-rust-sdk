// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, query_types::ObjectFilter},
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let package_address =
        Address::from_str("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")?;

    let package_versions = client
        .package_versions(package_address, Default::default(), None, None)
        .await?;
    if package_versions.data.is_empty() {
        eyre::bail!("no package versions found")
    }

    let mut versions: Vec<u64> = package_versions.data.iter().map(|pkg| pkg.version()).collect();
    versions.sort_unstable();
    println!("Versions: {versions:?}");

    let Some(latest_package) = client.package_latest(package_address).await? else {
        eyre::bail!("latest package not found")
    };

    println!("Latest package id: {}", latest_package.id());
    println!("Latest package version: {}", latest_package.version());

    let dependencies = latest_package.linkage_table();
    if dependencies.is_empty() {
        println!("Dependencies: none");
    } else {
        println!("Dependencies:");
        for dependency in dependencies.keys() {
            println!("- {dependency}");
        }
    }

    for (module_id, _) in latest_package.modules() {
        let Some(module) = client
            .normalized_move_module(
                package_address,
                module_id.as_str(),
                Some(latest_package.version()),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await?
        else {
            continue;
        };

        println!("\nModule: {module_id}");

        if let Some(functions) = module.functions {
            println!("Functions: {}", functions.nodes.len());
        }

        if let Some(structs) = module.structs {
            println!("Structs: {}", structs.nodes.len());
            for move_struct in structs.nodes.iter().take(2) {
                let struct_type = format!("{}::{module_id}::{}", latest_package.id(), move_struct.name);
                let objects = client
                    .objects(
                        ObjectFilter {
                            type_: Some(struct_type.clone()),
                            ..Default::default()
                        },
                        Default::default(),
                    )
                    .await?;
                if let Some(obj) = objects.data.first() {
                    println!("- {} -> example object {}", move_struct.name, obj.object_id());
                } else {
                    println!("- {} -> no objects found", move_struct.name);
                }
            }
        }
    }

    Ok(())
}
