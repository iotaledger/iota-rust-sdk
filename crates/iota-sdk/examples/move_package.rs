// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{Result, eyre};
use iota_sdk::{
    graphql_client::{Client, pagination::PaginationFilter, query_types::ObjectFilter},
    types::Address,
};

const PACKAGE_ADDRESS: &str = "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f";

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();
    let package_address = Address::from_str(PACKAGE_ADDRESS)?;

    let Some(package) = client.package(package_address, None).await? else {
        return Err(eyre!("no package found for {PACKAGE_ADDRESS}"));
    };

    println!("Package ID: {}", package.id);
    println!("Current version: {}", package.version);
    println!();

    let mut versions = client
        .package_versions(
            package_address,
            PaginationFilter {
                limit: Some(50),
                ..Default::default()
            },
            None,
            None,
        )
        .await?
        .data;
    versions.sort_by_key(|p| p.version);

    println!("Package versions:");
    for v in versions {
        let marker = if v.id == package.id && v.version == package.version {
            " (current)"
        } else {
            ""
        };
        println!("- id={} version={}{}", v.id, v.version, marker);
    }
    println!();

    println!("Dependencies:");
    if package.linkage_table.is_empty() {
        println!("- none");
    } else {
        for (original_id, info) in &package.linkage_table {
            println!(
                "- {} -> {} (version {})",
                original_id, info.upgraded_id, info.upgraded_version
            );
        }
    }
    println!();

    let mut module_ids = package
        .modules
        .keys()
        .map(|id| id.as_str().to_owned())
        .collect::<Vec<_>>();
    module_ids.sort();

    for module_id in module_ids {
        let Some(module) = client
            .normalized_move_module(
                package_address,
                &module_id,
                Some(package.version),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await?
        else {
            println!("Module: {module_id} (not found)");
            continue;
        };

        println!("Module: {module_id}");

        println!("Functions:");
        match module.functions {
            Some(functions) if !functions.nodes.is_empty() => {
                for fun in functions.nodes {
                    println!("- {fun}");
                }
            }
            _ => println!("- none"),
        }

        println!("Types (with sample object if available):");
        match module.structs {
            Some(structs) if !structs.nodes.is_empty() => {
                for struct_ in structs.nodes {
                    let type_tag = format!("{}::{}::{}", package.id, module_id, struct_.name);
                    let sample_objects = client
                        .objects(
                            ObjectFilter {
                                type_: Some(type_tag),
                                ..Default::default()
                            },
                            PaginationFilter {
                                limit: Some(1),
                                ..Default::default()
                            },
                        )
                        .await?;

                    if let Some(sample_object) = sample_objects.data.first() {
                        println!(
                            "- {} (example object: {})",
                            struct_.name,
                            sample_object.object_id()
                        );
                    } else {
                        println!("- {} (no example object found)", struct_.name);
                    }
                }
            }
            _ => println!("- none"),
        }

        println!();
    }

    Ok(())
}
