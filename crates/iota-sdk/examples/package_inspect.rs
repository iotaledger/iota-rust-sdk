// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::env;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{
        Client,
        pagination::{Direction, PaginationFilter},
        query_types::ObjectFilter,
    },
    types::{Address, MovePackage},
};

fn forward_page(cursor: Option<String>) -> PaginationFilter {
    PaginationFilter {
        direction: Direction::Forward,
        cursor,
        limit: None,
    }
}

async fn fetch_package_versions(
    client: &Client,
    package_address: Address,
) -> Result<Vec<MovePackage>> {
    let mut packages = Vec::new();
    let mut cursor = None;

    loop {
        let page = client
            .package_versions(package_address, forward_page(cursor.clone()), None, None)
            .await?;

        packages.extend(page.data);

        if page.page_info.has_next_page {
            cursor = page.page_info.end_cursor;
        } else {
            break;
        }
    }

    packages.sort_by_key(|package| package.version);
    Ok(packages)
}

async fn print_object_samples(client: &Client, type_tag: &str, is_generic: bool) -> Result<()> {
    if is_generic {
        println!("    sample objects: skipped for generic type");
        return Ok(());
    }

    let objects = client
        .objects(
            ObjectFilter {
                type_: Some(type_tag.to_owned()),
                ..Default::default()
            },
            forward_page(None),
        )
        .await?;

    if objects.data.is_empty() {
        println!("    sample objects: none found");
    } else {
        println!("    sample objects:");
        for object in &objects.data {
            println!(
                "      - {} (version {})",
                object.object_id(),
                object.version()
            );
        }
        if objects.page_info.has_next_page {
            println!("      - ...");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let package_id = env::args()
        .nth(1)
        .ok_or_eyre("Usage: cargo run -p iota-sdk --example package_inspect -- <PACKAGE_ID>")?;

    let package_address = Address::from_hex(&package_id)?;
    let client = Client::new_testnet();

    let package = client
        .package(package_address, None)
        .await?
        .ok_or_eyre("missing package")?;
    let latest_package = client
        .package_latest(package_address)
        .await?
        .ok_or_eyre("missing latest package")?;
    let versions = fetch_package_versions(&client, package_address).await?;

    println!("Requested package id: {package_id}");
    println!("Resolved package id: {}", package.id);
    println!("Resolved version: {}", package.version);
    println!(
        "Latest version: {} ({})",
        latest_package.version, latest_package.id
    );
    println!();

    println!("Versions:");
    for version in &versions {
        let mut labels = Vec::new();
        if version.id == package.id {
            labels.push("requested");
        }
        if version.id == latest_package.id {
            labels.push("latest");
        }

        if labels.is_empty() {
            println!("- v{} -> {}", version.version, version.id);
        } else {
            println!(
                "- v{} -> {} [{}]",
                version.version,
                version.id,
                labels.join(", ")
            );
        }
    }
    println!();

    println!("Dependencies:");
    let mut dependencies = package.linkage_table.iter().collect::<Vec<_>>();
    dependencies.sort_by_key(|(original_id, _)| original_id.to_hex());

    if dependencies.is_empty() {
        println!("- none");
    } else {
        for (original_id, upgrade) in dependencies {
            println!(
                "- {} -> {} @ v{}",
                original_id, upgrade.upgraded_id, upgrade.upgraded_version
            );
        }
    }
    println!();

    println!("Modules, functions, and types:");
    let module_page = forward_page(None);
    let package_type_prefix = package.id.to_hex();

    let mut module_names = package
        .modules
        .keys()
        .map(|module_id| module_id.as_str())
        .collect::<Vec<_>>();
    module_names.sort_unstable();

    for module_name in module_names {
        println!("Module: {module_name}");

        let Some(module) = client
            .normalized_move_module(
                package_address,
                module_name,
                None,
                module_page.clone(),
                module_page.clone(),
                module_page.clone(),
                module_page.clone(),
            )
            .await?
        else {
            println!("  metadata: missing");
            println!();
            continue;
        };

        if let Some(functions) = &module.functions {
            if functions.nodes.is_empty() {
                println!("  functions: none");
            } else {
                println!("  functions:");
                for function in &functions.nodes {
                    println!("    - {function}");
                }
                if functions.page_info.has_next_page {
                    println!("    - ...");
                }
            }
        } else {
            println!("  functions: none");
        }

        if let Some(structs) = &module.structs {
            if structs.nodes.is_empty() {
                println!("  types: none");
            } else {
                println!("  types:");
                for struct_ in &structs.nodes {
                    let type_tag =
                        format!("{package_type_prefix}::{module_name}::{}", struct_.name);
                    println!("    - {type_tag}");
                    let is_generic = struct_
                        .type_parameters
                        .as_ref()
                        .is_some_and(|parameters| !parameters.is_empty());
                    print_object_samples(&client, &type_tag, is_generic).await?;
                }
                if structs.page_info.has_next_page {
                    println!("    - ...");
                }
            }
        } else {
            println!("  types: none");
        }

        println!();
    }

    Ok(())
}
