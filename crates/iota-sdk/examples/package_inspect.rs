// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::env;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{
        pagination::{Direction, PaginationFilter},
        query_types::{MoveAbility, ObjectFilter, TransactionsFilter},
        Client,
    },
    types::{Address, MovePackage, ObjectId, StructTag, UpgradePolicy},
};

fn forward_page(cursor: Option<String>) -> PaginationFilter {
    PaginationFilter {
        direction: Direction::Forward,
        cursor,
        limit: None,
    }
}

fn format_function_signature(signature: &str, package_type_prefix: &str) -> String {
    signature.replace(&format!("{package_type_prefix}::"), "")
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

async fn print_object_samples(
    client: &Client,
    type_tag: &str,
    has_key_ability: bool,
    is_generic: bool,
) -> Result<()> {
    if !has_key_ability {
        return Ok(());
    }

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
            PaginationFilter {
                limit: Some(3),
                ..forward_page(None)
            },
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

fn format_policy_name(policy: u8) -> String {
    match UpgradePolicy::try_from(policy) {
        Ok(UpgradePolicy::Compatible) => "Compatible".to_owned(),
        Ok(UpgradePolicy::Additive) => "Additive".to_owned(),
        Ok(UpgradePolicy::DepOnly) => "Dependency-only".to_owned(),
        Ok(_) | Err(()) => format!("Unknown ({policy})"),
    }
}

fn extract_policy_value(contents: &serde_json::Value) -> Option<u8> {
    match contents.get("policy")? {
        serde_json::Value::Number(number) => {
            number.as_u64().and_then(|value| u8::try_from(value).ok())
        }
        serde_json::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

async fn resolve_upgrade_cap_id(client: &Client, package_id: ObjectId) -> Result<Option<ObjectId>> {
    let effects_page = client
        .transactions_effects(
            TransactionsFilter {
                changed_object: Some(package_id),
                ..Default::default()
            },
            PaginationFilter {
                direction: Direction::Forward,
                cursor: None,
                limit: Some(1),
            },
        )
        .await?;

    for effects in effects_page.data {
        let effects_v1 = effects.as_v1();

        for changed_object in &effects_v1.changed_objects {
            if !changed_object.output_state.is_object_write() {
                continue;
            }

            let Some(object) = client
                .object(changed_object.object_id, Some(effects_v1.lamport_version))
                .await?
            else {
                continue;
            };

            if object
                .as_struct_opt()
                .is_some_and(|move_struct| move_struct.type_ == StructTag::new_upgrade_cap())
            {
                return Ok(Some(changed_object.object_id));
            }
        }
    }

    Ok(None)
}

async fn current_package_policy(client: &Client, package_id: ObjectId) -> Result<String> {
    let Some(upgrade_cap_id) = resolve_upgrade_cap_id(client, package_id).await? else {
        return Ok("Unavailable".to_owned());
    };

    let Some(contents) = client.move_object_contents(upgrade_cap_id, None).await? else {
        return Ok("Unavailable".to_owned());
    };

    Ok(extract_policy_value(&contents)
        .map(format_policy_name)
        .unwrap_or_else(|| "Unavailable".to_owned()))
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
    println!(
        "Current package policy: {}",
        current_package_policy(&client, package.id).await?
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
                    println!(
                        "    - {}",
                        format_function_signature(&function.to_string(), &package_type_prefix)
                    );
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
                    let has_key_ability = struct_.abilities.as_ref().is_some_and(|abilities| {
                        abilities
                            .iter()
                            .any(|ability| matches!(ability, MoveAbility::Key))
                    });
                    let is_generic = struct_
                        .type_parameters
                        .as_ref()
                        .is_some_and(|parameters| !parameters.is_empty());
                    print_object_samples(&client, &type_tag, has_key_ability, is_generic)
                        .await?;
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
