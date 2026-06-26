// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This example inspects a published Move package on testnet and prints its
//! upgrade policy, version history, dependencies, functions, types, and sample
//! objects.

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::{
        Client,
        pagination::{Direction, PaginationFilter},
        query_types::{MoveAbility, ObjectFilter, TransactionsFilter},
    },
    types::{Address, Input, MoveCall, MovePackage, ObjectId, Transaction, UpgradePolicy},
};

#[tokio::main]
async fn main() -> Result<()> {
    let package_id = "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d";
    let package_address = Address::from_hex(package_id)?;
    let client = Client::new_testnet();

    // Fetch package metadata and version history.
    let package = client
        .package(package_address, None)
        .await?
        .ok_or_eyre("missing package")?;
    let latest_package = client
        .package_latest(package_address)
        .await?
        .ok_or_eyre("missing latest package")?;
    let versions = fetch_package_versions(&client, package_address).await?;

    println!(
        "Latest version: {} ({})",
        latest_package.version, latest_package.id
    );
    // Resolve the current upgrade policy.
    println!(
        "Current package policy: {}",
        current_package_policy(&client, package.id).await?
    );
    println!();

    // Print the package version history.
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

    // Print package dependencies and their linked versions.
    println!("Dependencies:");
    let mut dependencies = package.linkage_table.values().collect::<Vec<_>>();
    dependencies.sort_by_key(|upgrade| upgrade.upgraded_id.to_hex());

    if dependencies.is_empty() {
        println!("- none");
    } else {
        for upgrade in dependencies {
            println!("- {} @ v{}", upgrade.upgraded_id, upgrade.upgraded_version);
        }
    }
    println!();

    // Inspect normalized modules, functions, types, and sample key objects.
    println!("Package contents:");
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
                    print_object_samples(&client, &type_tag, has_key_ability, is_generic).await?;
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

fn forward_page(cursor: Option<String>) -> PaginationFilter {
    PaginationFilter {
        direction: Direction::Forward,
        cursor,
        limit: None,
    }
}

fn shorten_package_ids(signature: &str) -> String {
    let mut shortened = String::with_capacity(signature.len());
    let bytes = signature.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'0' && bytes.get(index + 1) == Some(&b'x') {
            let mut end = index + 2;
            while bytes.get(end).is_some_and(u8::is_ascii_hexdigit) {
                end += 1;
            }

            if end > index + 2 {
                let candidate = &signature[index..end];
                match Address::from_hex(candidate) {
                    Ok(address) => shortened.push_str(&address.to_short_hex()),
                    Err(_) => shortened.push_str(candidate),
                }
                index = end;
                continue;
            }
        }

        shortened.push(char::from(bytes[index]));
        index += 1;
    }

    shortened
}

fn format_function_signature(signature: &str, package_type_prefix: &str) -> String {
    shorten_package_ids(&signature.replace(&format!("{package_type_prefix}::"), ""))
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
            println!("      - {} (version {})", object.id(), object.version());
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
                .is_some_and(|move_struct| move_struct.object_type().is_upgrade_cap())
            {
                return Ok(Some(changed_object.object_id));
            }
        }
    }

    Ok(None)
}

fn is_package_make_immutable_call(move_call: &MoveCall) -> bool {
    move_call.package == ObjectId::from(Address::FRAMEWORK)
        && move_call.module.as_str() == "package"
        && move_call.function.as_str() == "make_immutable"
}

fn publishes_package_as_immutable(tx: &Transaction) -> bool {
    let Some(programmable_tx) = tx
        .as_opt_v1()
        .and_then(|tx_v1| tx_v1.kind.as_opt_programmable())
    else {
        return false;
    };

    let publish_indexes = programmable_tx
        .commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| {
            command
                .is_publish()
                .then(|| u16::try_from(index).ok())
                .flatten()
        })
        .collect::<Vec<_>>();

    let [publish_index] = publish_indexes.as_slice() else {
        return false;
    };

    programmable_tx
        .commands
        .iter()
        .skip(usize::from(*publish_index) + 1)
        .any(|command| {
            command.as_opt_move_call().is_some_and(|move_call| {
                is_package_make_immutable_call(move_call)
                    && move_call.arguments.len() == 1
                    && move_call.arguments[0].as_result_opt() == Some(*publish_index)
            })
        })
}

fn upgrade_cap_input_indexes(tx: &Transaction, upgrade_cap_id: ObjectId) -> Vec<u16> {
    let Some(programmable_tx) = tx
        .as_opt_v1()
        .and_then(|tx_v1| tx_v1.kind.as_opt_programmable())
    else {
        return Vec::new();
    };

    programmable_tx
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let matches_upgrade_cap = match input {
                Input::ImmutableOrOwned(object_ref) | Input::Receiving(object_ref) => {
                    object_ref.object_id == upgrade_cap_id
                }
                Input::Shared(shared_object_ref) => shared_object_ref.object_id == upgrade_cap_id,
                Input::Pure { .. } => false,
                _ => false,
            };

            matches_upgrade_cap
                .then(|| u16::try_from(index).ok())
                .flatten()
        })
        .collect()
}

fn uses_upgrade_cap_for_make_immutable(tx: &Transaction, upgrade_cap_id: ObjectId) -> bool {
    let Some(programmable_tx) = tx
        .as_opt_v1()
        .and_then(|tx_v1| tx_v1.kind.as_opt_programmable())
    else {
        return false;
    };

    let upgrade_cap_inputs = upgrade_cap_input_indexes(tx, upgrade_cap_id);
    if upgrade_cap_inputs.is_empty() {
        return false;
    }

    programmable_tx.commands.iter().any(|command| {
        command.as_opt_move_call().is_some_and(|move_call| {
            is_package_make_immutable_call(move_call)
                && move_call.arguments.len() == 1
                && move_call.arguments[0]
                    .as_input_opt()
                    .is_some_and(|input_index| upgrade_cap_inputs.contains(&input_index))
        })
    })
}

async fn was_package_published_as_immutable(client: &Client, package_id: ObjectId) -> Result<bool> {
    let mut cursor = None;

    loop {
        let page = client
            .transactions_data_effects(
                TransactionsFilter {
                    changed_object: Some(package_id),
                    ..Default::default()
                },
                forward_page(cursor.clone()),
            )
            .await?;

        if page
            .data
            .iter()
            .any(|tx_data| publishes_package_as_immutable(&tx_data.tx.transaction))
        {
            return Ok(true);
        }

        if page.page_info.has_next_page {
            cursor = page.page_info.end_cursor;
        } else {
            return Ok(false);
        }
    }
}

async fn was_upgrade_cap_used_for_make_immutable(
    client: &Client,
    upgrade_cap_id: ObjectId,
) -> Result<bool> {
    let mut cursor = None;

    loop {
        let page = client
            .transactions_data_effects(
                TransactionsFilter {
                    input_object: Some(upgrade_cap_id),
                    ..Default::default()
                },
                forward_page(cursor.clone()),
            )
            .await?;

        if page.data.iter().any(|tx_data| {
            uses_upgrade_cap_for_make_immutable(&tx_data.tx.transaction, upgrade_cap_id)
        }) {
            return Ok(true);
        }

        if page.page_info.has_next_page {
            cursor = page.page_info.end_cursor;
        } else {
            return Ok(false);
        }
    }
}

async fn current_package_policy(client: &Client, package_id: ObjectId) -> Result<String> {
    let Some(upgrade_cap_id) = resolve_upgrade_cap_id(client, package_id).await? else {
        return Ok(
            if was_package_published_as_immutable(client, package_id).await? {
                "Immutable".to_owned()
            } else {
                "Unavailable".to_owned()
            },
        );
    };

    let Some(contents) = client.move_object_contents(upgrade_cap_id, None).await? else {
        return Ok(
            if was_upgrade_cap_used_for_make_immutable(client, upgrade_cap_id).await? {
                "Immutable".to_owned()
            } else {
                "Unavailable".to_owned()
            },
        );
    };

    Ok(extract_policy_value(&contents)
        .map(format_policy_name)
        .unwrap_or_else(|| "Unavailable".to_owned()))
}
