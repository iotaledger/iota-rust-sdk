// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    graphql_client::{error::Result, pagination::PaginationFilter, Client},
    types::iota_names::{IotaNamesNft, NameFormat},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let name = "name.iota";
    println!("Resolving name: {name}");

    let Some(resolved_address) = client.iota_names_lookup(name).await? else {
        println!("No address resolved for {name}");
        return Ok(());
    };
    println!("Resolved address: {resolved_address}");

    let default_name_dot = client
        .iota_names_default_name(resolved_address.clone(), Some(NameFormat::Dot))
        .await?;
    match default_name_dot {
        Some(default_name) => println!("Default name (dot): {default_name}"),
        None => println!("No default dot-format name found"),
    }

    let default_name_at = client
        .iota_names_default_name(resolved_address.clone(), Some(NameFormat::At))
        .await?;
    match default_name_at {
        Some(default_name) => {
            println!("Default name (at): {}", default_name.format(NameFormat::At))
        }
        None => println!("No default at-format name found"),
    }

    let registrations = client
        .iota_names_registrations(
            resolved_address,
            PaginationFilter {
                limit: Some(10),
                ..Default::default()
            },
        )
        .await?;

    if registrations.is_empty() {
        println!("No IOTA Names registrations found for this address");
        return Ok(());
    }

    println!("Registrations ({}):", registrations.data().len());
    for registration in registrations.data() {
        println!(
            "- {} (id: {}, expires_at_ms: {})",
            registration.name_str(),
            registration.id(),
            registration.expiration_timestamp_ms()
        );
    }

    Ok(())
}
