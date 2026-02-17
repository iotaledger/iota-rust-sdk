// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: inspect object relationships.
//!
//! Demonstrates common relationship patterns:
//! - object -> owner (address/object/shared/immutable)
//! - parent object -> dynamic fields (child relationships)
//!
//! Set OBJECT_ID to inspect a specific on-chain object.

use std::{env::var, str::FromStr};

use eyre::{OptionExt, Result, bail};
use iota_sdk::{graphql_client::Client, types::ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let object_id = ObjectId::from_str(
        &var("OBJECT_ID").map_err(|_| eyre::eyre!("OBJECT_ID env var is required"))?,
    )?;

    let obj = client
        .object(object_id, None)
        .await?
        .ok_or_eyre("missing object")?;

    println!("Object ID: {}", obj.object_id());
    println!("Version: {}", obj.version());
    println!(
        "Owner relationship: {}",
        match obj.owner() {
            iota_types::Owner::Address(address) => format!("Address({address})"),
            iota_types::Owner::Object(parent_object) => format!("Object({parent_object})"),
            iota_types::Owner::Shared(version) => format!("Shared(initial_version={version})"),
            iota_types::Owner::Immutable => "Immutable".to_owned(),
            _ => bail!("unknown owner type"),
        }
    );

    // If this object is a parent object, dynamic fields describe child relations.
    let dynamic_fields = client
        .dynamic_fields(object_id.into(), Default::default())
        .await?;
    println!("Dynamic field relationships found: {}", dynamic_fields.data().len());

    for (idx, field) in dynamic_fields.data().iter().take(5).enumerate() {
        println!("- [{}] name: {}", idx, serde_json::to_string(&field.name)?);
        println!("      value: {}", serde_json::to_string(&field.value_as_json)?);
    }

    Ok(())
}
