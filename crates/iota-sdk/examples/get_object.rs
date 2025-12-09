// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_graphql_client::Client;
use iota_types::ObjectId;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let object_id =
        ObjectId::from_str("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")?;

    let obj = client
        .object(object_id, None)
        .await?
        .ok_or_eyre("missing object")?;

    println!("Object ID: {}", obj.object_id());
    println!("Version: {}", obj.version());
    println!(
        "Previous transaction: {}",
        obj.previous_transaction().to_base58()
    );
    println!(
        "Owner: {}",
        match obj.owner() {
            iota_types::Owner::Address(address) => format!("Address({address})"),
            iota_types::Owner::Object(object_id) => format!("Object({object_id})"),
            iota_types::Owner::Shared(version) => format!("Shared({version})"),
            iota_types::Owner::Immutable => "Immutable".to_owned(),
        }
    );
    println!("Storage rebate: {}", obj.storage_rebate());
    println!(
        "Type: {}",
        match obj.object_type() {
            iota_types::ObjectType::Package => "Package".to_owned(),
            iota_types::ObjectType::Struct(tag) => format!("{tag}"),
        }
    );
    println!("BCS bytes: {}", hex::encode(&obj.as_struct().contents));

    Ok(())
}
