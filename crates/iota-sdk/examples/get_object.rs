// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_sdk::{
    graphql_client::Client,
    types::{ObjectId, ObjectType, Owner},
};

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
            Owner::Address(address) => format!("Address({address})"),
            Owner::Object(object_id) => format!("Object({object_id})"),
            Owner::Shared(version) => format!("Shared({version})"),
            Owner::Immutable => "Immutable".to_owned(),
            _ => bail!("unknown owner type"),
        }
    );
    println!("Storage rebate: {}", obj.storage_rebate());
    println!(
        "Type: {}",
        match obj.object_type() {
            ObjectType::Package => "Package".to_owned(),
            ObjectType::Struct(tag) => format!("{tag}"),
        }
    );
    println!("BCS bytes: {}", hex::encode(&obj.as_struct().contents));

    Ok(())
}
