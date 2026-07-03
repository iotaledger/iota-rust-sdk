// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_sdk::{graphql_client::Client, types::ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let object_id =
        ObjectId::from_str("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")?;

    let obj = client
        .object(object_id, None)
        .await?
        .ok_or_eyre("missing object")?;

    println!("Object ID: {}", obj.id());
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
            _ => bail!("unknown owner type"),
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
    println!("BCS bytes: {}", hex::encode(obj.as_struct().contents()));

    Ok(())
}
