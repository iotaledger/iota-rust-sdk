// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result, bail};
use iota_sdk_graphql_client_next::{
    GraphQLClient,
    iota_types::{ObjectId, ObjectType, Owner},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    let object_id =
        ObjectId::from_str("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")?;

    let object = client
        .object(object_id)
        .await?
        .ok_or_eyre("missing object")?;

    println!("Object ID: {}", object.id());
    println!("Version: {}", object.version());
    println!(
        "Previous transaction: {}",
        object.previous_transaction().to_base58()
    );
    println!(
        "Owner: {}",
        match object.owner() {
            Owner::Address(address) => format!("Address({address})"),
            Owner::Object(object_id) => format!("Object({object_id})"),
            Owner::Shared(version) => format!("Shared({version})"),
            Owner::Immutable => "Immutable".to_owned(),
            _ => bail!("unknown owner type"),
        }
    );
    println!("Storage rebate: {}", object.storage_rebate());
    println!(
        "Type: {}",
        match object.object_type() {
            ObjectType::Package => "Package".to_owned(),
            ObjectType::Struct(tag) => format!("{tag}"),
            other => format!("{other}"),
        }
    );

    // The same version again, this time only the JSON rendering of its
    // contents.
    let contents = client
        .object(object_id)
        .version(object.version())
        .json()
        .await?
        .ok_or_eyre("missing object contents")?;
    println!("Contents: {contents:#}");

    Ok(())
}
