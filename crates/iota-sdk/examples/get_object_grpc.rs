// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! gRPC counterpart to `get_object.rs`.
//!
//! Highlights two things about the gRPC API:
//! - `get_objects` is batched (it takes an iterable of ids and streams the
//!   matched objects back), so we just hand it one id.
//! - The returned proto `Object` is *lazy* — you convert into the SDK type only
//!   when you need the deserialized fields.

use eyre::{Result, bail};
use iota_sdk::{
    grpc_client::{Client, read_mask_fields::ObjectReadMask},
    types::{ObjectId, Owner},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    let object_id: ObjectId =
        "0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755".parse()?;

    let response = client
        .get_objects([object_id], ObjectReadMask::default())
        .await?;
    let proto_obj = response
        .body()
        .first()
        .ok_or_else(|| eyre::eyre!("missing object"))?;

    // Deserialize the proto Object into the SDK Object type.
    let obj = proto_obj.object()?;

    println!("Object ID: {}", obj.id());
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
            iota_sdk::types::ObjectType::Package => "Package".to_owned(),
            iota_sdk::types::ObjectType::Struct(tag) => format!("{tag}"),
        }
    );
    println!("BCS bytes: {}", hex::encode(obj.as_struct().contents()));

    Ok(())
}
