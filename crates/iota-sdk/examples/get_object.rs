// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::{OptionExt, Result, bail};
use iota_sdk::graphql_client::{Client, faucet::FaucetClient};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let address = "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522".parse()?;
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(address, &client)
        .await?;
    let object_id = *client
        .coins(address, None, Default::default())
        .await?
        .data()
        .first()
        .ok_or_eyre("address has no coins after faucet request")?
        .id();

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
