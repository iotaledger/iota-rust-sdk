// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Example: inspect a Move package object.
//!
//! Set PACKAGE_ID to a published package object id.

use std::{env::var, str::FromStr};

use eyre::{OptionExt, Result, bail};
use iota_sdk::{graphql_client::Client, types::ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let package_id = ObjectId::from_str(
        &var("PACKAGE_ID").map_err(|_| eyre::eyre!("PACKAGE_ID env var is required"))?,
    )?;

    let obj = client
        .object(package_id, None)
        .await?
        .ok_or_eyre("package object not found")?;

    match obj.object_type() {
        iota_types::ObjectType::Package => {
            println!("Package ID: {}", obj.object_id());
            println!("Version: {}", obj.version());
            println!("Previous Tx: {}", obj.previous_transaction().to_base58());
            println!("Storage rebate: {}", obj.storage_rebate());
        }
        other => bail!("object is not a package: {other:?}"),
    }

    Ok(())
}
