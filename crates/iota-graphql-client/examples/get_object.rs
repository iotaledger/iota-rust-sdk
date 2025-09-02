// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_types::ObjectId;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let object_id =
        ObjectId::from_str("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")?;

    let object_json = client
        .move_object_contents(object_id, None)
        .await?
        .context("missing object")?;

    println!("Domain: {}", object_json["domain_name"]);

    Ok(())
}
