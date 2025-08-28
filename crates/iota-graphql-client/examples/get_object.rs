// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{Context, Result};
use iota_graphql_client::Client;
use iota_types::ObjectId;
use serde::Deserialize;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let object_id =
        ObjectId::from_str("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")?;

    let object = client
        .object(object_id, None)
        .await?
        .context("missing object")?;

    let bytes = &object.as_struct().contents;

    println!("{}", object.as_struct().type_);

    let registration = bcs::from_bytes::<IotaNamesRegistration>(bytes)?;

    println!("registration name: {}", registration.name_str);

    Ok(())
}

#[derive(Deserialize)]
#[expect(unused)]
struct IotaNamesRegistration {
    id: ObjectId,
    name: Name,
    name_str: String,
    expiration_timestamp: u64,
}

#[derive(Deserialize)]
#[expect(unused)]
struct Name {
    labels: Vec<String>,
}
