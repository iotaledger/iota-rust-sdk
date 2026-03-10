// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let parent_object_id =
        "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec".parse()?;
    let dynamic_fields_page = client
        .dynamic_fields(parent_object_id, Default::default())
        .await?;
    println!("{:#?}", dynamic_fields_page.page_info());
    println!("Page size: {}", dynamic_fields_page.data().len());
    println!(
        "First field name:\n{}",
        serde_json::to_string_pretty(&dynamic_fields_page.data().first().unwrap().name)?
    );
    println!(
        "First field value:\n{}",
        serde_json::to_string_pretty(&dynamic_fields_page.data().first().unwrap().value_as_json)?
    );

    Ok(())
}
