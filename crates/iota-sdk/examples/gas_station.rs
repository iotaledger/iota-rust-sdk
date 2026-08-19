// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{crypto::ed25519::Ed25519PrivateKey, graphql_client::Client, types::Address};
use reqwest::header::HeaderValue;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();
    let gas_station_url = reqwest::Url::parse("http://0.0.0.0:9527")?;
    let gas_station_auth_token = "test";
    let keypair = Ed25519PrivateKey::random();
    let sender = keypair.public_key().derive_address();

    let mut builder = client.transaction_builder(sender);

    builder
        .move_call(Address::STD, "u64", "sqrt")
        .arguments([64_u64])
        .gas_station_sponsor(gas_station_url)
        .add_gas_station_header(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {gas_station_auth_token}"))?,
        );

    let effects = builder.execute(&keypair, None).await?;
    println!("{effects:#?}");

    println!("Sponsored transaction was successful!");

    Ok(())
}
