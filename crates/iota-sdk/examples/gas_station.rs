// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use eyre::Result;
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey, graphql_client::Client, transaction_builder::GasStation,
    types::Address,
};
use reqwest::header::{AUTHORIZATION, HeaderValue};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();
    let gas_station_auth_token = "test";
    let keypair = Ed25519PrivateKey::random();
    let sender = keypair.public_key().derive_address();

    // A gas station is configured once and reused for any number of
    // transactions. Pass `.http_client(..)` to control timeouts, proxies or
    // TLS roots.
    let station = GasStation::builder("http://0.0.0.0:9527".parse()?)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {gas_station_auth_token}"))?,
        )
        .reservation_duration(Duration::from_secs(60))
        .build();

    let mut builder = client.transaction_builder(sender);
    builder
        .move_call(Address::STD, "u64", "sqrt")
        .arguments([64_u64]);

    let effects = builder.execute_with_gas_sponsor(&station, &keypair).await?;
    println!("{effects:#?}");

    println!("Sponsored transaction was successful!");

    Ok(())
}
