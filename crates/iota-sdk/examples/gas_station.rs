// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use eyre::Result;
use iota_sdk::{
    crypto::ed25519::Ed25519PrivateKey, graphql_client::GraphQLClient,
    transaction_builder::GasStation, types::Address,
};
use reqwest::header::{AUTHORIZATION, HeaderValue};

#[tokio::main]
async fn main() -> Result<()> {
    // The SDK selects its own rustls provider, so `reqwest` has no default to
    // fall back on and the clients built below would panic without this.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let client = GraphQLClient::new_localnet();
    let gas_station_auth_token = "test";
    let keypair = Ed25519PrivateKey::random();
    let sender = keypair.public_key().derive_address();

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
