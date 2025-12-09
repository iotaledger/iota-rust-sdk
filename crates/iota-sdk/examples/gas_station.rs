// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_crypto::ed25519::Ed25519PrivateKey;
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::Address;
use reqwest::header::HeaderValue;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();
    let gas_station_url = reqwest::Url::parse("http://0.0.0.0:9527")?;
    let gas_station_auth_token = "test";
    let keypair = Ed25519PrivateKey::generate(rand::thread_rng());
    let sender = keypair.public_key().derive_address();

    let mut builder = TransactionBuilder::new(sender).with_client(&client);

    builder
        .move_call(Address::STD_LIB, "u64", "sqrt")
        .arguments([64_u64])
        .gas_station_sponsor(gas_station_url)
        .add_gas_station_header(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {gas_station_auth_token}"))?,
        );

    let effects = builder.execute(&keypair.into(), None).await?;

    println!("{effects:#?}");

    println!("Sponsored transaction was successful!");

    Ok(())
}
