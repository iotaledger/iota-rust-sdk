// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Configure the client's headers, timeouts and retries, with the built-in
//! transport or a `reqwest::Client` of your own.

use std::time::Duration;

use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, RetryPolicy};

const TESTNET: &str = "https://graphql.testnet.iota.cafe";

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::builder(TESTNET)
        .header("x-request-source", "configuration-example")
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .retry(RetryPolicy::new(5).with_backoff(Duration::from_millis(100), Duration::from_secs(1)))
        .build()?;
    println!("Chain ID: {}", client.chain_id().await?);
    if let Some(version) = client.server_version() {
        println!("Server version: {version}");
    }

    // A `reqwest::Client` of your own, e.g. to set a proxy or a TLS backend.
    // The client's headers, timeout and retries still apply to its requests.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(2)
        .build()?;
    let client = GraphQLClient::builder(TESTNET)
        .reqwest_client(http)
        .header("x-request-source", "configuration-example")
        .timeout(Duration::from_secs(10))
        .build()?;
    println!("Chain ID: {}", client.chain_id().await?);

    Ok(())
}
