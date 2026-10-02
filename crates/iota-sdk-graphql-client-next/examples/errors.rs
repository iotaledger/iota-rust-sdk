// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The kinds of errors the client reports, and which are worth retrying.

use std::time::Duration;

use eyre::Result;
use iota_sdk_graphql_client_next::{Error, GraphQLClient, RetryPolicy};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    // The server rejects pages larger than its maximum.
    match client.events().first(1000).await {
        Err(Error::Server(errors)) => {
            for error in errors.errors() {
                println!(
                    "Server error: {} (code {:?})",
                    error.message(),
                    error.code()
                );
            }
            println!("Bad input: {}", errors.has_code("BAD_USER_INPUT"));
        }
        other => println!("Unexpected result: {other:?}"),
    }

    // Nothing listens on this port, so the request does not reach a server.
    let unreachable = GraphQLClient::builder("http://127.0.0.1:9")
        .timeout(Duration::from_secs(2))
        .retry(RetryPolicy::none())
        .build()?;
    match unreachable.chain_id().await {
        Err(error) => println!("{error} (retryable: {})", error.is_retryable()),
        Ok(chain_id) => println!("Unexpected chain ID: {chain_id}"),
    }

    // An invalid endpoint fails before anything is sent.
    if let Err(Error::InvalidInput(message)) = GraphQLClient::new("localhost:9125") {
        println!("Invalid input: {message}");
    }

    Ok(())
}
