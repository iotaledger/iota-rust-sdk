// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test utilities shared across the crate.

use crate::GraphQLClient;

/// Number of coins expected from a faucet request.
pub const NUM_COINS_FROM_FAUCET: usize = 5;

/// Create a test client based on the NETWORK environment variable.
pub fn test_client() -> GraphQLClient {
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "local".to_string());
    match network.as_str() {
        "mainnet" => GraphQLClient::new_mainnet(),
        "testnet" => GraphQLClient::new_testnet(),
        "devnet" => GraphQLClient::new_devnet(),
        "local" => GraphQLClient::new_localnet(),
        _ => GraphQLClient::new(&network).expect("Invalid network URL: {network}"),
    }
}

/// A pagination filter whose every field differs from the default, so a
/// query that drops it sends different variables.
pub fn backward_page() -> crate::PaginationFilter {
    crate::PaginationFilter {
        direction: crate::Direction::Backward,
        cursor: Some("cursor".to_owned()),
        limit: Some(7),
    }
}

/// Run `send` against a local server that answers every request with `{}`,
/// and return the variables of the first request that is not the service
/// config query, which pagination sends first.
pub async fn sent_variables<Fut: Future>(
    send: impl FnOnce(GraphQLClient) -> Fut,
) -> serde_json::Value {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = GraphQLClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = async {
        loop {
            let request = answer_one_request(&listener).await;
            if request["operationName"] != "ServiceConfigQueryFragment" {
                break request["variables"].clone();
            }
        }
    };
    let (variables, _) = tokio::join!(server, send(client));
    variables
}

async fn answer_one_request(listener: &tokio::net::TcpListener) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    let body = loop {
        let mut chunk = [0; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed before the request body");
        request.extend_from_slice(&chunk[..read]);
        let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .expect("request without content-length")
            .trim()
            .parse()
            .unwrap();
        if request.len() >= end + 4 + length {
            break request[end + 4..end + 4 + length].to_vec();
        }
    };
    stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

pub fn assert_backward_page(variables: &serde_json::Value) {
    assert_eq!(variables["before"], "cursor");
    assert_eq!(variables["last"], 7);
    assert!(variables["after"].is_null());
    assert!(variables["first"].is_null());
}
