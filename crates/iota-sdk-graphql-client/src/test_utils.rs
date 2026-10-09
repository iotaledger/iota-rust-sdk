// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test utilities shared across the crate.

use crate::GraphQLClient;

/// Number of coins expected from a faucet request.
pub(crate) const NUM_COINS_FROM_FAUCET: usize = 5;

/// Create a test client based on the NETWORK environment variable.
pub(crate) fn test_client() -> GraphQLClient {
    let network = std::env::var("NETWORK").unwrap_or_else(|_| "local".to_string());
    match network.as_str() {
        "mainnet" => GraphQLClient::new_mainnet().unwrap(),
        "testnet" => GraphQLClient::new_testnet().unwrap(),
        "devnet" => GraphQLClient::new_devnet().unwrap(),
        "local" => GraphQLClient::new_localnet().unwrap(),
        _ => GraphQLClient::new(&network).expect("Invalid network URL: {network}"),
    }
}

/// A pagination filter whose every field differs from the default, so a
/// query that drops it sends different variables.
pub(crate) fn backward_page() -> crate::PaginationFilter {
    crate::PaginationFilter {
        direction: crate::Direction::Backward,
        cursor: Some("cursor".to_owned()),
        limit: Some(7),
    }
}

/// Run `send` against a local server that answers every request with `{}`,
/// and return the variables of the first request that is not the service
/// config query, which pagination sends first.
pub(crate) async fn sent_variables<Fut: Future>(
    operation: &str,
    send: impl FnOnce(GraphQLClient) -> Fut,
) -> serde_json::Value {
    answered_variables(operation, vec![serde_json::json!({})], send)
        .await
        .remove(0)
}

/// Run `send` against a local server that answers the service config query
/// with `{}` and the requests for `operation` with `responses` in order, and
/// return the variables of those requests.
pub(crate) async fn answered_variables<Fut: Future>(
    operation: &str,
    responses: Vec<serde_json::Value>,
    send: impl FnOnce(GraphQLClient) -> Fut,
) -> Vec<serde_json::Value> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = GraphQLClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = async {
        let requests = async {
            let mut variables = Vec::new();
            for response in responses {
                loop {
                    let request = answer_one_request(&listener, |request| {
                        if request["operationName"] == "ServiceConfigQueryFragment" {
                            serde_json::json!({})
                        } else {
                            response.clone()
                        }
                    })
                    .await;
                    if request["operationName"] != "ServiceConfigQueryFragment" {
                        assert_eq!(request["operationName"], operation);
                        variables.push(request["variables"].clone());
                        break;
                    }
                }
            }
            variables
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), requests)
            .await
            .expect("not every response was requested")
    };
    let (variables, _) = tokio::join!(server, send(client));
    variables
}

async fn answer_one_request(
    listener: &tokio::net::TcpListener,
    respond: impl FnOnce(&serde_json::Value) -> serde_json::Value,
) -> serde_json::Value {
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
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let response = serde_json::to_vec(&respond(&request)).unwrap();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&response).await.unwrap();
    request
}

pub(crate) fn forward_page() -> crate::PaginationFilter {
    crate::PaginationFilter {
        direction: crate::Direction::Forward,
        ..backward_page()
    }
}

pub(crate) fn assert_forward_page(variables: &serde_json::Value) {
    assert_eq!(variables["after"], "cursor");
    assert_eq!(variables["first"], 7);
    assert!(variables["before"].is_null());
    assert!(variables["last"].is_null());
}

pub(crate) fn assert_backward_page(variables: &serde_json::Value) {
    assert_eq!(variables["before"], "cursor");
    assert_eq!(variables["last"], 7);
    assert!(variables["after"].is_null());
    assert!(variables["first"].is_null());
}

pub(crate) fn test_transaction() -> iota_types::Transaction {
    use iota_types::{
        Address, GasPayment, ObjectDigest, ObjectId, ObjectReference, ProgrammableTransaction,
        Transaction, TransactionExpiration, TransactionKind, TransactionV1, Version,
    };

    Transaction::V1(TransactionV1 {
        kind: TransactionKind::Programmable(ProgrammableTransaction {
            inputs: Vec::new(),
            commands: Vec::new(),
        }),
        sender: Address::STD,
        gas_payment: GasPayment {
            objects: vec![ObjectReference::new(
                ObjectId::SYSTEM_STATE,
                Version::from_u64(3),
                ObjectDigest::ZERO,
            )],
            owner: Address::FRAMEWORK,
            price: 1000,
            budget: 5_000_000,
        },
        expiration: TransactionExpiration::None,
    })
}
