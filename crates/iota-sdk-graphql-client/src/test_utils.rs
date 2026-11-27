// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Test utilities shared across the crate.

use std::time::Duration;

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

/// A pagination filter whose every field differs from the default, so a query that drops it sends
/// different variables.
pub(crate) fn backward_page() -> crate::PaginationFilter {
    crate::PaginationFilter {
        direction: crate::Direction::Backward,
        cursor: Some("cursor".to_owned()),
        limit: Some(7),
    }
}

pub(crate) struct SentRequest {
    pub operation: String,
    pub variables: serde_json::Value,
}

/// Run `send` against a local server that answers the n-th request with the n-th body of
/// `responses` and every later one with `{}`, and return the requests in arrival order together
/// with what `send` returned.
pub(crate) async fn scripted<Fut: Future>(
    responses: Vec<serde_json::Value>,
    send: impl FnOnce(GraphQLClient) -> Fut,
) -> (Vec<SentRequest>, Fut::Output) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = GraphQLClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let requests = std::sync::Mutex::new(Vec::new());
    let serve = async {
        let mut bodies = responses.into_iter();
        loop {
            let body = bodies.next().unwrap_or_else(|| serde_json::json!({}));
            let request = answer_one_request(&listener, &body.to_string()).await;
            requests.lock().unwrap().push(SentRequest {
                operation: request["operationName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                variables: request["variables"].clone(),
            });
        }
    };
    let output = tokio::select! {
        output = tokio::time::timeout(Duration::from_secs(10), send(client)) => {
            output.expect("send did not finish")
        }
        _ = serve => unreachable!(),
    };
    (requests.into_inner().unwrap(), output)
}

/// Run `send` against a local server that answers every request with `{}`, and return the variables
/// of the first request that is not the service config query, which pagination sends first.
pub(crate) async fn sent_variables<Fut: Future>(
    operation: &str,
    send: impl FnOnce(GraphQLClient) -> Fut,
) -> serde_json::Value {
    let (requests, _) = scripted(Vec::new(), send).await;
    let request = requests
        .into_iter()
        .find(|request| request.operation != "ServiceConfigQueryFragment")
        .expect("no request sent");
    assert_eq!(request.operation, operation);
    request.variables
}

async fn answer_one_request(listener: &tokio::net::TcpListener, body: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    let request_body = loop {
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
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    serde_json::from_slice(&request_body).unwrap()
}

/// A service config response whose only value of interest is `max_page_size`.
pub(crate) fn service_config_body(max_page_size: i32) -> serde_json::Value {
    serde_json::json!({ "data": { "serviceConfig": {
        "defaultPageSize": 20,
        "enabledFeatures": [],
        "maxMoveValueDepth": 128,
        "maxOutputNodes": 100_000,
        "maxPageSize": max_page_size,
        "maxQueryDepth": 20,
        "maxQueryNodes": 300,
        "maxQueryPayloadSize": 5_000,
        "maxTypeArgumentDepth": 16,
        "maxTypeArgumentWidth": 32,
        "maxTypeNodes": 256,
        "mutationTimeoutMs": 74_000,
        "requestTimeoutMs": 40_000,
    } } })
}

/// A value drawn from the type's proptest strategy with a fixed seed.
pub(crate) fn arbitrary<T: proptest::arbitrary::Arbitrary>() -> T {
    use proptest::strategy::{Strategy, ValueTree};

    proptest::arbitrary::any::<T>()
        .new_tree(&mut proptest::test_runner::TestRunner::deterministic())
        .unwrap()
        .current()
}

/// The BCS bytes of `value`, Base64-encoded as the server sends them.
pub(crate) fn base64_bcs<T: serde::Serialize>(value: &T) -> String {
    use base64ct::Encoding;

    base64ct::Base64::encode_string(&bcs::to_bytes(value).unwrap())
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
