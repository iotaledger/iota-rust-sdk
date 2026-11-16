// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Calls through `GrpcClient` against a local server that answers every call
//! with an error and a given minimum SDK version.

use std::{
    convert::Infallible,
    future::Ready,
    task::{Context, Poll},
};

use iota_grpc_types::headers::X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN;
use iota_sdk_grpc_client::{GrpcClient, GrpcError, VERSION};
use tonic::{
    Code,
    body::Body,
    server::NamedService,
    transport::{Server, server::TcpIncoming},
};
use tower_service::Service;

/// Ledger service answering every call with `NOT_FOUND` and the given
/// minimum SDK version.
#[derive(Clone)]
struct NotFoundWithMinimum(String);

impl NamedService for NotFoundWithMinimum {
    const NAME: &'static str = "iota.grpc.v1.ledger_service.LedgerService";
}

impl<B> Service<http::Request<B>> for NotFoundWithMinimum {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: http::Request<B>) -> Self::Future {
        let response = http::Response::builder()
            .header("content-type", "application/grpc")
            .header("grpc-status", (Code::NotFound as i32).to_string())
            .header(X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN, self.0.as_str())
            .body(Body::empty())
            .unwrap();
        std::future::ready(Ok(response))
    }
}

/// Starts a server answering with `minimum` and returns a client for it.
fn client_for_node_with_minimum(minimum: impl Into<String>) -> GrpcClient {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = incoming.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(NotFoundWithMinimum(minimum.into()))
            .serve_with_incoming(incoming),
    );
    GrpcClient::new(format!("http://{address}")).unwrap()
}

#[tokio::test]
async fn older_client_gets_the_version_error() {
    let current = semver::Version::parse(VERSION).unwrap();
    let minimum = semver::Version::new(current.major + 1, 0, 0).to_string();
    let client = client_for_node_with_minimum(minimum.clone());

    let error = client.service_info().await.unwrap_err();

    assert!(
        matches!(
            &error,
            GrpcError::IncompatibleSdkVersion { minimum: m, current: c }
                if *m == minimum && c == VERSION
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn supported_client_gets_the_node_error() {
    let client = client_for_node_with_minimum(VERSION);

    let error = client.service_info().await.unwrap_err();

    assert!(
        matches!(&error, GrpcError::Grpc(status) if status.code() == Code::NotFound),
        "unexpected error: {error:?}"
    );
}
