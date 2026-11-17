// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Calls through `GrpcClient` against a local ledger service that sends a
//! given minimum SDK version. `service_info` succeeds and every other call
//! fails with `NOT_FOUND`.

use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use iota_grpc_types::{
    headers::X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN,
    v1::ledger_service::{
        CheckpointData, GetCheckpointRequest, GetEpochRequest, GetEpochResponse, GetHealthRequest,
        GetHealthResponse, GetObjectsRequest, GetObjectsResponse, GetServiceInfoRequest,
        GetServiceInfoResponse, GetTransactionsRequest, GetTransactionsResponse,
        StreamCheckpointsRequest,
        ledger_service_server::{LedgerService, LedgerServiceServer},
    },
};
use iota_sdk_grpc_client::{CRATE_VERSION, GrpcClient, GrpcError, ResponseExt};
use tonic::{
    Code, Request, Response, Status,
    body::Body,
    codegen::{async_trait, tokio_stream::Empty},
    server::NamedService,
    transport::{Server, server::TcpIncoming},
};
use tower_service::Service;

const CHAIN: &str = "fake-chain";

struct FakeLedger;

#[async_trait]
impl LedgerService for FakeLedger {
    type GetObjectsStream = Empty<Result<GetObjectsResponse, Status>>;
    type GetTransactionsStream = Empty<Result<GetTransactionsResponse, Status>>;
    type GetCheckpointStream = Empty<Result<CheckpointData, Status>>;
    type StreamCheckpointsStream = Empty<Result<CheckpointData, Status>>;

    async fn get_service_info(
        &self,
        _request: Request<GetServiceInfoRequest>,
    ) -> Result<Response<GetServiceInfoResponse>, Status> {
        Ok(Response::new(
            GetServiceInfoResponse::default().with_chain(CHAIN),
        ))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthRequest>,
    ) -> Result<Response<GetHealthResponse>, Status> {
        Err(Status::not_found("fake"))
    }

    async fn get_objects(
        &self,
        _request: Request<GetObjectsRequest>,
    ) -> Result<Response<Self::GetObjectsStream>, Status> {
        Err(Status::not_found("fake"))
    }

    async fn get_transactions(
        &self,
        _request: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        Err(Status::not_found("fake"))
    }

    async fn get_checkpoint(
        &self,
        _request: Request<GetCheckpointRequest>,
    ) -> Result<Response<Self::GetCheckpointStream>, Status> {
        Err(Status::not_found("fake"))
    }

    async fn stream_checkpoints(
        &self,
        _request: Request<StreamCheckpointsRequest>,
    ) -> Result<Response<Self::StreamCheckpointsStream>, Status> {
        Err(Status::not_found("fake"))
    }

    async fn get_epoch(
        &self,
        _request: Request<GetEpochRequest>,
    ) -> Result<Response<GetEpochResponse>, Status> {
        Err(Status::not_found("fake"))
    }
}

/// Adds the minimum SDK version header to every response of `inner`, as the
/// node does.
#[derive(Clone)]
struct WithMinimum<S> {
    inner: S,
    minimum: String,
}

impl<S: NamedService> NamedService for WithMinimum<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> Service<http::Request<Body>> for WithMinimum<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let response = self.inner.call(request);
        let minimum = http::HeaderValue::from_str(&self.minimum).unwrap();
        Box::pin(async move {
            let mut response = response.await?;
            response
                .headers_mut()
                .insert(X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN, minimum);
            Ok(response)
        })
    }
}

/// Starts a fake node sending `minimum` and returns a client for it.
fn client_for_node_with_minimum(minimum: impl Into<String>) -> GrpcClient {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = incoming.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(WithMinimum {
                inner: LedgerServiceServer::new(FakeLedger),
                minimum: minimum.into(),
            })
            .serve_with_incoming(incoming),
    );
    GrpcClient::new(format!("http://{address}")).unwrap()
}

/// A minimum newer than this crate.
fn newer_minimum() -> String {
    let current = semver::Version::parse(CRATE_VERSION).unwrap();
    semver::Version::new(current.major + 1, 0, 0).to_string()
}

fn assert_outdated_client(error: &GrpcError, minimum: &str) {
    assert!(
        matches!(
            error,
            GrpcError::OutdatedClient { minimum: m, current: c }
                if m == minimum && c == CRATE_VERSION
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn older_client_gets_the_version_error() {
    let minimum = newer_minimum();
    let client = client_for_node_with_minimum(minimum.clone());

    let error = client.service_info().await.unwrap_err();

    assert_outdated_client(&error, &minimum);
}

#[tokio::test]
async fn older_client_gets_the_version_error_in_place_of_the_node_error() {
    let minimum = newer_minimum();
    let client = client_for_node_with_minimum(minimum.clone());

    let error = client.health().await.unwrap_err();

    assert_outdated_client(&error, &minimum);
}

#[tokio::test]
async fn supported_client_gets_the_response() {
    let client = client_for_node_with_minimum(CRATE_VERSION);

    let response = client.service_info().await.unwrap();

    assert_eq!(response.body().chain.as_deref(), Some(CHAIN));
    assert_eq!(
        response.iota_sdk_grpc_client_version_min(),
        Some(CRATE_VERSION)
    );
}

#[tokio::test]
async fn supported_client_gets_the_node_error() {
    let client = client_for_node_with_minimum(CRATE_VERSION);

    let error = client.health().await.unwrap_err();

    assert!(
        matches!(&error, GrpcError::Grpc(status) if status.code() == Code::NotFound),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn service_client_status_carries_the_minimum() {
    let minimum = newer_minimum();
    let client = client_for_node_with_minimum(minimum.clone());

    let status = client
        .ledger_service_client()
        .get_service_info(GetServiceInfoRequest::default())
        .await
        .unwrap_err();

    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.iota_sdk_grpc_client_version_min(),
        Some(minimum.as_str())
    );
}
