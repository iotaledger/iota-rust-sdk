// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rejects responses from a node that requires a newer SDK than this one.
//!
//! The node stamps every gRPC response with the lowest `iota-sdk-grpc-client`
//! version able to decode its wire types, in the
//! [`X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN`](crate::headers::X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN) header. The
//! check runs on the response headers, before any body is decoded, so an
//! outdated client fails with a clear error instead of tripping over a wire
//! value it does not know.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use semver::Version;
use tower_service::Service;

use crate::{ResponseExt, client::BoxError};

/// Version of this crate, which the node's minimum SDK version is compared
/// against.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The node requires a newer `iota-sdk-grpc-client` than the one in use.
///
/// Attached as the source of the `FAILED_PRECONDITION` status a failed check
/// produces, so the high-level API can surface it as its own error variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutdatedClientError {
    pub(crate) minimum: Version,
    pub(crate) current: Version,
}

impl fmt::Display for OutdatedClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the node requires a newer IOTA SDK, upgrade it (needs iota-sdk-grpc-client >= {}, this SDK uses {})",
            self.minimum, self.current
        )
    }
}

impl std::error::Error for OutdatedClientError {}

/// gRPC channel wrapper that fails a call when the node's minimum SDK version
/// is newer than this crate.
///
/// A response without the header, or with one that is not a semantic version,
/// passes unchanged.
#[derive(Clone, Debug)]
pub struct CheckedChannel<S> {
    inner: S,
    current: Version,
}

impl<S> CheckedChannel<S> {
    pub(crate) fn new(inner: S) -> Self {
        // `CARGO_PKG_VERSION` comes from this crate's manifest, which cargo
        // only accepts with a valid semantic version.
        let current = Version::parse(CRATE_VERSION).expect("CARGO_PKG_VERSION is a valid version");
        Self::with_current_version(inner, current)
    }

    fn with_current_version(inner: S, current: Version) -> Self {
        Self { inner, current }
    }
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for CheckedChannel<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    ResBody: 'static,
{
    type Response = http::Response<ResBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: http::Request<ReqBody>) -> Self::Future {
        let current = self.current.clone();
        let response = self.inner.call(request);
        Box::pin(async move {
            let response = response.await.map_err(Into::into)?;
            check_min_sdk_version(response.headers(), &current)?;
            Ok(response)
        })
    }
}

fn check_min_sdk_version(
    response_headers: &http::HeaderMap,
    current: &Version,
) -> Result<(), tonic::Status> {
    let Some(minimum) = response_headers
        .iota_sdk_grpc_client_version_min()
        .and_then(|value| Version::parse(value).ok())
    else {
        return Ok(());
    };

    if current.cmp_precedence(&minimum).is_ge() {
        return Ok(());
    }

    let error = OutdatedClientError {
        minimum,
        current: current.clone(),
    };
    let mut metadata = tonic::metadata::MetadataMap::from_headers(response_headers.clone());
    // The node's own status for the call, when it failed; this status replaces
    // it.
    for reserved in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        metadata.remove(reserved);
    }
    let mut status =
        tonic::Status::with_metadata(tonic::Code::FailedPrecondition, error.to_string(), metadata);
    status.set_source(Arc::new(error));
    Err(status)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use iota_grpc_types::headers;

    use super::*;

    /// Inner service answering every request with a fixed set of response
    /// headers.
    #[derive(Clone)]
    struct FixedHeaders(http::HeaderMap);

    impl Service<http::Request<()>> for FixedHeaders {
        type Response = http::Response<()>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: http::Request<()>) -> Self::Future {
            let mut response = http::Response::new(());
            *response.headers_mut() = self.0.clone();
            std::future::ready(Ok(response))
        }
    }

    fn headers_with_minimum(minimum: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            headers::X_IOTA_SDK_GRPC_CLIENT_VERSION_MIN,
            http::HeaderValue::from_str(minimum).unwrap(),
        );
        headers
    }

    async fn call_with(
        response_headers: http::HeaderMap,
        current: &str,
    ) -> Result<http::Response<()>, BoxError> {
        let mut service = CheckedChannel::with_current_version(
            FixedHeaders(response_headers),
            Version::parse(current).unwrap(),
        );
        service.call(http::Request::new(())).await
    }

    fn outdated_client_error(error: BoxError) -> OutdatedClientError {
        let status = tonic::Status::from_error(error);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        std::error::Error::source(&status)
            .and_then(|source| source.downcast_ref::<OutdatedClientError>())
            .expect("status carries the version error as its source")
            .clone()
    }

    #[tokio::test]
    async fn passes_when_client_matches_minimum() {
        call_with(headers_with_minimum("1.2.3"), "1.2.3")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn passes_when_client_is_newer() {
        call_with(headers_with_minimum("1.2.3"), "1.3.0")
            .await
            .unwrap();
        call_with(headers_with_minimum("1.0.0-beta.1"), "1.0.0")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fails_when_client_is_older() {
        let error = call_with(headers_with_minimum("1.3.0"), "1.2.9")
            .await
            .unwrap_err();
        let error = outdated_client_error(error);
        assert_eq!(error.minimum, Version::parse("1.3.0").unwrap());
        assert_eq!(error.current, Version::parse("1.2.9").unwrap());
        assert_eq!(
            error.to_string(),
            "the node requires a newer IOTA SDK, upgrade it (needs iota-sdk-grpc-client >= 1.3.0, this SDK uses 1.2.9)"
        );
    }

    #[tokio::test]
    async fn fails_when_client_is_older_pre_release() {
        let error = call_with(headers_with_minimum("1.0.0-beta.2"), "1.0.0-beta.1")
            .await
            .unwrap_err();
        outdated_client_error(error);
    }

    #[tokio::test]
    async fn failed_check_keeps_the_response_headers_but_not_the_node_status() {
        let mut response_headers = headers_with_minimum("1.3.0");
        response_headers.insert(
            headers::X_IOTA_SERVER,
            http::HeaderValue::from_static("iota-node/1.37.0"),
        );
        response_headers.insert("grpc-status", http::HeaderValue::from_static("5"));
        response_headers.insert("grpc-message", http::HeaderValue::from_static("not found"));

        let error = call_with(response_headers, "1.2.9").await.unwrap_err();
        let status = tonic::Status::from_error(error);

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.iota_sdk_grpc_client_version_min(), Some("1.3.0"));
        assert_eq!(status.server_version(), Some("iota-node/1.37.0"));
        assert!(status.metadata().get("grpc-status").is_none());
        assert!(status.metadata().get("grpc-message").is_none());
    }

    #[tokio::test]
    async fn ignores_build_metadata() {
        call_with(headers_with_minimum("1.2.3+build"), "1.2.3")
            .await
            .unwrap();
        let error = call_with(headers_with_minimum("1.2.4+build"), "1.2.3")
            .await
            .unwrap_err();
        outdated_client_error(error);
    }

    #[tokio::test]
    async fn passes_without_header() {
        call_with(http::HeaderMap::new(), "1.2.3").await.unwrap();
    }

    #[tokio::test]
    async fn passes_with_unparsable_header() {
        call_with(headers_with_minimum("latest"), "1.2.3")
            .await
            .unwrap();
    }

    #[test]
    fn crate_version_is_valid_semver() {
        Version::parse(CRATE_VERSION).unwrap();
    }
}
