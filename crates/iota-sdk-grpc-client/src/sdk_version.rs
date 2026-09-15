// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rejects responses from a node that requires a newer SDK than this one.
//!
//! The node stamps every gRPC response with the lowest `iota-sdk-grpc-client`
//! version able to decode its wire types, in the
//! [`X_IOTA_MIN_SDK_VERSION`](headers::X_IOTA_MIN_SDK_VERSION) header. The
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

use iota_grpc_types::headers;
use semver::Version;
use tower_service::Service;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Version of this crate, which the node's minimum SDK version is compared
/// against.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The node requires a newer `iota-sdk-grpc-client` than the one in use.
///
/// Attached as the source of the `FAILED_PRECONDITION` status a failed check
/// produces, so the high-level API can surface it as its own error variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IncompatibleSdkVersion {
    pub(crate) minimum: Version,
    pub(crate) current: Version,
}

impl fmt::Display for IncompatibleSdkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "node requires iota-sdk-grpc-client >= {}, this client is {}",
            self.minimum, self.current
        )
    }
}

impl std::error::Error for IncompatibleSdkVersion {}

/// gRPC channel wrapper that fails a call when the node's minimum SDK version
/// is newer than this crate.
///
/// A response without the header, or with one that is not a semantic version,
/// passes unchanged.
#[derive(Clone, Debug)]
pub struct SdkVersionCheck<S> {
    inner: S,
    current: Version,
}

impl<S> SdkVersionCheck<S> {
    pub(crate) fn new(inner: S) -> Self {
        // `CARGO_PKG_VERSION` comes from this crate's manifest, which cargo
        // only accepts with a valid semantic version.
        let current = Version::parse(VERSION).expect("CARGO_PKG_VERSION is a valid version");
        Self::with_current_version(inner, current)
    }

    fn with_current_version(inner: S, current: Version) -> Self {
        Self { inner, current }
    }
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for SdkVersionCheck<S>
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
        .get(headers::X_IOTA_MIN_SDK_VERSION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Version::parse(value).ok())
    else {
        return Ok(());
    };

    if *current >= minimum {
        return Ok(());
    }

    let error = IncompatibleSdkVersion {
        minimum,
        current: current.clone(),
    };
    let mut status = tonic::Status::failed_precondition(error.to_string());
    status.set_source(Arc::new(error));
    Err(status)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

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
            headers::X_IOTA_MIN_SDK_VERSION,
            http::HeaderValue::from_str(minimum).unwrap(),
        );
        headers
    }

    async fn call_with(
        response_headers: http::HeaderMap,
        current: &str,
    ) -> Result<http::Response<()>, BoxError> {
        let mut service = SdkVersionCheck::with_current_version(
            FixedHeaders(response_headers),
            Version::parse(current).unwrap(),
        );
        service.call(http::Request::new(())).await
    }

    fn incompatible_error(error: BoxError) -> IncompatibleSdkVersion {
        let status = tonic::Status::from_error(error);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        std::error::Error::source(&status)
            .and_then(|source| source.downcast_ref::<IncompatibleSdkVersion>())
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
        let error = incompatible_error(error);
        assert_eq!(error.minimum, Version::parse("1.3.0").unwrap());
        assert_eq!(error.current, Version::parse("1.2.9").unwrap());
        assert_eq!(
            error.to_string(),
            "node requires iota-sdk-grpc-client >= 1.3.0, this client is 1.2.9"
        );
    }

    #[tokio::test]
    async fn fails_when_client_is_older_pre_release() {
        let error = call_with(headers_with_minimum("1.0.0-beta.2"), "1.0.0-beta.1")
            .await
            .unwrap_err();
        incompatible_error(error);
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
        Version::parse(VERSION).unwrap();
    }
}
