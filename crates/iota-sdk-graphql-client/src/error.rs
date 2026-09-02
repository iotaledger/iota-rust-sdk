// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::num::{ParseIntError, TryFromIntError};

use cynic::GraphQlError;
use iota_types::{AddressParseError, DigestParseError, TypeParseError};
use reqwest::{StatusCode, Url};

use crate::faucet::FaucetError;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type GraphQLResult<T, E = GraphQLError> = std::result::Result<T, E>;

/// Maximum number of body bytes retained in an HTTP/decode error. Load
/// balancer and gateway pages can be hundreds of KB, so the body is truncated
/// before being stored in the error.
const MAX_ERROR_BODY_BYTES: usize = 512;

/// Render a response body as a truncated, UTF-8-lossy string suitable for
/// inclusion in an error message.
fn truncated_body(bytes: &[u8]) -> String {
    let truncated = bytes.len() > MAX_ERROR_BODY_BYTES;
    let slice = &bytes[..bytes.len().min(MAX_ERROR_BODY_BYTES)];
    let mut body = String::from_utf8_lossy(slice).into_owned();
    if truncated {
        body.push_str("… (truncated)");
    }
    body
}

fn display_graphql_errors(errors: &[GraphQlError]) -> String {
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Errors returned by the GraphQL client.
///
/// A queried object, transaction or checkpoint that does not exist is reported
/// as `Ok(None)`, so absence never surfaces here and there is nothing to test
/// an error against to detect it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphQLError {
    /// The request could not be sent, or the response could not be read.
    #[error("request error: {0}")]
    Request(#[source] reqwest::Error),

    /// The server answered with a non-success HTTP status.
    #[error(
        "GraphQL request to {url} failed with HTTP {status} while decoding `{target_type}`, \
         body={body:?}",
        url = .0.url,
        status = .0.status,
        target_type = .0.target_type,
        body = .0.body,
    )]
    Http(Box<HttpResponse>),

    /// The response body could not be parsed as JSON.
    #[error(
        "GraphQL request to {url} returned HTTP {status} but the body could not be parsed as JSON \
         while decoding `{target_type}` (body={body:?}): {source}",
        url = .response.url,
        status = .response.status,
        target_type = .response.target_type,
        body = .response.body,
    )]
    Json {
        response: Box<HttpResponse>,
        #[source]
        source: serde_json::Error,
    },

    /// The server returned errors for the query.
    #[error("query error: [{}]", display_graphql_errors(.0))]
    Query(Vec<GraphQlError>),

    /// The response carried neither data nor errors.
    #[error("query error: expected a non-empty response data from query")]
    EmptyResponse,

    /// A response field the client needs to build its return value was empty.
    #[error("empty response field: {0}")]
    EmptyResponseField(&'static str),

    /// The server returned a variant of a GraphQL union or enum this client
    /// does not know.
    #[error("unknown {0} variant")]
    UnknownVariant(&'static str),

    /// A response value could not be deserialized into its SDK type.
    #[error("deserialization error: {0}")]
    Deserialization(#[source] BoxError),

    /// A response value or a caller-supplied string could not be parsed.
    #[error("parse error: {0}")]
    Parse(#[source] BoxError),

    /// The arguments passed to a query cannot be combined.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// The operation did not complete within its deadline.
    #[error("timed out")]
    Timeout,

    /// A faucet request failed.
    #[error("faucet error: {0}")]
    Faucet(#[source] FaucetError),

    /// The subscription transport failed.
    #[error("subscription error: {0}")]
    Subscription(#[source] BoxError),

    /// The subscription server dropped `count` payloads before the next one
    /// because the client could not keep up. The stream continues after this
    /// error.
    #[error("subscription lagged: {count} payload(s) dropped by the server")]
    Lagged { count: i32 },
}

/// The HTTP response a [`GraphQLError::Http`] or [`GraphQLError::Json`] was
/// raised for.
#[derive(Debug)]
#[non_exhaustive]
pub struct HttpResponse {
    pub url: Url,
    pub status: StatusCode,
    /// Truncated, UTF-8-lossy snapshot of the response body.
    pub body: String,
    /// Name of the type the response was being decoded into. A bare status or
    /// `serde_json` error does not reveal what the client was decoding.
    pub target_type: String,
}

impl HttpResponse {
    fn new(url: Url, status: StatusCode, body: &[u8], target_type: &str) -> Box<Self> {
        Box::new(Self {
            url,
            status,
            body: truncated_body(body),
            target_type: target_type.to_owned(),
        })
    }
}

impl GraphQLError {
    /// Build a [`GraphQLError::Http`] from a non-success response, retaining a
    /// truncated, UTF-8-lossy snapshot of the body.
    pub(crate) fn http(url: Url, status: StatusCode, body: &[u8], target_type: &str) -> Self {
        Self::Http(HttpResponse::new(url, status, body, target_type))
    }

    /// Build a [`GraphQLError::Json`] from a response whose body is not valid
    /// JSON, retaining a truncated, UTF-8-lossy snapshot of the body.
    pub(crate) fn json(
        url: Url,
        status: StatusCode,
        body: &[u8],
        target_type: &str,
        source: serde_json::Error,
    ) -> Self {
        Self::Json {
            response: HttpResponse::new(url, status, body, target_type),
            source,
        }
    }

    /// Wrap an error raised while turning a response value into its SDK type.
    pub fn deserialization<E: Into<BoxError>>(error: E) -> Self {
        Self::Deserialization(error.into())
    }

    /// Wrap an error raised while parsing a response value or a
    /// caller-supplied string.
    pub fn parse<E: Into<BoxError>>(error: E) -> Self {
        Self::Parse(error.into())
    }

    /// Wrap a subscription transport failure.
    pub fn subscription<E: Into<BoxError>>(error: E) -> Self {
        Self::Subscription(error.into())
    }
}

impl From<bcs::Error> for GraphQLError {
    fn from(error: bcs::Error) -> Self {
        Self::Deserialization(error.into())
    }
}

impl From<reqwest::Error> for GraphQLError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

impl From<FaucetError> for GraphQLError {
    fn from(error: FaucetError) -> Self {
        Self::Faucet(error)
    }
}

impl From<url::ParseError> for GraphQLError {
    fn from(error: url::ParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<ParseIntError> for GraphQLError {
    fn from(error: ParseIntError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<AddressParseError> for GraphQLError {
    fn from(error: AddressParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<base64ct::Error> for GraphQLError {
    fn from(error: base64ct::Error) -> Self {
        Self::Parse(error.into())
    }
}

impl From<chrono::ParseError> for GraphQLError {
    fn from(error: chrono::ParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<DigestParseError> for GraphQLError {
    fn from(error: DigestParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<TryFromIntError> for GraphQLError {
    fn from(error: TryFromIntError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<TypeParseError> for GraphQLError {
    fn from(error: TypeParseError) -> Self {
        Self::Parse(error.into())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<tokio_tungstenite::tungstenite::Error> for GraphQLError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Subscription(error.into())
    }
}

impl From<graphql_ws_client::Error> for GraphQLError {
    fn from(error: graphql_ws_client::Error) -> Self {
        Self::Subscription(error.into())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<ws_stream_wasm::WsErr> for GraphQLError {
    fn from(error: ws_stream_wasm::WsErr) -> Self {
        Self::Subscription(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_surfaces_status_body_and_decode_target() {
        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let error = GraphQLError::http(
            url,
            StatusCode::TOO_MANY_REQUESTS,
            b"Too Many Requests",
            "my_crate::MyResponse",
        );
        let message = error.to_string();
        assert!(message.contains("https://graphql.devnet.iota.cafe"));
        assert!(message.contains("HTTP 429 Too Many Requests"));
        assert!(message.contains("Too Many Requests"));
        assert!(message.contains("while decoding `my_crate::MyResponse`"));
        // The status stays inspectable instead of only being rendered.
        assert!(
            matches!(error, GraphQLError::Http(response) if response.status == StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[test]
    fn json_error_surfaces_status_body_and_source() {
        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let serde_error = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        let error = GraphQLError::json(
            url,
            StatusCode::OK,
            b"not json",
            "my_crate::MyResponse",
            serde_error,
        );
        let message = error.to_string();
        assert!(message.contains("https://graphql.devnet.iota.cafe"));
        assert!(message.contains("HTTP 200 OK"));
        assert!(message.contains("not json"));
        // The underlying serde_json error text is included.
        assert!(message.contains("expected"));
    }

    #[test]
    fn wrapped_error_is_exposed_as_the_cause() {
        use std::error::Error as _;

        let bcs_error = bcs::from_bytes::<u64>(&[]).unwrap_err();
        let expected = bcs_error.to_string();
        let error = GraphQLError::from(bcs_error);
        assert_eq!(
            error.source().expect("expected a cause").to_string(),
            expected
        );
    }

    #[test]
    fn body_is_truncated() {
        let body = vec![b'a'; MAX_ERROR_BODY_BYTES + 100];
        let rendered = truncated_body(&body);
        assert!(rendered.contains("… (truncated)"));
        assert_eq!(rendered.len(), MAX_ERROR_BODY_BYTES + "… (truncated)".len());
    }
}
