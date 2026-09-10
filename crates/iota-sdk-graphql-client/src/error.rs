// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    num::{ParseIntError, TryFromIntError},
    string::FromUtf8Error,
};

use cynic::GraphQlError;
use iota_types::{
    AddressParseError, DigestParseError, TypeParseError, TypeTag, iota_names::error::IotaNamesError,
};
use reqwest::{StatusCode, Url};

use crate::faucet::FaucetError;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Result<T, E = Error> = std::result::Result<T, E>;

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
/// as `Ok(None)`, so absence never surfaces here.
///
/// A variant that wraps another error renders that error inline and also
/// exposes it through [`std::error::Error::source`], so the message is
/// self-contained and the cause stays matchable.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request could not be sent, or the response could not be read.
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),
    /// The server answered with a non-success HTTP status.
    #[error(
        "GraphQL request to {url} failed with HTTP {status} while decoding `{target_type}`, \
         body={body:?}",
        url = .response.url,
        status = .response.status,
        target_type = .response.target_type,
        body = .response.body,
    )]
    Http { response: Box<HttpResponse> },
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
    #[error("empty response: the server returned neither data nor errors")]
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
    /// An IOTA name could not be parsed.
    #[error("invalid name `{name}`: {source}")]
    InvalidName {
        /// The name that could not be parsed.
        name: String,
        #[source]
        source: IotaNamesError,
    },
    /// A dynamic field holds a different type than the caller asked for.
    #[error("type mismatch: expected `{expected}`, got `{actual}`")]
    TypeMismatch {
        /// The type the caller asked for.
        expected: TypeTag,
        /// The type the field actually holds.
        actual: TypeTag,
    },
    /// The caller-supplied arguments cannot be combined, or a caller-supplied
    /// value is not usable for this operation.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// The RPC URL scheme is not usable for subscriptions.
    #[error("unsupported RPC scheme `{0}` for subscriptions, expected http, https, ws or wss")]
    UnsupportedScheme(String),
    /// The operation did not complete within its deadline.
    #[error("timed out")]
    Timeout,
    /// A faucet request failed.
    #[error("faucet error: {0}")]
    Faucet(#[from] FaucetError),
    /// The subscription transport failed.
    #[error("subscription error: {0}")]
    Subscription(#[source] BoxError),
    /// The subscription server dropped `count` payloads before the next one
    /// because the client could not keep up. The stream continues after this
    /// error.
    #[error("subscription lagged: {count} payload(s) dropped by the server")]
    Lagged { count: u32 },
}

/// The HTTP response a [`Error::Http`] or [`Error::Json`] was
/// raised for.
#[derive(Debug)]
#[non_exhaustive]
pub struct HttpResponse {
    /// URL the request was sent to.
    pub url: Url,
    /// HTTP status the server answered with.
    pub status: StatusCode,
    /// Truncated, UTF-8-lossy snapshot of the response body.
    pub body: String,
    /// Name of the type the response was being decoded into. A bare status or
    /// `serde_json` error does not reveal what the client was decoding.
    pub target_type: &'static str,
}

impl HttpResponse {
    fn new(url: Url, status: StatusCode, body: &[u8], target_type: &'static str) -> Box<Self> {
        Box::new(Self {
            url,
            status,
            body: truncated_body(body),
            target_type,
        })
    }
}

impl Error {
    /// Build a [`Error::Http`] from a non-success response, retaining a
    /// truncated, UTF-8-lossy snapshot of the body.
    pub(crate) fn http(
        url: Url,
        status: StatusCode,
        body: &[u8],
        target_type: &'static str,
    ) -> Self {
        Self::Http {
            response: HttpResponse::new(url, status, body, target_type),
        }
    }

    /// Build a [`Error::Json`] from a response whose body is not valid
    /// JSON, retaining a truncated, UTF-8-lossy snapshot of the body.
    pub(crate) fn json(
        url: Url,
        status: StatusCode,
        body: &[u8],
        target_type: &'static str,
        source: serde_json::Error,
    ) -> Self {
        Self::Json {
            response: HttpResponse::new(url, status, body, target_type),
            source,
        }
    }

    /// Wrap an error raised while turning a response value into its SDK type.
    pub(crate) fn deserialization<E: Into<BoxError>>(error: E) -> Self {
        Self::Deserialization(error.into())
    }

    /// Wrap a subscription transport failure.
    pub(crate) fn subscription<E: Into<BoxError>>(error: E) -> Self {
        Self::Subscription(error.into())
    }
}

impl From<bcs::Error> for Error {
    fn from(error: bcs::Error) -> Self {
        Self::Deserialization(error.into())
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<ParseIntError> for Error {
    fn from(error: ParseIntError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<AddressParseError> for Error {
    fn from(error: AddressParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: base64ct::Error) -> Self {
        Self::Parse(error.into())
    }
}

impl From<chrono::ParseError> for Error {
    fn from(error: chrono::ParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<DigestParseError> for Error {
    fn from(error: DigestParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<TryFromIntError> for Error {
    fn from(error: TryFromIntError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<TypeParseError> for Error {
    fn from(error: TypeParseError) -> Self {
        Self::Parse(error.into())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Self::Parse(error.into())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Subscription(error.into())
    }
}

impl From<graphql_ws_client::Error> for Error {
    fn from(error: graphql_ws_client::Error) -> Self {
        Self::Subscription(error.into())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<ws_stream_wasm::WsErr> for Error {
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
        let error = Error::http(
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
            matches!(error, Error::Http { response } if response.status == StatusCode::TOO_MANY_REQUESTS)
        );
    }

    #[test]
    fn json_error_surfaces_status_body_and_source() {
        use std::error::Error as _;

        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let serde_error = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        let cause = serde_error.to_string();
        let error = Error::json(
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
        // The message is self-contained, and the cause stays matchable.
        assert!(message.contains(&cause));
        assert_eq!(error.source().expect("expected a cause").to_string(), cause);
    }

    #[test]
    fn wrapped_error_is_exposed_as_the_cause() {
        use std::error::Error as _;

        let bcs_error = bcs::from_bytes::<u64>(&[]).unwrap_err();
        let expected = bcs_error.to_string();
        let error = Error::from(bcs_error);
        assert_eq!(
            error.to_string(),
            format!("deserialization error: {expected}")
        );
        assert_eq!(
            error.source().expect("expected a cause").to_string(),
            expected
        );
    }

    /// Rendering the message inline and exposing the same error through
    /// `source` means a cause-chain formatter (`anyhow`/`eyre` `{:#}`, `{:?}`)
    /// prints the wrapped message twice. That is the accepted cost of a
    /// self-contained `Display`: a consumer that reads only the top frame,
    /// such as the FFI layer, still sees the whole failure.
    #[test]
    fn chain_formatters_repeat_the_wrapped_message() {
        use std::error::Error as _;

        let error = Error::from(bcs::from_bytes::<u64>(&[]).unwrap_err());

        assert_eq!(
            error.to_string(),
            "deserialization error: unexpected end of input"
        );

        let mut chain = vec![error.to_string()];
        let mut next = error.source();
        while let Some(error) = next {
            chain.push(error.to_string());
            next = error.source();
        }

        assert_eq!(
            chain,
            [
                "deserialization error: unexpected end of input",
                "unexpected end of input",
            ]
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
