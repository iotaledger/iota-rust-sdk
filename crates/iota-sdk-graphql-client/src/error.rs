// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::num::{ParseIntError, TryFromIntError};

use cynic::GraphQlError;
use iota_types::{AddressParseError, DigestParseError, TypeParseError};
use reqwest::{StatusCode, Url};

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

/// General error type for the client. It is used to wrap all the possible
/// errors that can occur.
#[derive(Debug)]
pub struct Error {
    inner: Box<InnerError>,
}

/// Error type for the client. It is split into multiple fields to allow for
/// more granular error handling. The `source` field is used to store the
/// original error.
#[derive(Debug)]
struct InnerError {
    /// Error kind.
    kind: Kind,
    /// Errors returned by the GraphQL server.
    query_errors: Option<Vec<GraphQlError>>,
    /// The original error.
    source: Option<BoxError>,
    /// Name of the type the response was being deserialized into, if known.
    /// Recorded by the client so a bare HTTP/JSON error also reveals *what*
    /// the client was trying to decode.
    target_type: Option<String>,
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Kind {
    Deserialization,
    Parse,
    Query,
    Missing,
    /// The HTTP response carried a non-success status code.
    Http {
        status: reqwest::StatusCode,
    },
    Subscription,
    Other,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // `Display` already renders the inner error's own message inline, so we
        // expose only its *underlying* cause here. Returning the inner error
        // directly would make cause-chain formatters (e.g. `anyhow`/`eyre`
        // `{:?}`) repeat that message verbatim under "Caused by".
        self.inner.source.as_deref()?.source()
    }
}

impl Error {
    /// Error kind, useful for programmatic handling (e.g. matching on
    /// [`Kind::Http`] to retry on certain status codes).
    pub fn kind(&self) -> Kind {
        self.inner.kind
    }

    /// Original GraphQL query errors.
    pub fn graphql_errors(&self) -> Option<&[GraphQlError]> {
        self.inner.query_errors.as_deref()
    }

    /// Convert the given error into a generic error.
    pub fn from_error<E: Into<BoxError>>(kind: Kind, error: E) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind,
                source: Some(error.into()),
                query_errors: None,
                target_type: None,
            }),
        }
    }

    /// Convert the given message into a generic error.
    pub fn from_message(kind: Kind, message: String) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind,
                source: Some(message.into()),
                query_errors: None,
                target_type: None,
            }),
        }
    }

    /// Special constructor for queries that expect to return data but it's
    /// none.
    pub fn empty_response_error() -> Self {
        Self {
            inner: Box::new(InnerError {
                kind: Kind::Query,
                source: Some("Expected a non-empty response data from query".into()),
                query_errors: None,
                target_type: None,
            }),
        }
    }

    /// Create an error for a non-success HTTP response, capturing the request
    /// URL, the HTTP status (code + reason phrase) and a truncated, UTF-8-lossy
    /// snapshot of the response body.
    pub fn http(url: Url, status: StatusCode, body: &[u8]) -> Self {
        Self::from_message(
            Kind::Http { status },
            format!(
                "GraphQL request to {url} failed, body={:?}",
                truncated_body(body)
            ),
        )
    }

    /// Create an error for a response whose body could not be parsed as JSON,
    /// capturing the request URL, the HTTP status, a truncated, UTF-8-lossy
    /// snapshot of the body and the underlying `serde_json` error.
    pub fn decode(url: Url, status: StatusCode, body: &[u8], source: serde_json::Error) -> Self {
        Self::from_message(
            Kind::Deserialization,
            format!(
                "GraphQL request to {url} returned HTTP {status} but the body could not be parsed \
                 as JSON (body={:?}): {source}",
                truncated_body(body)
            ),
        )
    }

    /// Record the name of the type the response was being deserialized into,
    /// adding `while decoding \`T\`` context to the error message. A plain HTTP
    /// status or `serde_json` error does not reveal *what* the client was
    /// trying to decode; this fills that gap.
    pub fn while_decoding(mut self, target_type: impl Into<String>) -> Self {
        self.inner.target_type = Some(target_type.into());
        self
    }

    /// Create an error signaling that the subscription server dropped
    /// `count` payloads before the next one because the client could not keep
    /// up. The stream continues after this error.
    pub fn lagged(count: i32) -> Self {
        Self::from_message(
            Kind::Subscription,
            format!("subscription lagged: {count} payload(s) dropped by the server"),
        )
    }

    /// Create a Query kind of error with the original graphql errors.
    pub fn graphql_error(errors: Vec<GraphQlError>) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind: Kind::Query,
                source: None,
                query_errors: Some(errors),
                target_type: None,
            }),
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Kind::Deserialization => write!(f, "Deserialization error:"),
            Kind::Parse => write!(f, "Parse error:"),
            Kind::Query => write!(f, "Query error:"),
            Kind::Missing => write!(f, "Missing:"),
            Kind::Http { status } => write!(f, "HTTP {status}:"),
            Kind::Subscription => write!(f, "Subscription error:"),
            Kind::Other => write!(f, "Error:"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.inner.kind)?;

        if let Some(source) = &self.inner.source {
            write!(f, " {source}")?;
        }

        if let Some(target_type) = &self.inner.target_type {
            write!(f, " (while decoding `{target_type}`)")?;
        }

        if let Some(errors) = &self.inner.query_errors {
            write!(
                f,
                " [{}]",
                errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        Ok(())
    }
}

impl From<bcs::Error> for Error {
    fn from(error: bcs::Error) -> Self {
        Self::from_error(Kind::Deserialization, error)
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::from_error(Kind::Other, error)
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<ParseIntError> for Error {
    fn from(error: ParseIntError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<AddressParseError> for Error {
    fn from(error: AddressParseError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: base64ct::Error) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<chrono::ParseError> for Error {
    fn from(error: chrono::ParseError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<DigestParseError> for Error {
    fn from(error: DigestParseError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<TryFromIntError> for Error {
    fn from(error: TryFromIntError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

impl From<TypeParseError> for Error {
    fn from(error: TypeParseError) -> Self {
        Self::from_error(Kind::Parse, error)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::from_error(Kind::Subscription, error)
    }
}

impl From<graphql_ws_client::Error> for Error {
    fn from(error: graphql_ws_client::Error) -> Self {
        Self::from_error(Kind::Subscription, error)
    }
}

#[cfg(target_arch = "wasm32")]
impl From<ws_stream_wasm::WsErr> for Error {
    fn from(error: ws_stream_wasm::WsErr) -> Self {
        Self::from_error(Kind::Subscription, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_surfaces_status_and_body() {
        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let error = Error::http(url, StatusCode::TOO_MANY_REQUESTS, b"Too Many Requests");
        let message = error.to_string();
        assert!(message.contains("https://graphql.devnet.iota.cafe"));
        assert!(message.contains("HTTP 429 Too Many Requests"));
        assert!(message.contains("Too Many Requests"));
    }

    #[test]
    fn decode_error_surfaces_status_body_and_source() {
        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let serde_error = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        let error = Error::decode(url, StatusCode::OK, b"not json", serde_error);
        let message = error.to_string();
        assert!(message.contains("https://graphql.devnet.iota.cafe"));
        assert!(message.contains("HTTP 200 OK"));
        assert!(message.contains("not json"));
        // The underlying serde_json error text is included.
        assert!(message.contains("expected"));
    }

    #[test]
    fn http_error_has_no_duplicate_cause() {
        // The full message lives in `Display`; there is no underlying cause, so
        // `source()` must be `None` to avoid cause-chain formatters repeating
        // the message under "Caused by".
        use std::error::Error as _;

        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let error = Error::http(url, StatusCode::TOO_MANY_REQUESTS, b"Too Many Requests");
        assert!(error.source().is_none());
    }

    #[test]
    fn wrapped_error_exposes_underlying_cause_not_its_own_message() {
        use std::error::Error as _;

        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "inner cause")
            }
        }
        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "outer message")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let error = Error::from_error(Kind::Other, Outer(Inner));
        // `Display` carries the wrapped error's own message exactly once.
        assert!(error.to_string().contains("outer message"));
        // `source()` skips that already-rendered message and exposes the
        // deeper cause, so the chain does not repeat "outer message".
        let source = error.source().expect("expected an underlying cause");
        assert_eq!(source.to_string(), "inner cause");
    }

    #[test]
    fn while_decoding_adds_target_type_and_keeps_status() {
        let url = Url::parse("https://graphql.devnet.iota.cafe").unwrap();
        let error = Error::http(url, StatusCode::BAD_GATEWAY, b"Bad Gateway")
            .while_decoding("my_crate::MyResponse");
        let message = error.to_string();
        // The decode target is surfaced in the message,
        assert!(message.contains("while decoding `my_crate::MyResponse`"));
        // yet the HTTP status remains programmatically inspectable.
        assert!(matches!(error.kind(), Kind::Http { status } if status == StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn body_is_truncated() {
        let body = vec![b'a'; MAX_ERROR_BODY_BYTES + 100];
        let rendered = truncated_body(&body);
        assert!(rendered.contains("… (truncated)"));
        assert_eq!(rendered.len(), MAX_ERROR_BODY_BYTES + "… (truncated)".len());
    }
}
