// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The result of a client operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Maximum number of response body bytes kept in a [`TransportError`].
const MAX_BODY_BYTES: usize = 512;

/// Errors returned by the GraphQL client.
///
/// A queried object, transaction or epoch that does not exist is reported as
/// `Ok(None)`, so absence never surfaces here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request did not reach the server, or its response did not come
    /// back.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// The server answered with errors.
    #[error("server error: {0}")]
    Server(#[from] ServerErrors),
    /// The response does not have the shape the client expects.
    #[error("malformed response: {0}")]
    MalformedResponse(#[from] MalformedResponse),
    /// An input cannot be sent as given.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The operation did not finish within its deadline.
    #[error("timed out after {0:?}")]
    TimedOut(Duration),
}

impl Error {
    /// Whether sending the same request again may succeed.
    ///
    /// True for connection failures, timeouts, HTTP 429, 502, 503 and 504, and
    /// server errors with the `REQUEST_TIMEOUT` code.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(error) => error.is_retryable(),
            Self::Server(errors) => errors.is_retryable(),
            Self::MalformedResponse(_) | Self::InvalidInput(_) | Self::TimedOut(_) => false,
        }
    }

    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::MalformedResponse(MalformedResponse {
            message: message.into(),
            source: None,
        })
    }

    pub(crate) fn malformed_with(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::MalformedResponse(MalformedResponse {
            message: message.into(),
            source: Some(source.into()),
        })
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }
}

/// What kind of failure a [`TransportError`] is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// The connection could not be established.
    Connect,
    /// The request did not complete in time.
    Timeout,
    /// The server answered with a non-success HTTP status.
    Status(u16),
    /// Any other transport failure.
    Other,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("connection failed"),
            Self::Timeout => f.write_str("request timed out"),
            Self::Status(status) => write!(f, "HTTP {status}"),
            Self::Other => f.write_str("request failed"),
        }
    }
}

/// A failure to deliver a request or to receive its response.
///
/// Transports other than the built-in one build these with the constructors.
#[derive(Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    detail: Option<String>,
    source: Option<BoxError>,
}

impl TransportError {
    /// The connection could not be established.
    pub fn connect(source: impl Into<BoxError>) -> Self {
        Self::new(TransportErrorKind::Connect, None, Some(source.into()))
    }

    /// The request did not complete in time.
    pub fn timeout() -> Self {
        Self::new(TransportErrorKind::Timeout, None, None)
    }

    /// The server answered with `status`. A truncated copy of `body` is kept
    /// for the error message.
    pub fn status(status: u16, body: &[u8]) -> Self {
        let truncated = &body[..body.len().min(MAX_BODY_BYTES)];
        let mut detail = String::from_utf8_lossy(truncated).into_owned();
        if body.len() > MAX_BODY_BYTES {
            detail.push_str("… (truncated)");
        }
        Self::new(TransportErrorKind::Status(status), Some(detail), None)
    }

    /// Any other transport failure.
    pub fn other(source: impl Into<BoxError>) -> Self {
        Self::new(TransportErrorKind::Other, None, Some(source.into()))
    }

    fn new(kind: TransportErrorKind, detail: Option<String>, source: Option<BoxError>) -> Self {
        Self {
            kind,
            detail,
            source,
        }
    }

    /// What kind of failure this is.
    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    /// The HTTP status the server answered with, if it answered.
    pub fn status_code(&self) -> Option<u16> {
        match self.kind {
            TransportErrorKind::Status(status) => Some(status),
            _ => None,
        }
    }

    /// Whether sending the same request again may succeed.
    pub fn is_retryable(&self) -> bool {
        match self.kind {
            TransportErrorKind::Connect | TransportErrorKind::Timeout => true,
            TransportErrorKind::Status(status) => matches!(status, 429 | 502 | 503 | 504),
            TransportErrorKind::Other => false,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(detail) = &self.detail {
            write!(f, ", body={detail:?}")?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// The errors a server answered a request with.
#[derive(Clone, Debug)]
pub struct ServerErrors(Vec<ServerError>);

impl ServerErrors {
    pub(crate) fn new(errors: Vec<ServerError>) -> Self {
        Self(errors)
    }

    /// The individual errors, in the order the server reported them.
    pub fn errors(&self) -> &[ServerError] {
        &self.0
    }

    /// Whether any of the errors has the given code, e.g. `"BAD_USER_INPUT"`.
    pub fn has_code(&self, code: &str) -> bool {
        self.0.iter().any(|error| error.code() == Some(code))
    }

    fn is_retryable(&self) -> bool {
        self.has_code("REQUEST_TIMEOUT")
    }
}

impl fmt::Display for ServerErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ServerErrors {}

/// One error a server answered a request with.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct ServerError {
    message: String,
    #[serde(default)]
    path: Vec<serde_json::Value>,
    #[serde(default)]
    extensions: Option<ServerErrorExtensions>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct ServerErrorExtensions {
    code: Option<String>,
}

impl ServerError {
    /// The server's description of the error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The error's code from its `extensions`, e.g. `"BAD_USER_INPUT"`. Errors
    /// the server reports while validating the query carry none.
    pub fn code(&self) -> Option<&str> {
        self.extensions.as_ref()?.code.as_deref()
    }

    /// The path of the response field the error belongs to, as field names
    /// and list indices.
    pub fn path(&self) -> &[serde_json::Value] {
        &self.path
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(code) = self.code() {
            write!(f, " ({code})")?;
        }
        Ok(())
    }
}

/// A response that does not have the shape the client expects.
#[derive(Debug)]
pub struct MalformedResponse {
    message: String,
    source: Option<BoxError>,
}

impl fmt::Display for MalformedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for MalformedResponse {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_errors_keep_their_code() {
        let error: ServerError = serde_json::from_value(serde_json::json!({
            "message": "Connection's page size of 1000 exceeds max of 50",
            "path": ["events"],
            "extensions": { "code": "BAD_USER_INPUT" },
        }))
        .unwrap();
        assert_eq!(error.code(), Some("BAD_USER_INPUT"));
        assert_eq!(error.path(), [serde_json::json!("events")]);
        assert_eq!(
            error.to_string(),
            "Connection's page size of 1000 exceeds max of 50 (BAD_USER_INPUT)"
        );
    }

    #[test]
    fn retryable_errors() {
        assert!(Error::from(TransportError::timeout()).is_retryable());
        assert!(Error::from(TransportError::status(503, b"")).is_retryable());
        assert!(!Error::from(TransportError::status(400, b"")).is_retryable());
        assert!(!Error::malformed("missing field").is_retryable());

        let timeout = ServerErrors::new(vec![
            serde_json::from_value(serde_json::json!({
                "message": "Request timed out",
                "extensions": { "code": "REQUEST_TIMEOUT" },
            }))
            .unwrap(),
        ]);
        assert!(Error::from(timeout).is_retryable());
    }

    #[test]
    fn status_errors_truncate_the_body() {
        let error = TransportError::status(502, &[b'a'; MAX_BODY_BYTES + 10]);
        assert_eq!(error.status_code(), Some(502));
        assert!(error.to_string().ends_with("… (truncated)\""));
    }
}
