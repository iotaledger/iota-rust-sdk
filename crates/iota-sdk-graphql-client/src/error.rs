// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::num::{ParseIntError, TryFromIntError};

use cynic::GraphQlError;
use iota_types::{AddressParseError, DigestParseError, TypeParseError};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type Result<T, E = Error> = std::result::Result<T, E>;

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
}

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum Kind {
    Deserialization,
    Parse,
    Query,
    Missing,
    Other,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source.as_deref().map(|e| e as _)
    }
}

impl Error {
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
            }),
        }
    }

    /// Create a Query kind of error with the original graphql errors.
    pub fn graphql_error(errors: Vec<GraphQlError>) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind: Kind::Query,
                source: None,
                query_errors: Some(errors),
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

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use super::*;

    // --- Kind Display tests ---

    #[test]
    fn kind_display_deserialization() {
        assert_eq!(Kind::Deserialization.to_string(), "Deserialization error:");
    }

    #[test]
    fn kind_display_parse() {
        assert_eq!(Kind::Parse.to_string(), "Parse error:");
    }

    #[test]
    fn kind_display_query() {
        assert_eq!(Kind::Query.to_string(), "Query error:");
    }

    #[test]
    fn kind_display_missing() {
        assert_eq!(Kind::Missing.to_string(), "Missing:");
    }

    #[test]
    fn kind_display_other() {
        assert_eq!(Kind::Other.to_string(), "Error:");
    }

    // --- Error constructor tests ---

    #[test]
    fn from_error_preserves_kind_and_source() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::from_error(Kind::Other, inner);
        let display = err.to_string();
        assert!(display.starts_with("Error:"));
        assert!(display.contains("file not found"));
        // source() should return the original error
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn from_message_preserves_kind_and_message() {
        let err = Error::from_message(Kind::Parse, "invalid format".to_string());
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
        assert!(display.contains("invalid format"));
    }

    #[test]
    fn empty_response_error_is_query_kind() {
        let err = Error::empty_response_error();
        let display = err.to_string();
        assert!(display.starts_with("Query error:"));
        assert!(display.contains("non-empty response"));
    }

    #[test]
    fn empty_response_error_has_no_graphql_errors() {
        let err = Error::empty_response_error();
        assert!(err.graphql_errors().is_none());
    }

    #[test]
    fn graphql_error_stores_errors() {
        let gql_err = GraphQlError {
            message: "field not found".to_string(),
            locations: None,
            path: None,
            extensions: None,
        };
        let err = Error::graphql_error(vec![gql_err]);
        let gql_errors = err.graphql_errors().unwrap();
        assert_eq!(gql_errors.len(), 1);
        assert_eq!(gql_errors[0].message, "field not found");
    }

    #[test]
    fn graphql_error_with_multiple_errors() {
        let errs = vec![
            GraphQlError {
                message: "error1".to_string(),
                locations: None,
                path: None,
                extensions: None,
            },
            GraphQlError {
                message: "error2".to_string(),
                locations: None,
                path: None,
                extensions: None,
            },
        ];
        let err = Error::graphql_error(errs);
        let gql_errors = err.graphql_errors().unwrap();
        assert_eq!(gql_errors.len(), 2);
    }

    #[test]
    fn graphql_error_display_includes_errors() {
        let gql_err = GraphQlError {
            message: "some gql error".to_string(),
            locations: None,
            path: None,
            extensions: None,
        };
        let err = Error::graphql_error(vec![gql_err]);
        let display = err.to_string();
        assert!(display.contains("Query error:"));
        assert!(display.contains("some gql error"));
    }

    #[test]
    fn graphql_error_has_no_source() {
        let gql_err = GraphQlError {
            message: "test".to_string(),
            locations: None,
            path: None,
            extensions: None,
        };
        let err = Error::graphql_error(vec![gql_err]);
        assert!(StdError::source(&err).is_none());
    }

    // --- Error Display formatting tests ---

    #[test]
    fn display_kind_only_no_source_no_graphql() {
        // from_message creates source, so we use graphql_error with empty vec
        let err = Error::graphql_error(vec![]);
        let display = err.to_string();
        assert!(display.starts_with("Query error:"));
        assert!(display.contains("[]"));
    }

    #[test]
    fn display_with_source_and_no_graphql_errors() {
        let err = Error::from_message(Kind::Deserialization, "bad json".to_string());
        let display = err.to_string();
        assert_eq!(display, "Deserialization error: bad json");
        assert!(err.graphql_errors().is_none());
    }

    // --- From implementations tests ---

    #[test]
    fn from_bcs_error() {
        // Create a BCS error by trying to deserialize invalid data
        let bcs_err = bcs::from_bytes::<String>(&[0xff, 0xff]).unwrap_err();
        let err: Error = bcs_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Deserialization error:"));
    }

    #[test]
    fn from_url_parse_error() {
        let url_err = url::Url::parse("not a url!@#$").unwrap_err();
        let err: Error = url_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_parse_int_error() {
        let int_err: ParseIntError = "not_a_number".parse::<i32>().unwrap_err();
        let err: Error = int_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_try_from_int_error() {
        let int_err: TryFromIntError = u8::try_from(256u16).unwrap_err();
        let err: Error = int_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_base64_error() {
        let b64_err = base64ct::Error::InvalidEncoding;
        let err: Error = b64_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    // --- std::error::Error trait tests ---

    #[test]
    fn error_source_is_some_when_created_with_from_error() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "inner error");
        let err = Error::from_error(Kind::Other, inner);
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn error_source_is_some_when_created_with_from_message() {
        let err = Error::from_message(Kind::Missing, "missing field".to_string());
        // from_message wraps message as a BoxError, so source is Some
        assert!(StdError::source(&err).is_some());
    }

    // --- Kind Copy/Clone tests ---

    #[test]
    fn kind_is_copy() {
        let k1 = Kind::Query;
        let k2 = k1; // Copy
        assert!(matches!(k1, Kind::Query));
        assert!(matches!(k2, Kind::Query));
    }

    // --- Previously missing From implementation tests ---

    #[test]
    fn from_address_parse_error() {
        let addr_err = iota_types::Address::from_hex("not_hex").unwrap_err();
        let err: Error = addr_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_chrono_parse_error() {
        let chrono_err = "not-a-date".parse::<chrono::NaiveDate>().unwrap_err();
        let err: Error = chrono_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_digest_parse_error() {
        let digest_err = iota_types::Digest::from_base58("!invalid!").unwrap_err();
        let err: Error = digest_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }

    #[test]
    fn from_type_parse_error() {
        use std::str::FromStr;
        let type_err = iota_types::TypeTag::from_str(":::invalid:::").unwrap_err();
        let err: Error = type_err.into();
        let display = err.to_string();
        assert!(display.starts_with("Parse error:"));
    }
}
