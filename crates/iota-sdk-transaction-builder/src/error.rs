// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction Builder errors.

use base64ct::Error as Base64Error;
use iota_types::{Digest, ObjectId};

use crate::builder::gas_station::{GasStationVersion, VersionParsingError};

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    #[error("Conversion error due to input issue: {0}")]
    Input(String),
    #[error("Gas object should be an immutable or owned object")]
    WrongGasObject,
    #[error("BCS serialization error: {0}")]
    Bcs(bcs::Error),
    #[error("Decoding error: {0}")]
    Decoding(#[from] Base64Error),
    #[error("Missing object id")]
    MissingObjectId,
    #[error("Missing version for object {0}")]
    MissingVersion(ObjectId),
    #[error("Missing digest for object {0}")]
    MissingDigest(ObjectId),
    #[error("Missing transaction for digest {0}")]
    MissingTransaction(Digest),
    #[error("Missing gas objects")]
    MissingGasObjects,
    #[error("Missing gas budget")]
    MissingGasBudget,
    #[error("Missing gas price")]
    MissingGasPrice,
    #[error("Missing object kind for object {0}")]
    MissingObjectKind(ObjectId),
    #[error("Missing initial shared version for object {0}")]
    MissingInitialSharedVersion(ObjectId),
    #[error("Missing pure value")]
    MissingPureValue,
    #[error("Missing gas station data")]
    MissingGasStationData,
    #[error("Unknown shared object mutability for object {0}")]
    SharedObjectMutability(ObjectId),
    #[error("Unsupported literal")]
    UnsupportedLiteral,
    #[error("Invalid account for move authenticator: {0}")]
    InvalidMoveAuthAccount(String),
    #[error("Invalid argument for move authenticator: {0}")]
    InvalidMoveAuthArg(String),
    #[error(transparent)]
    InvalidUrl(<reqwest::Url as std::str::FromStr>::Err),
    #[error("Request to gas station `{gas_station_url}` failed: {source}")]
    GasStationRequest {
        source: reqwest::Error,
        gas_station_url: reqwest::Url,
    },
    #[
        error("Invalid gas station response from {gas_station_url}{}", 
        .message.as_deref().map(|msg| format!(": {msg}")).unwrap_or_default())
    ]
    GasStationResponse {
        message: Option<String>,
        gas_station_url: reqwest::Url,
    },
    #[error(
        "invalid gas-station version: got version `{version}`, but at least version `{min_required_version}` is required"
    )]
    InvalidGasStationVersion {
        /// The minimum IOTA gas-station version needed for this operation.
        min_required_version: GasStationVersion,
        /// The actual IOTA gas-station's version.
        version: GasStationVersion,
    },
    #[error(transparent)]
    VersionParsing(VersionParsingError),
    #[error(transparent)]
    Signature(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Client(Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to dry run transaction: {0}")]
    DryRun(String),
}

impl Error {
    /// Create a client error
    pub fn client<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::Client(Box::new(e))
    }

    /// Create a signature error
    pub fn signature<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::Signature(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_input() {
        let err = Error::Input("bad input".to_string());
        assert_eq!(err.to_string(), "Conversion error due to input issue: bad input");
    }

    #[test]
    fn error_display_wrong_gas_object() {
        let err = Error::WrongGasObject;
        assert_eq!(
            err.to_string(),
            "Gas object should be an immutable or owned object"
        );
    }

    #[test]
    fn error_display_missing_gas_objects() {
        let err = Error::MissingGasObjects;
        assert_eq!(err.to_string(), "Missing gas objects");
    }

    #[test]
    fn error_display_missing_gas_budget() {
        let err = Error::MissingGasBudget;
        assert_eq!(err.to_string(), "Missing gas budget");
    }

    #[test]
    fn error_display_missing_gas_price() {
        let err = Error::MissingGasPrice;
        assert_eq!(err.to_string(), "Missing gas price");
    }

    #[test]
    fn error_display_missing_object_id() {
        let err = Error::MissingObjectId;
        assert_eq!(err.to_string(), "Missing object id");
    }

    #[test]
    fn error_display_missing_version() {
        let id = ObjectId::ZERO;
        let err = Error::MissingVersion(id);
        let msg = err.to_string();
        assert!(msg.contains("Missing version for object"));
    }

    #[test]
    fn error_display_missing_digest() {
        let id = ObjectId::ZERO;
        let err = Error::MissingDigest(id);
        let msg = err.to_string();
        assert!(msg.contains("Missing digest for object"));
    }

    #[test]
    fn error_display_missing_pure_value() {
        let err = Error::MissingPureValue;
        assert_eq!(err.to_string(), "Missing pure value");
    }

    #[test]
    fn error_display_missing_gas_station_data() {
        let err = Error::MissingGasStationData;
        assert_eq!(err.to_string(), "Missing gas station data");
    }

    #[test]
    fn error_display_unsupported_literal() {
        let err = Error::UnsupportedLiteral;
        assert_eq!(err.to_string(), "Unsupported literal");
    }

    #[test]
    fn error_display_shared_object_mutability() {
        let id = ObjectId::ZERO;
        let err = Error::SharedObjectMutability(id);
        let msg = err.to_string();
        assert!(msg.contains("Unknown shared object mutability"));
    }

    #[test]
    fn error_display_invalid_move_auth_account() {
        let err = Error::InvalidMoveAuthAccount("bad_account".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Invalid account for move authenticator"));
        assert!(msg.contains("bad_account"));
    }

    #[test]
    fn error_display_invalid_move_auth_arg() {
        let err = Error::InvalidMoveAuthArg("bad_arg".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Invalid argument for move authenticator"));
        assert!(msg.contains("bad_arg"));
    }

    #[test]
    fn error_display_dry_run() {
        let err = Error::DryRun("something went wrong".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Failed to dry run transaction"));
        assert!(msg.contains("something went wrong"));
    }

    #[test]
    fn error_display_invalid_gas_station_version() {
        let err = Error::InvalidGasStationVersion {
            min_required_version: GasStationVersion::from_str("0.3.0").unwrap(),
            version: GasStationVersion::from_str("0.2.0").unwrap(),
        };
        let msg = err.to_string();
        assert!(msg.contains("0.3.0"));
        assert!(msg.contains("0.2.0"));
    }

    #[test]
    fn error_display_gas_station_response_with_message() {
        let err = Error::GasStationResponse {
            message: Some("insufficient funds".to_string()),
            gas_station_url: reqwest::Url::parse("http://localhost:8080").unwrap(),
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient funds"));
        assert!(msg.contains("localhost"));
    }

    #[test]
    fn error_display_gas_station_response_without_message() {
        let err = Error::GasStationResponse {
            message: None,
            gas_station_url: reqwest::Url::parse("http://localhost:8080").unwrap(),
        };
        let msg = err.to_string();
        assert!(msg.contains("localhost"));
    }

    #[test]
    fn error_client_wraps_error() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        let err = Error::client(inner);
        assert!(matches!(err, Error::Client(_)));
        let msg = err.to_string();
        assert!(msg.contains("test error"));
    }

    #[test]
    fn error_signature_wraps_error() {
        let inner = std::io::Error::new(std::io::ErrorKind::Other, "sig error");
        let err = Error::signature(inner);
        assert!(matches!(err, Error::Signature(_)));
        let msg = err.to_string();
        assert!(msg.contains("sig error"));
    }

    #[test]
    fn error_from_base64() {
        let b64_err = base64ct::Error::InvalidEncoding;
        let err: Error = b64_err.into();
        assert!(matches!(err, Error::Decoding(_)));
    }

    // --- Previously missing error variant Display tests ---

    #[test]
    fn error_display_bcs() {
        let bcs_err = bcs::from_bytes::<String>(&[0xff, 0xff]).unwrap_err();
        let err = Error::Bcs(bcs_err);
        let msg = err.to_string();
        assert!(msg.contains("BCS serialization error"));
    }

    #[test]
    fn error_display_missing_transaction() {
        let err = Error::MissingTransaction(Digest::ZERO);
        let msg = err.to_string();
        assert!(msg.contains("Missing transaction for digest"));
    }

    #[test]
    fn error_display_missing_object_kind() {
        let err = Error::MissingObjectKind(ObjectId::ZERO);
        let msg = err.to_string();
        assert!(msg.contains("Missing object kind for object"));
    }

    #[test]
    fn error_display_missing_initial_shared_version() {
        let err = Error::MissingInitialSharedVersion(ObjectId::ZERO);
        let msg = err.to_string();
        assert!(msg.contains("Missing initial shared version for object"));
    }

    #[test]
    fn error_display_invalid_url() {
        let url_err = reqwest::Url::parse("not a valid url!@#$").unwrap_err();
        let err = Error::InvalidUrl(url_err);
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn error_display_version_parsing() {
        let parse_result = GasStationVersion::from_str("not.valid.version");
        let version_err = parse_result.unwrap_err();
        let err = Error::VersionParsing(version_err);
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    use std::str::FromStr;
    use crate::builder::gas_station::GasStationVersion;
}
