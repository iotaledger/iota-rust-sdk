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
    Signature(iota_crypto::SignatureError),
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
}
