// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Error as Base64Error;
use iota_types::ObjectId;

#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
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
    #[error("Missing sender")]
    MissingSender,
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
    #[error("Unknown shared object mutability for object {0}")]
    SharedObjectMutability(ObjectId),
    #[error("Unsupported literal")]
    UnsupportedLiteral,
}
