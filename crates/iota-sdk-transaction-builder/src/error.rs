// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction Builder errors.

use base64ct::Error as Base64Error;
use iota_types::{Address, ObjectId, TransactionDigest};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum TransactionBuilderError {
    #[error("Conversion error due to input issue: {0}")]
    Input(String),
    #[error("Gas object should be an immutable or owned object")]
    WrongGasObject,
    #[error("gas coin {object_id} cannot also be passed to a command")]
    GasCoinAsArgument { object_id: ObjectId },
    #[error(
        "transferring gas coin {transferred} would also transfer gas coin {missing} due to gas smashing; if this is intentional, add coin {missing} to the transferred objects"
    )]
    IncompleteGasTransfer {
        transferred: ObjectId,
        missing: ObjectId,
    },
    #[error("only one command can transfer the gas coin")]
    GasCoinTransferredMoreThanOnce,
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
    MissingTransaction(TransactionDigest),
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
    #[error("only programmable transactions can be converted into a TransactionBuilder")]
    UnsupportedTransactionKind,
    #[error("Invalid account for move authenticator: {0}")]
    InvalidMoveAuthAccount(String),
    #[error("Invalid argument for move authenticator: {0}")]
    InvalidMoveAuthArg(String),
    #[error("gas coins were set on the transaction, but the gas sponsor supplies the gas payment")]
    SponsorGasConflict,
    #[error(
        "sponsor {sponsor} was set on the transaction, but the gas sponsor supplies the gas payment"
    )]
    SponsorAddressConflict { sponsor: Address },
    #[error(transparent)]
    GasSponsor(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Signature(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Client(Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to dry run transaction: {0}")]
    DryRun(String),
}

impl TransactionBuilderError {
    /// Create a client error
    pub fn client<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::Client(Box::new(e))
    }

    /// Create a signature error
    pub fn signature<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::Signature(Box::new(e))
    }

    /// Create a gas sponsor error
    pub fn sponsor<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::GasSponsor(Box::new(e))
    }
}
