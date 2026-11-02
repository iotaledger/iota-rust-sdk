// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction Builder errors.

use iota_types::{Address, ObjectId, TransactionDigest};

use crate::unresolved::Argument;

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
    #[error("Missing transaction for digest {0}")]
    MissingTransaction(TransactionDigest),
    #[error("Missing gas budget")]
    MissingGasBudget,
    #[error("Missing gas price")]
    MissingGasPrice,
    #[error("Missing protocol value: {name}")]
    MissingProtocolValue { name: String },
    #[error("Invalid protocol value: {name} = {value}")]
    InvalidProtocolValue { name: String, value: String },
    #[error("Unknown shared object mutability for object {0}")]
    SharedObjectMutability(ObjectId),
    #[error("only programmable transactions can be converted into a TransactionBuilder")]
    UnsupportedTransactionKind,
    #[error(
        "command {command} refers to {argument:?}, which is neither an input of the transaction nor the result of an earlier command"
    )]
    InvalidArgument { command: usize, argument: Argument },
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
    #[error("the gas sponsor executed transaction {got}, expected {expected}")]
    SponsorDigestMismatch {
        expected: TransactionDigest,
        got: TransactionDigest,
    },
    #[error(transparent)]
    Lookup(#[from] LookupError),
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
    pub fn gas_sponsor<E: 'static + std::error::Error + Send + Sync>(e: E) -> Self {
        Self::GasSponsor(Box::new(e))
    }
}

/// A response from a [`TransactionBuilderLedgerClient`] that does not match
/// what was requested.
///
/// [`TransactionBuilderLedgerClient`]: crate::TransactionBuilderLedgerClient
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The client returned a different object than the one requested.
    #[error("requested object {requested}, but the client responded with object {returned}")]
    ObjectIdMismatch {
        /// The object requested.
        requested: ObjectId,
        /// The object the client returned.
        returned: ObjectId,
    },
    /// The client left a requested object out of its response.
    #[error("the client gave no response for requested object {object_id}")]
    MissingObject {
        /// The object left without a response.
        object_id: ObjectId,
    },
    /// The client responded with more objects than were requested.
    #[error("requested {requested} objects, but the client responded with {returned}")]
    ExtraObjects {
        /// How many objects were requested.
        requested: usize,
        /// How many objects the client responded with.
        returned: usize,
    },
}
