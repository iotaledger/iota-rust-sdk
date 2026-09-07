// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    move_core::TypeTag,
    transaction::{SignedTransaction, TransactionEffects},
};

/// A transaction argument used in programmable transactions.
#[derive(uniffi::Enum)]
pub enum TransactionArgument {
    /// Reference to the gas coin.
    GasCoin,
    /// An input to the programmable transaction block.
    Input {
        /// Index of the programmable transaction block input (0-indexed).
        index: u32,
    },
    /// The result of another transaction command.
    Result {
        /// The index of the previous command (0-indexed) that returned this
        /// result.
        cmd: u32,
        /// If the previous command returns multiple values, this is the index
        /// of the individual result among the multiple results from
        /// that command (also 0-indexed).
        index: Option<u32>,
    },
}

impl From<iota_sdk::graphql_client::TransactionArgument> for TransactionArgument {
    fn from(value: iota_sdk::graphql_client::TransactionArgument) -> Self {
        match value {
            iota_sdk::graphql_client::TransactionArgument::GasCoin => TransactionArgument::GasCoin,
            iota_sdk::graphql_client::TransactionArgument::Input { index } => {
                TransactionArgument::Input { index }
            }
            iota_sdk::graphql_client::TransactionArgument::Result { cmd, index } => {
                TransactionArgument::Result { cmd, index }
            }
            _ => unimplemented!(
                "a new TransactionArgument enum variant was added and needs to be handled"
            ),
        }
    }
}

impl From<TransactionArgument> for iota_sdk::graphql_client::TransactionArgument {
    fn from(value: TransactionArgument) -> Self {
        match value {
            TransactionArgument::GasCoin => iota_sdk::graphql_client::TransactionArgument::GasCoin,
            TransactionArgument::Input { index } => {
                iota_sdk::graphql_client::TransactionArgument::Input { index }
            }
            TransactionArgument::Result { cmd, index } => {
                iota_sdk::graphql_client::TransactionArgument::Result { cmd, index }
            }
        }
    }
}

/// A return value from a command in the dry run.
#[derive(uniffi::Record)]
pub struct DryRunReturn {
    /// The Move type of the return value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the return value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DryRunReturn> for DryRunReturn {
    fn from(value: iota_sdk::graphql_client::DryRunReturn) -> Self {
        DryRunReturn {
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DryRunReturn> for iota_sdk::graphql_client::DryRunReturn {
    fn from(value: DryRunReturn) -> Self {
        iota_sdk::graphql_client::DryRunReturn {
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// A mutation to an argument that was mutably borrowed by a command.
#[derive(uniffi::Record)]
pub struct DryRunMutation {
    /// The transaction argument that was mutated.
    pub input: TransactionArgument,
    /// The Move type of the mutated value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the mutated value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DryRunMutation> for DryRunMutation {
    fn from(value: iota_sdk::graphql_client::DryRunMutation) -> Self {
        DryRunMutation {
            input: value.input.into(),
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DryRunMutation> for iota_sdk::graphql_client::DryRunMutation {
    fn from(value: DryRunMutation) -> Self {
        iota_sdk::graphql_client::DryRunMutation {
            input: value.input.into(),
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// Effects of a single command in the dry run, including mutated references
/// and return values.
#[derive(uniffi::Record)]
pub struct DryRunEffect {
    /// Changes made to arguments that were mutably borrowed by this command.
    pub mutated_references: Vec<DryRunMutation>,
    /// Return results of this command.
    pub return_values: Vec<DryRunReturn>,
}

impl From<iota_sdk::graphql_client::DryRunEffect> for DryRunEffect {
    fn from(value: iota_sdk::graphql_client::DryRunEffect) -> Self {
        DryRunEffect {
            mutated_references: value
                .mutated_references
                .into_iter()
                .map(Into::into)
                .collect(),
            return_values: value.return_values.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<DryRunEffect> for iota_sdk::graphql_client::DryRunEffect {
    fn from(value: DryRunEffect) -> Self {
        iota_sdk::graphql_client::DryRunEffect {
            mutated_references: value
                .mutated_references
                .into_iter()
                .map(Into::into)
                .collect(),
            return_values: value.return_values.into_iter().map(Into::into).collect(),
        }
    }
}

/// The result of a simulation (dry run), which includes the effects of the
/// transaction, any errors that may have occurred, and intermediate results for
/// each command.
#[derive(uniffi::Record)]
pub struct DryRunResult {
    /// The error that occurred during dry run execution, if any.
    pub error: Option<String>,
    /// The intermediate results for each command of the dry run execution,
    /// including contents of mutated references and return values.
    pub results: Vec<DryRunEffect>,
    /// The transaction block representing the dry run execution.
    pub transaction: Option<SignedTransaction>,
    /// The effects of the transaction execution.
    pub effects: Option<Arc<TransactionEffects>>,
}

impl From<iota_sdk::graphql_client::DryRunResult> for DryRunResult {
    fn from(value: iota_sdk::graphql_client::DryRunResult) -> Self {
        DryRunResult {
            error: value.error,
            results: value.results.into_iter().map(Into::into).collect(),
            transaction: value.transaction.map(Into::into),
            effects: value.effects.map(Into::into).map(Arc::new),
        }
    }
}

impl From<DryRunResult> for iota_sdk::graphql_client::DryRunResult {
    fn from(value: DryRunResult) -> Self {
        iota_sdk::graphql_client::DryRunResult {
            error: value.error,
            results: value.results.into_iter().map(Into::into).collect(),
            transaction: value.transaction.map(Into::into),
            effects: value.effects.map(|v| v.0.clone()),
        }
    }
}
