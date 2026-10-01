// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    move_core::TypeTag,
    transaction::{SignedTransaction, TransactionEffects},
};

/// A transaction argument used in programmable transactions.
#[derive(uniffi::Enum)]
pub enum GraphQLTransactionArgument {
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

impl From<iota_sdk::graphql_client::TransactionArgument> for GraphQLTransactionArgument {
    fn from(value: iota_sdk::graphql_client::TransactionArgument) -> Self {
        match value {
            iota_sdk::graphql_client::TransactionArgument::GasCoin => {
                GraphQLTransactionArgument::GasCoin
            }
            iota_sdk::graphql_client::TransactionArgument::Input { index } => {
                GraphQLTransactionArgument::Input { index }
            }
            iota_sdk::graphql_client::TransactionArgument::Result { cmd, index } => {
                GraphQLTransactionArgument::Result { cmd, index }
            }
            _ => unimplemented!(
                "a new TransactionArgument enum variant was added and needs to be handled"
            ),
        }
    }
}

impl From<GraphQLTransactionArgument> for iota_sdk::graphql_client::TransactionArgument {
    fn from(value: GraphQLTransactionArgument) -> Self {
        match value {
            GraphQLTransactionArgument::GasCoin => {
                iota_sdk::graphql_client::TransactionArgument::GasCoin
            }
            GraphQLTransactionArgument::Input { index } => {
                iota_sdk::graphql_client::TransactionArgument::Input { index }
            }
            GraphQLTransactionArgument::Result { cmd, index } => {
                iota_sdk::graphql_client::TransactionArgument::Result { cmd, index }
            }
        }
    }
}

/// A return value from a command in the dry run.
#[derive(uniffi::Record)]
pub struct GraphQLDryRunReturn {
    /// The Move type of the return value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the return value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DryRunReturn> for GraphQLDryRunReturn {
    fn from(value: iota_sdk::graphql_client::DryRunReturn) -> Self {
        GraphQLDryRunReturn {
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

/// A mutation to an argument that was mutably borrowed by a command.
#[derive(uniffi::Record)]
pub struct GraphQLDryRunMutation {
    /// The transaction argument that was mutated.
    pub input: GraphQLTransactionArgument,
    /// The Move type of the mutated value.
    pub type_tag: Arc<TypeTag>,
    /// The BCS representation of the mutated value.
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DryRunMutation> for GraphQLDryRunMutation {
    fn from(value: iota_sdk::graphql_client::DryRunMutation) -> Self {
        GraphQLDryRunMutation {
            input: value.input.into(),
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

/// Effects of a single command in the dry run, including mutated references
/// and return values.
#[derive(uniffi::Record)]
pub struct GraphQLDryRunEffect {
    /// Changes made to arguments that were mutably borrowed by this command.
    pub mutated_references: Vec<GraphQLDryRunMutation>,
    /// Return results of this command.
    pub return_values: Vec<GraphQLDryRunReturn>,
}

impl From<iota_sdk::graphql_client::DryRunEffect> for GraphQLDryRunEffect {
    fn from(value: iota_sdk::graphql_client::DryRunEffect) -> Self {
        GraphQLDryRunEffect {
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
pub struct GraphQLDryRunResult {
    /// The error that occurred during dry run execution, if any.
    pub error: Option<String>,
    /// The intermediate results for each command of the dry run execution,
    /// including contents of mutated references and return values.
    pub results: Vec<GraphQLDryRunEffect>,
    /// The transaction block representing the dry run execution.
    pub transaction: Option<SignedTransaction>,
    /// The effects of the transaction execution.
    pub effects: Option<Arc<TransactionEffects>>,
}

impl From<iota_sdk::graphql_client::DryRunResult> for GraphQLDryRunResult {
    fn from(value: iota_sdk::graphql_client::DryRunResult) -> Self {
        GraphQLDryRunResult {
            error: value.error,
            results: value.results.into_iter().map(Into::into).collect(),
            transaction: value.transaction.map(Into::into),
            effects: value.effects.map(Into::into).map(Arc::new),
        }
    }
}
