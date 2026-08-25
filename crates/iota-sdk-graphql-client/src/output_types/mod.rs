// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use base64ct::Encoding;
use cynic::serde;
use iota_types::{SignedTransaction, TransactionEffects, TypeTag};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    error::{Error, Kind, Result},
    query_types::{
        DryRunEffect as GraphQLDryRunEffect, DryRunMutation as GraphQLDryRunMutation,
        DryRunReturn as GraphQLDryRunReturn,
    },
};

/// The result of a simulation (dry run), which includes the effects of the
/// transaction and intermediate results for each command.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DryRunResult {
    /// The error that occurred during dry run execution, if any.
    pub error: Option<String>,
    /// The intermediate results for each command of the dry run execution,
    /// including contents of mutated references and return values.
    pub results: Vec<DryRunEffect>,
    /// The transaction block representing the dry run execution.
    pub transaction: Option<SignedTransaction>,
    /// The effects of the transaction execution.
    pub effects: Option<TransactionEffects>,
}

/// Effects of a single command in the dry run, including mutated references
/// and return values.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DryRunEffect {
    /// Changes made to arguments that were mutably borrowed by this
    /// command.
    pub mutated_references: Vec<DryRunMutation>,
    /// Return results of this command.
    pub return_values: Vec<DryRunReturn>,
}

/// A mutation to an argument that was mutably borrowed by a command.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DryRunMutation {
    /// The transaction argument that was mutated.
    pub input: TransactionArgument,
    /// The Move type of the mutated value.
    pub type_tag: TypeTag,
    /// The BCS representation of the mutated value.
    pub bcs: Vec<u8>,
}

/// A return value from a command in the dry run.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DryRunReturn {
    /// The Move type of the return value.
    pub type_tag: TypeTag,
    /// The BCS representation of the return value.
    pub bcs: Vec<u8>,
}

/// A transaction argument used in programmable transactions.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
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
        /// If the previous command returns multiple values, this is the
        /// index of the individual result among the multiple
        /// results from that command (also 0-indexed).
        index: Option<u32>,
    },
}

impl TryFrom<&GraphQLDryRunEffect> for DryRunEffect {
    type Error = Error;

    fn try_from(effect: &GraphQLDryRunEffect) -> Result<Self> {
        let mutated_references = effect
            .mutated_references
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(DryRunMutation::try_from)
            .collect::<Result<Vec<_>>>()?;

        let return_values = effect
            .return_values
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(DryRunReturn::try_from)
            .collect::<Result<Vec<_>>>()?;

        Ok(DryRunEffect {
            mutated_references,
            return_values,
        })
    }
}

impl TryFrom<&GraphQLDryRunMutation> for DryRunMutation {
    type Error = Error;

    fn try_from(mutation: &GraphQLDryRunMutation) -> Result<Self> {
        let input = TransactionArgument::try_from(&mutation.input)?;
        let type_tag = TypeTag::from_str(&mutation.move_type.repr)?;
        let bcs = base64ct::Base64::decode_vec(&mutation.bcs.0)?;

        Ok(DryRunMutation {
            input,
            type_tag,
            bcs,
        })
    }
}

impl TryFrom<&GraphQLDryRunReturn> for DryRunReturn {
    type Error = Error;

    fn try_from(return_val: &GraphQLDryRunReturn) -> Result<Self> {
        let type_tag = TypeTag::from_str(&return_val.move_type.repr)?;
        let bcs = base64ct::Base64::decode_vec(&return_val.bcs.0)?;

        Ok(DryRunReturn { type_tag, bcs })
    }
}

impl TryFrom<&crate::query_types::TransactionArgument> for TransactionArgument {
    type Error = Error;

    fn try_from(arg: &crate::query_types::TransactionArgument) -> Result<Self> {
        match arg {
            crate::query_types::TransactionArgument::GasCoin(_) => Ok(TransactionArgument::GasCoin),
            crate::query_types::TransactionArgument::Input(input) => {
                Ok(TransactionArgument::Input {
                    index: input.ix as u32,
                })
            }
            crate::query_types::TransactionArgument::Result(result) => {
                Ok(TransactionArgument::Result {
                    cmd: result.cmd as u32,
                    index: result.ix.map(|ix| ix as u32),
                })
            }
            crate::query_types::TransactionArgument::Unknown => Err(Error::from_error(
                Kind::Deserialization,
                "Unknown transaction argument type",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionDataEffects {
    pub tx: SignedTransaction,
    pub effects: TransactionEffects,
}

/// The name part of a dynamic field, including its type, bcs, and json
/// representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicFieldName {
    /// The type name of this dynamic field name
    pub type_tag: TypeTag,
    /// The bcs bytes of this dynamic field name
    pub bcs: Vec<u8>,
    /// The json representation of the dynamic field name
    pub json: Option<serde_json::Value>,
}

/// The value part of a dynamic field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicFieldValue {
    pub type_tag: TypeTag,
    pub bcs: Vec<u8>,
}

/// The output of a dynamic field query, that includes the name, value, and
/// value's json representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicFieldOutput {
    /// The name of the dynamic field
    pub name: DynamicFieldName,
    /// The dynamic field value typename and bcs
    pub value: Option<DynamicFieldValue>,
    /// The json representation of the dynamic field value object
    pub value_as_json: Option<serde_json::Value>,
}

/// Helper struct for passing a value that has a type that implements Serialize,
/// for the dynamic fields API.
pub struct NameValue(pub Vec<u8>);

/// Helper struct for passing a raw bcs value.
#[derive(derive_more::From)]
pub struct BcsName(pub Vec<u8>);

impl<T: Serialize> From<T> for NameValue {
    fn from(value: T) -> Self {
        NameValue(bcs::to_bytes(&value).unwrap())
    }
}

impl From<BcsName> for NameValue {
    fn from(value: BcsName) -> Self {
        NameValue(value.0)
    }
}

impl DynamicFieldOutput {
    /// Deserialize the name of the dynamic field into the specified type.
    pub fn deserialize_name<T: DeserializeOwned>(&self, expected_type: &TypeTag) -> Result<T> {
        assert_eq!(
            expected_type, &self.name.type_tag,
            "Expected type {expected_type}, but got {}",
            self.name.type_tag
        );

        let bcs = &self.name.bcs;
        bcs::from_bytes::<T>(bcs).map_err(Into::into)
    }

    /// Deserialize the value of the dynamic field into the specified type.
    pub fn deserialize_value<T: DeserializeOwned>(&self, expected_type: &TypeTag) -> Result<T> {
        let typetag = self.value.as_ref().map(|dfv| &dfv.type_tag);
        assert_eq!(
            Some(&expected_type),
            typetag.as_ref(),
            "Expected type {expected_type}, but got {typetag:?}"
        );

        if let Some(dfv) = &self.value {
            bcs::from_bytes::<T>(&dfv.bcs).map_err(Into::into)
        } else {
            Err(Error::from_error(Kind::Deserialization, "Value is missing"))
        }
    }
}
