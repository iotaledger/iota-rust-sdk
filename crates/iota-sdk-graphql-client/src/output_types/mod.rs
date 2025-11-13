// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use base64ct::Encoding;
use cynic::serde;
use iota_types::{
    DryRunEffect, DryRunMutation, DryRunReturn, SignedTransaction, TransactionArgument,
    TransactionEffects, TypeTag,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    error::{Error, Kind, Result},
    query_types::{
        DryRunEffect as GraphQLDryRunEffect, DryRunMutation as GraphQLDryRunMutation,
        DryRunReturn as GraphQLDryRunReturn,
    },
};

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
        let type_tag = TypeTag::from_str(&mutation.type_.repr)?;
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
        let type_tag = TypeTag::from_str(&return_val.type_.repr)?;
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
                    ix: input.ix as u32,
                })
            }
            crate::query_types::TransactionArgument::Result(result) => {
                Ok(TransactionArgument::Result {
                    cmd: result.cmd as u32,
                    ix: result.ix.map(|ix| ix as u32),
                })
            }
            crate::query_types::TransactionArgument::Unknown => Err(Error::from_error(
                Kind::Deserialization,
                "Unknown transaction argument type",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionDataEffects {
    pub tx: SignedTransaction,
    pub effects: TransactionEffects,
}

/// The name part of a dynamic field, including its type, bcs, and json
/// representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicFieldName {
    /// The type name of this dynamic field name
    pub type_: TypeTag,
    /// The bcs bytes of this dynamic field name
    pub bcs: Vec<u8>,
    /// The json representation of the dynamic field name
    pub json: Option<serde_json::Value>,
}

/// The value part of a dynamic field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicFieldValue {
    pub type_: TypeTag,
    pub bcs: Vec<u8>,
}

/// The output of a dynamic field query, that includes the name, value, and
/// value's json representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
            expected_type, &self.name.type_,
            "Expected type {expected_type}, but got {}",
            &self.name.type_
        );

        let bcs = &self.name.bcs;
        bcs::from_bytes::<T>(bcs).map_err(Into::into)
    }

    /// Deserialize the value of the dynamic field into the specified type.
    pub fn deserialize_value<T: DeserializeOwned>(&self, expected_type: &TypeTag) -> Result<T> {
        let typetag = self.value.as_ref().map(|dfv| &dfv.type_);
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
