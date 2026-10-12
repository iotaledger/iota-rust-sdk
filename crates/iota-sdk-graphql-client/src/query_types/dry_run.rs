// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::ObjectReference;

use super::transaction::TransactionBlockEffects;
use crate::query_types::{Address, Base64, BigInt, MoveType, ObjectId, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DryRunArgs")]
pub(crate) struct DryRunQueryFragment {
    #[arguments(txBytes: $tx_bytes, skipChecks: $skip_checks, txMeta: $tx_meta)]
    pub dry_run_transaction_block: DryRunResult,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunResult")]
pub(crate) struct DryRunResult {
    pub error: Option<String>,
    pub results: Option<Vec<DryRunEffect>>,
    pub transaction: Option<DryRunTransactionBlock>,
    pub suggested_gas_price: Option<BigInt>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct DryRunTransactionBlock {
    pub bcs_unsigned: Option<Base64>,
    pub effects: Option<TransactionBlockEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunEffect")]
pub(crate) struct DryRunEffect {
    pub mutated_references: Option<Vec<DryRunMutation>>,
    pub return_values: Option<Vec<DryRunReturn>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunMutation")]
pub(crate) struct DryRunMutation {
    pub input: TransactionArgument,
    #[cynic(rename = "type")]
    pub move_type: MoveType,
    pub bcs: Base64,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunReturn")]
pub(crate) struct DryRunReturn {
    #[cynic(rename = "type")]
    pub move_type: MoveType,
    pub bcs: Base64,
}

#[derive(cynic::InlineFragments, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionArgument")]
#[non_exhaustive]
pub(crate) enum TransactionArgument {
    GasCoin(GasCoin),
    Input(Input),
    Result(ResultArg),
    #[cynic(fallback)]
    Unknown,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "GasCoin")]
pub(crate) struct GasCoin {
    #[cynic(rename = "_")]
    pub _placeholder: Option<bool>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Input")]
pub(crate) struct Input {
    pub ix: i32,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Result")]
pub(crate) struct ResultArg {
    pub cmd: i32,
    pub ix: Option<i32>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct DryRunArgs {
    pub tx_bytes: String,
    pub skip_checks: bool,
    pub tx_meta: Option<TransactionMetadata>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "TransactionMetadata")]
pub struct TransactionMetadata {
    pub gas_budget: Option<u64>,
    pub gas_objects: Option<Vec<ObjectRef>>,
    pub gas_price: Option<u64>,
    pub gas_sponsor: Option<Address>,
    pub sender: Option<Address>,
}

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectRef")]
pub struct ObjectRef {
    pub address: ObjectId,
    pub digest: String,
    pub version: u64,
}

impl From<ObjectReference> for ObjectRef {
    fn from(value: ObjectReference) -> Self {
        ObjectRef {
            address: *value.object_id(),
            version: value.version().as_u64(),
            digest: value.digest().to_string(),
        }
    }
}
