// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Base64, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Mutation",
    variables = "ExecuteTransactionArgs"
)]
pub(crate) struct ExecuteTransactionQuery {
    #[arguments(signatures: $signatures, txBytes: $tx_bytes)]
    pub execute_transaction_block: ExecutionResult,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct ExecuteTransactionArgs {
    pub signatures: Vec<String>,
    pub tx_bytes: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ExecutionResult")]
pub(crate) struct ExecutionResult {
    pub effects: TransactionBlockEffects,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockEffects")]
pub(crate) struct TransactionBlockEffects {
    pub bcs: Base64,
}
