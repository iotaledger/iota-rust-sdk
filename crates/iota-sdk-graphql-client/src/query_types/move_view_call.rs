// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{JsonValue, schema};

/// GraphQL query for executing a Move View Function.
///
/// A View Function is a function in a Move module with a return type that does
/// not alter the state of the ledger. When using the Move View Function
/// interface, no transactions are submitted to the network for inclusion into
/// the ledger.
///
/// Move View Functions are callable via this RPC method that supports type
/// parameters and function arguments. The use of this interface does not
/// require signature checks or gas coins, as it does not alter ledger state.
/// Spam attacks are dealt with at the RPC level rather than execution level.
///
/// Returned results are resolved (Move types deserialized) and formatted in
/// JSON.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "MoveViewCallArgs")]
pub struct MoveViewCallQuery {
    #[arguments(functionName: $function_name, typeArgs: $type_arguments, arguments: $arguments)]
    pub move_view_call: MoveViewResult,
}

/// The result of executing a Move View Function.
///
/// Execution errors are captured in the `error` field, in which case the
/// `results` field will be `None`. On success, the `results` field will contain
/// the return values of the Move view function, and the `error` field will be
/// `None`.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveViewResult")]
pub struct MoveViewResult {
    /// Execution error from executing the Move view function.
    pub error: Option<String>,
    /// The return values of the Move view function, resolved and formatted as
    /// JSON.
    pub results: Option<Vec<JsonValue>>,
}

/// Arguments for the Move View Call GraphQL query.
///
/// The function name should be fully qualified as
/// `<package_id>::<module_name>::<function_name>`,
/// e.g., `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`.
#[derive(cynic::QueryVariables, Debug)]
pub struct MoveViewCallArgs {
    /// The Move function fully qualified name as
    /// `<package_id>::<module_name>::<function_name>`.
    pub function_name: String,
    /// The type arguments of the Move function.
    pub type_arguments: Option<Vec<String>>,
    /// The arguments to be passed into the Move function, in JSON format.
    pub arguments: Option<Vec<JsonValue>>,
}
