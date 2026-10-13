// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::graphql_client::MoveViewCallJsonQuery;

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::GraphQLMoveViewResult},
    helpers::SetIfSome,
    move_view_call::MoveViewArg,
    types::{move_core::TypeTag, object::ObjectId},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Execute a Move View Function with raw JSON arguments.
    ///
    /// This is an alternative to [`GraphQLClient::move_view_call`] that accepts
    /// raw JSON values instead of typed arguments.
    ///
    /// A View Function is a function in a Move module with a return type that
    /// does not alter the state of the ledger. When using this interface,
    /// no transactions are submitted to the network for inclusion into the
    /// ledger.
    ///
    /// # Arguments
    /// * `package` - The package the Move function is defined in
    /// * `module` - The module the Move function is defined in
    /// * `function` - The name of the Move function
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The arguments to be passed into the Move function, in
    ///   JSON format
    ///
    /// # Returns
    /// A `GraphQLMoveViewResult` containing either execution results (return
    /// values) or an error.
    #[uniffi::method(default(type_arguments = None, arguments = None))]
    pub async fn move_view_call_json(
        &self,
        package: &ObjectId,
        module: String,
        function: String,
        type_arguments: Option<Vec<String>>,
        arguments: Option<Vec<serde_json::Value>>,
    ) -> Result<GraphQLMoveViewResult> {
        Ok(self
            .client()
            .move_view_call_json(**package, module, function)
            .set_if_some(type_arguments, MoveViewCallJsonQuery::type_arguments)
            .set_if_some(arguments, MoveViewCallJsonQuery::arguments)
            .await?
            .into())
    }

    /// Execute a Move View Function.
    ///
    /// A View Function is a function in a Move module with a return type that
    /// does not alter the state of the ledger. When using this interface,
    /// no transactions are submitted to the network for inclusion into the
    /// ledger.
    ///
    /// This method allows calling nearly any Move function with a return type
    /// and any arguments. The function's result values are provided and
    /// decoded using the appropriate Move type, then formatted in JSON.
    ///
    /// The use of this interface does not require signature checks (even for
    /// functions that take Owned Objects as input) or gas coins, as it does
    /// not alter ledger state. Spam attacks are dealt with at the RPC level
    /// rather than execution level.
    ///
    /// # Arguments
    /// * `package` - The package the Move function is defined in
    /// * `module` - The module the Move function is defined in
    /// * `function` - The name of the Move function
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The typed arguments to be passed into the Move function
    ///
    /// # Returns
    /// A `GraphQLMoveViewResult` containing either execution results (return
    /// values) or an error.
    #[uniffi::method(default(type_arguments = None, arguments = None))]
    pub async fn move_view_call(
        &self,
        package: &ObjectId,
        module: String,
        function: String,
        type_arguments: Option<Vec<Arc<TypeTag>>>,
        arguments: Option<Vec<Arc<MoveViewArg>>>,
    ) -> Result<GraphQLMoveViewResult> {
        let arguments = arguments.map(|args| args.iter().map(|arg| arg.to_json()).collect());
        let type_arguments =
            type_arguments.map(|tags| tags.iter().map(|t| t.to_string()).collect());

        self.move_view_call_json(package, module, function, type_arguments, arguments)
            .await
    }
}
