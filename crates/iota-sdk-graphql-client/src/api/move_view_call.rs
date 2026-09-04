// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cynic::QueryBuilder;
use iota_transaction_builder::types::MoveViewArgList;
use iota_types::TypeTag;

use crate::{
    Client,
    error::Result,
    query_types::{MoveViewCallArgs, MoveViewCallQuery, MoveViewResult},
};

impl Client {
    /// Execute a Move View Function with raw JSON arguments.
    ///
    /// This is an alternative to [`Client::move_view_call`] that accepts raw
    /// JSON values instead of typed arguments.
    ///
    /// A View Function is a function in a Move module with a return type that
    /// does not alter the state of the ledger. When using this interface,
    /// no transactions are submitted to the network for inclusion into the
    /// ledger.
    ///
    /// # Arguments
    /// * `function_name` - The Move function fully qualified name as
    ///   `<package_id>::<module_name>::<function_name>`, e.g.,
    ///   `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The arguments to be passed into the Move function, in
    ///   JSON format
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    pub async fn move_view_call_json(
        &self,
        function_name: impl Into<String>,
        type_arguments: impl Into<Option<Vec<String>>>,
        arguments: impl Into<Option<Vec<serde_json::Value>>>,
    ) -> Result<MoveViewResult> {
        let operation = MoveViewCallQuery::build(MoveViewCallArgs {
            function_name: function_name.into(),
            type_arguments: type_arguments.into(),
            arguments: arguments.into(),
        });
        let response = self.run_query(&operation).await?;

        Ok(response.move_view_call)
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
    /// See [`MoveViewCallBuilder`](iota_transaction_builder::MoveViewCallBuilder)
    /// for a call that is assembled argument by argument.
    ///
    /// The use of this interface does not require signature checks (even for
    /// functions that take Owned Objects as input) or gas coins, as it does
    /// not alter ledger state. Spam attacks are dealt with at the RPC level
    /// rather than execution level.
    ///
    /// # Arguments
    /// * `function_name` - The Move function fully qualified name as
    ///   `<package_id>::<module_name>::<function_name>`, e.g.,
    ///   `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The typed arguments to be passed into the Move function
    ///
    /// # Example
    /// ```rust,ignore
    /// // The `view_demo` package published on testnet, and the shared
    /// // `view_demo::shop::Shop` created when it was published.
    /// let package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";
    /// let shop = ObjectId::from_str(
    ///     "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20",
    /// )?;
    ///
    /// // Single argument: wrap in a list or tuple
    /// let result = client
    ///     .move_view_call(format!("{package}::shop::total_revenue"), None, (shop,))
    ///     .await?;
    /// ```
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    pub async fn move_view_call<A: MoveViewArgList>(
        &self,
        function_name: impl Into<String>,
        type_arguments: impl Into<Option<Vec<TypeTag>>>,
        arguments: A,
    ) -> Result<MoveViewResult> {
        let type_args_strings = type_arguments
            .into()
            .map(|tags| tags.into_iter().map(|t| t.to_string()).collect());
        self.move_view_call_json(
            function_name,
            type_args_strings,
            Some(arguments.to_json_vec()),
        )
        .await
    }
}
