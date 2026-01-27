// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Normalized Move Package API implementation.

use cynic::QueryBuilder;
use iota_types::Address;

use crate::{
    Client,
    error::Result,
    pagination::PaginationFilter,
    query_types::{
        MoveFunction, MoveModule, NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs,
        NormalizedMoveModuleQuery, NormalizedMoveModuleQueryArgs,
    },
};

impl Client {
    /// Return the normalized Move function data for the provided package,
    /// module, and function.
    pub async fn normalized_move_function(
        &self,
        package: Address,
        module: &str,
        function: &str,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<MoveFunction>> {
        let operation = NormalizedMoveFunctionQuery::build(NormalizedMoveFunctionQueryArgs {
            address: package,
            module,
            function,
            version: version.into(),
        });
        let response = self.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|p| p.module)
            .and_then(|m| m.function))
    }

    /// Return the normalized Move module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep pagination
    // options?
    #[allow(clippy::too_many_arguments)]
    pub async fn normalized_move_module(
        &self,
        package: Address,
        module: &str,
        version: impl Into<Option<u64>>,
        pagination_filter_enums: PaginationFilter,
        pagination_filter_friends: PaginationFilter,
        pagination_filter_functions: PaginationFilter,
        pagination_filter_structs: PaginationFilter,
    ) -> Result<Option<MoveModule>> {
        let enums = self.pagination_filter(pagination_filter_enums).await;
        let friends = self.pagination_filter(pagination_filter_friends).await;
        let functions = self.pagination_filter(pagination_filter_functions).await;
        let structs = self.pagination_filter(pagination_filter_structs).await;
        let operation = NormalizedMoveModuleQuery::build(NormalizedMoveModuleQueryArgs {
            package,
            module,
            version: version.into(),
            after_enums: enums.after.as_deref(),
            after_functions: functions.after.as_deref(),
            after_structs: structs.after.as_deref(),
            after_friends: friends.after.as_deref(),
            before_enums: enums.after.as_deref(),
            before_functions: functions.before.as_deref(),
            before_structs: structs.before.as_deref(),
            before_friends: friends.before.as_deref(),
            first_enums: enums.first,
            first_functions: functions.first,
            first_structs: structs.first,
            first_friends: friends.first,
            last_enums: enums.last,
            last_functions: functions.last,
            last_structs: structs.last,
            last_friends: friends.last,
        });
        let response = self.run_query(&operation).await?;

        Ok(response.package.and_then(|p| p.module))
    }
}
