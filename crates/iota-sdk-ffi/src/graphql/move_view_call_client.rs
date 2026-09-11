// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`MoveViewCallClient`] for the FFI [`GraphQLClient`].

use std::sync::Arc;

use iota_sdk::{graphql_client::Client, transaction_builder::MoveViewCallClient};

use crate::{
    graphql::client::GraphQLClient,
    transaction_builder::move_view_call_builder::{ClientMoveViewCallBuilder, MoveViewCallBuilder},
    types::object::ObjectId,
};

#[uniffi::export]
impl GraphQLClient {
    /// Create a new `MoveViewCallBuilder` with the given package, module, and
    /// function.
    pub fn move_view_call_builder(
        self: Arc<GraphQLClient>,
        package: &ObjectId,
        module: String,
        function: String,
    ) -> ClientMoveViewCallBuilder {
        MoveViewCallBuilder::new(package, module, function).with_client(self)
    }
}

impl MoveViewCallClient for GraphQLClient {
    type Error = <Client as MoveViewCallClient>::Error;

    async fn move_view_call(
        &self,
        function_name: &str,
        type_arguments: &[iota_sdk::types::TypeTag],
        arguments: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>, Self::Error> {
        MoveViewCallClient::move_view_call(
            &*self.0.read().await,
            function_name,
            type_arguments,
            arguments,
        )
        .await
    }
}
