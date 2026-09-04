// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`MoveViewCallClient`] for the GraphQL [`Client`].

use iota_transaction_builder::{MoveViewCallBuilder, MoveViewCallClient};
use iota_types::{ObjectId, TypeTag};

use crate::{
    Client,
    error::{Error, Kind},
};

impl Client {
    /// Create a new [`MoveViewCallBuilder`] with the given package, module, and
    /// function.
    pub fn move_view_call_builder(
        &self,
        package: impl Into<ObjectId>,
        module: impl Into<String>,
        function: impl Into<String>,
    ) -> MoveViewCallBuilder<&Self> {
        MoveViewCallBuilder::new(package.into(), module.into(), function.into()).with_client(self)
    }
}

impl MoveViewCallClient for Client {
    type Error = crate::error::Error;

    async fn move_view_call(
        &self,
        function_name: &str,
        type_arguments: &[TypeTag],
        arguments: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>, Self::Error> {
        let result = self
            .move_view_call_json(
                function_name,
                (!type_arguments.is_empty())
                    .then(|| type_arguments.iter().map(|t| t.to_string()).collect()),
                (!arguments.is_empty()).then(|| arguments.to_vec()),
            )
            .await?;

        match (result.error, result.results) {
            (Some(error), _) => Err(Error::from_message(Kind::Query, error)),
            (None, Some(results)) => Ok(results),
            (None, None) => Err(Error::empty_response_error()),
        }
    }
}
