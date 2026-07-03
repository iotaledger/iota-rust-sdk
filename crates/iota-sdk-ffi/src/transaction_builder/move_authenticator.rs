// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    graphql::client::GraphQLClient,
    transaction_builder::ptb_arg::PTBArgument,
    types::{crypto::move_authenticator::MoveAuthenticator, move_core::TypeTag, object::ObjectId},
};

#[derive(uniffi::Object)]
pub struct MoveAuthenticatorBuilder(pub iota_sdk::transaction_builder::MoveAuthenticatorBuilder);

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl MoveAuthenticatorBuilder {
    /// Create a new move authenticator call with the account ID, function
    /// inputs, and generic types.
    #[uniffi::constructor]
    pub fn new(
        account_id: &ObjectId,
        call_args: Vec<Arc<PTBArgument>>,
        type_args: Vec<Arc<TypeTag>>,
    ) -> MoveAuthenticatorBuilder {
        Self(
            iota_sdk::transaction_builder::MoveAuthenticatorBuilder::new(account_id.0)
                .call_args(call_args)
                .type_args(type_args.into_iter().map(|v| v.0.clone())),
        )
    }

    /// Resolve this move authenticator builder into a `MoveAuthenticator` which
    /// can be used to execute a transaction.
    pub async fn finish(&self, client: &GraphQLClient) -> Result<MoveAuthenticator> {
        Ok(MoveAuthenticator(self.0.clone().finish(client).await?))
    }
}
