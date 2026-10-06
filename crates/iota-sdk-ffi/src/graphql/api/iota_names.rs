// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Names API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient, pagination::GraphQLNameRegistrationPage,
        query_types::GraphQLPaginationFilter,
    },
    types::{
        address::Address,
        iota_names::{Name, NameFormat},
    },
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return the resolved address for the given name.
    pub async fn iota_names_lookup(&self, name: &str) -> Result<Option<Arc<Address>>> {
        Ok(self
            .client()
            .iota_names_lookup(name)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Find all registration NFTs for the given address.
    pub async fn iota_names_registrations(
        &self,
        address: &Address,
        pagination_filter: GraphQLPaginationFilter,
    ) -> Result<GraphQLNameRegistrationPage> {
        Ok(self
            .client()
            .iota_names_registrations(**address)
            .pagination(pagination_filter.into())
            .await?
            .map(Into::into)
            .into())
    }

    /// Get the default name pointing to this address, if one exists.
    pub async fn iota_names_default_name(
        &self,
        address: &Address,
        format: Option<NameFormat>,
    ) -> Result<Option<Arc<Name>>> {
        Ok(self
            .client()
            .iota_names_default_name(**address, format.map(Into::into))
            .await?
            .map(Into::into)
            .map(Arc::new))
    }
}
