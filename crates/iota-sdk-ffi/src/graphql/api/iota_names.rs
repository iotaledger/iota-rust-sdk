// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Names API implementation.

use std::sync::Arc;

use iota_sdk::{graphql_client::pagination::PaginationFilter, types::iota_names::NameFormat};

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, pagination::NameRegistrationPage},
    types::{address::Address, iota_names::Name},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return the resolved address for the given name.
    pub async fn iota_names_lookup(&self, name: &str) -> Result<Option<Arc<Address>>> {
        Ok(self
            .0
            .read()
            .await
            .iota_names_lookup(name)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Find all registration NFTs for the given address.
    pub async fn iota_names_registrations(
        &self,
        address: &Address,
        pagination_filter: PaginationFilter,
    ) -> Result<NameRegistrationPage> {
        Ok(self
            .0
            .read()
            .await
            .iota_names_registrations(**address, pagination_filter)
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
            .0
            .read()
            .await
            .iota_names_default_name(**address, format)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }
}
