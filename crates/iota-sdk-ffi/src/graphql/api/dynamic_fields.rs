// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dynamic fields API implementation.

use iota_sdk::graphql_client::pagination::PaginationFilter;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient, pagination::DynamicFieldOutputPage, query_types::DynamicFieldOutput,
    },
    types::{address::Address, move_core::TypeTag},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Access a dynamic field on an object using its name. Names are arbitrary
    /// Move values whose type have copy, drop, and store, and are specified
    /// using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument is a json serialized type.
    ///
    /// This returns `DynamicFieldOutput` which contains the name, the value
    /// as json, and object.
    pub async fn dynamic_field(
        &self,
        address: &Address,
        type_tag: &TypeTag,
        name: serde_json::Value,
    ) -> Result<Option<DynamicFieldOutput>> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_field(**address, type_tag.0.clone(), name)
            .await?
            .map(Into::into))
    }

    /// Access a dynamic object field on an object using its name. Names are
    /// arbitrary Move values whose type have copy, drop, and store, and are
    /// specified using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument is a json serialized type.
    ///
    /// This returns `DynamicFieldOutput` which contains the name, the value
    /// as json, and object.
    pub async fn dynamic_object_field(
        &self,
        address: &Address,
        type_tag: &TypeTag,
        name: serde_json::Value,
    ) -> Result<Option<DynamicFieldOutput>> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_object_field(**address, type_tag.0.clone(), name)
            .await?
            .map(Into::into))
    }

    /// Get a page of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    ///
    /// This returns a page of `DynamicFieldOutput`s.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn dynamic_fields(
        &self,
        address: &Address,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<DynamicFieldOutputPage> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_fields(**address, pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }
}
