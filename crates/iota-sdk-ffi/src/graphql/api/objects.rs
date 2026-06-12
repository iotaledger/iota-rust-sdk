// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use std::sync::Arc;

use iota_sdk::graphql_client::pagination::PaginationFilter;

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, pagination::ObjectPage, query_types::ObjectFilter},
    types::{
        object::{Object, ObjectId},
        version::Version,
    },
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return an object based on the provided `Address`.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn object(
        &self,
        object_id: &ObjectId,
        version: Option<Arc<Version>>,
    ) -> Result<Option<Arc<Object>>> {
        Ok(self
            .0
            .read()
            .await
            .object(**object_id, version.map(|v| **v))
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Return a page of objects based on the provided parameters.
    ///
    /// Use this function together with the `ObjectFilter::owner` to get the
    /// objects owned by an address.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn objects(
        &self,
        filter: Option<ObjectFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<ObjectPage> {
        Ok(self
            .0
            .read()
            .await
            .objects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Return the object's bcs content `Vec<u8>` based on the provided
    /// `Address`.
    pub async fn object_bcs(&self, object_id: &ObjectId) -> Result<Option<Vec<u8>>> {
        Ok(self.0.read().await.object_bcs(**object_id).await?)
    }

    /// Return the BCS of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn move_object_contents_bcs(
        &self,
        object_id: &ObjectId,
        version: Option<Arc<Version>>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .read()
            .await
            .move_object_contents_bcs(**object_id, version.map(|v| **v))
            .await?)
    }

    /// Return the contents' JSON of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn move_object_contents(
        &self,
        object_id: &ObjectId,
        version: Option<Arc<Version>>,
    ) -> Result<Option<serde_json::Value>> {
        Ok(self
            .0
            .read()
            .await
            .move_object_contents(**object_id, version.map(|v| **v))
            .await?)
    }
}
