// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Owned objects API implementation.

use std::sync::Arc;

use iota_sdk::grpc_client::read_mask_fields::OwnedObjectReadMask;

use crate::{
    error::{Result, SdkFfiError},
    grpc::{client::GrpcClient, output_types::OwnedObjectPage},
    types::{address::Address, move_core::StructTag, object::Object},
};

fn convert_objects(
    objects: Vec<iota_sdk::grpc_types::v1::object::Object>,
) -> Result<Vec<Arc<Object>>> {
    Ok(objects
        .iter()
        .map(|object| object.object().map_err(SdkFfiError::new))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(Into::into)
        .map(Arc::new)
        .collect())
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of objects owned by an address, optionally filtered
    /// by object type.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    #[uniffi::method(default(object_type = None, page_size = None, page_token = None))]
    pub async fn list_owned_objects(
        &self,
        owner: &Address,
        object_type: Option<Arc<StructTag>>,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<OwnedObjectPage> {
        let query = self.0.read().await.list_owned_objects(
            **owner,
            object_type.map(|object_type| object_type.0.clone()),
            page_size,
            page_token.map(Into::into),
            OwnedObjectReadMask::default(),
        );
        let page = query.await?.into_inner();
        Ok(OwnedObjectPage {
            objects: convert_objects(page.items)?,
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all objects owned by an address, optionally filtered by object
    /// type, auto-paginating up to `limit` objects. If `limit` is `None`,
    /// all objects are returned.
    #[uniffi::method(default(object_type = None, limit = None))]
    pub async fn list_all_owned_objects(
        &self,
        owner: &Address,
        object_type: Option<Arc<StructTag>>,
        limit: Option<u32>,
    ) -> Result<Vec<Arc<Object>>> {
        let query = self.0.read().await.list_owned_objects(
            **owner,
            object_type.map(|object_type| object_type.0.clone()),
            None,
            None,
            OwnedObjectReadMask::default(),
        );
        convert_objects(query.collect(limit).await?.into_inner())
    }
}
