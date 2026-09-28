// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Owned objects API implementation.

use std::sync::Arc;

use iota_sdk::grpc_client::read_mask_fields::OwnedObjectReadMask;

use crate::{
    error::Result,
    grpc::{api::ledger::objects::GrpcObject, client::GrpcClient},
    types::{address::Address, move_core::StructTag},
};

/// A page of objects returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct OwnedObjectPage {
    /// The objects returned in the page.
    pub objects: Vec<GrpcObject>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of objects owned by an address, optionally filtered
    /// by object type.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the object reference and the BCS-encoded object are
    /// returned.
    #[uniffi::method(default(
        object_type = None,
        page_size = None,
        page_token = None,
        read_mask = None
    ))]
    pub async fn owned_objects(
        &self,
        owner: &Address,
        object_type: Option<Arc<StructTag>>,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<OwnedObjectPage> {
        let query = self.client().owned_objects(
            **owner,
            object_type.map(|object_type| object_type.0.clone()),
            page_size,
            page_token.map(Into::into),
            crate::grpc::api::read_mask::<OwnedObjectReadMask>(&read_mask),
        );
        let page = query.await?.into_inner();
        Ok(OwnedObjectPage {
            objects: page
                .items
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all objects owned by an address, optionally filtered by object
    /// type, auto-paginating up to `limit` objects. If `limit` is `None`,
    /// all objects are returned.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the object reference and the BCS-encoded object are
    /// returned.
    #[uniffi::method(default(object_type = None, limit = None, read_mask = None))]
    pub async fn all_owned_objects(
        &self,
        owner: &Address,
        object_type: Option<Arc<StructTag>>,
        limit: Option<u32>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<GrpcObject>> {
        let query = self.client().owned_objects(
            **owner,
            object_type.map(|object_type| object_type.0.clone()),
            None,
            None,
            crate::grpc::api::read_mask::<OwnedObjectReadMask>(&read_mask),
        );
        query
            .collect(limit)
            .await?
            .into_inner()
            .iter()
            .map(TryInto::try_into)
            .collect()
    }
}
