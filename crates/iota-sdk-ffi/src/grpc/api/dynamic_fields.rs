// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dynamic fields API implementation.

use iota_sdk::grpc_client::read_mask_fields::DynamicFieldReadMask;

use crate::{
    error::Result,
    grpc::{
        client::GrpcClient,
        output_types::{DynamicField, DynamicFieldPage},
    },
    types::object::ObjectId,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of dynamic fields of an object.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the parent and field id are returned.
    #[uniffi::method(default(page_size = None, page_token = None, read_mask = None))]
    pub async fn list_dynamic_fields(
        &self,
        parent: &ObjectId,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<DynamicFieldPage> {
        let query = self.0.read().await.list_dynamic_fields(
            **parent,
            page_size,
            page_token.map(Into::into),
            super::read_mask::<DynamicFieldReadMask>(&read_mask),
        );
        let page = query.await?.into_inner();
        Ok(DynamicFieldPage {
            dynamic_fields: page
                .items
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all dynamic fields of an object, auto-paginating up to `limit`
    /// fields. If `limit` is `None`, all fields are returned.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the parent and field id are returned.
    #[uniffi::method(default(limit = None, read_mask = None))]
    pub async fn list_all_dynamic_fields(
        &self,
        parent: &ObjectId,
        limit: Option<u32>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<DynamicField>> {
        let query = self.0.read().await.list_dynamic_fields(
            **parent,
            None,
            None,
            super::read_mask::<DynamicFieldReadMask>(&read_mask),
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
