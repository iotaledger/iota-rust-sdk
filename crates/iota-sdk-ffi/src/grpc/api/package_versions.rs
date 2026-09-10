// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Move package versions API implementation.

use crate::{
    error::Result,
    grpc::{
        client::GrpcClient,
        output_types::{PackageVersion, PackageVersionPage},
    },
    types::object::ObjectId,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of versions of a Move package.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    #[uniffi::method(default(page_size = None, page_token = None))]
    pub async fn list_package_versions(
        &self,
        package_id: &ObjectId,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<PackageVersionPage> {
        let query = self.0.read().await.list_package_versions(
            **package_id,
            page_size,
            page_token.map(Into::into),
        );
        let page = query.await?.into_inner();
        Ok(PackageVersionPage {
            versions: page
                .items
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all versions of a Move package, auto-paginating up to `limit`
    /// versions. If `limit` is `None`, all versions are returned.
    #[uniffi::method(default(limit = None))]
    pub async fn list_all_package_versions(
        &self,
        package_id: &ObjectId,
        limit: Option<u32>,
    ) -> Result<Vec<PackageVersion>> {
        let query = self
            .0
            .read()
            .await
            .list_package_versions(**package_id, None, None);
        query
            .collect(limit)
            .await?
            .into_inner()
            .iter()
            .map(TryInto::try_into)
            .collect()
    }
}
