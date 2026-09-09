// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Move package versions API implementation.

use std::sync::Arc;

use iota_sdk::grpc_types::v1 as proto;

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::object::ObjectId,
};

/// A version of a Move package.
#[derive(uniffi::Record)]
pub struct PackageVersion {
    /// The original (immutable) package id shared across all versions.
    pub original_id: Option<Arc<ObjectId>>,
    /// The storage id of the specific package version.
    pub storage_id: Option<Arc<ObjectId>>,
    /// The version number.
    pub version: Option<u64>,
}

impl TryFrom<&proto::move_package_service::PackageVersion> for PackageVersion {
    type Error = SdkFfiError;

    fn try_from(value: &proto::move_package_service::PackageVersion) -> Result<Self> {
        Ok(Self {
            original_id: value
                .original_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            storage_id: value
                .storage_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            version: value.version,
        })
    }
}

/// A page of package versions returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct PackageVersionPage {
    /// The package versions returned in the page.
    pub versions: Vec<PackageVersion>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of versions of a Move package.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    #[uniffi::method(default(page_size = None, page_token = None))]
    pub async fn package_versions(
        &self,
        package_id: &ObjectId,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
    ) -> Result<PackageVersionPage> {
        let query = self.0.read().await.package_versions(
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
    pub async fn all_package_versions(
        &self,
        package_id: &ObjectId,
        limit: Option<u32>,
    ) -> Result<Vec<PackageVersion>> {
        let query = self
            .0
            .read()
            .await
            .package_versions(**package_id, None, None);
        query
            .collect(limit)
            .await?
            .into_inner()
            .iter()
            .map(TryInto::try_into)
            .collect()
    }
}
