// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing package versions.

use iota_grpc_types::v1::move_package_service::{
    ListPackageVersionsRequest, PackageVersion,
    move_package_service_client::MovePackageServiceClient,
};
use iota_types::ObjectId;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{define_list_query, proto_object_id},
};

define_list_query! {
    /// Builder for listing versions of a Move package.
    ///
    /// Created by [`GrpcClient::package_versions`]. Await directly for a
    /// single page, or call [`.collect(limit)`](Self::collect) to
    /// auto-paginate.
    pub struct ListPackageVersionsQuery {
        service_client: MovePackageServiceClient<InterceptedChannel>,
        request: ListPackageVersionsRequest,
        item: PackageVersion,
        rpc_method: list_package_versions,
        items_field: versions,
    }
}

impl GrpcClient {
    /// List all versions of a Move package.
    ///
    /// Returns a query builder. Await it directly for a single page
    /// (with access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results. Page with
    /// [`page_size`](ListPackageVersionsQuery::page_size) and
    /// [`page_token`](ListPackageVersionsQuery::page_token).
    ///
    /// # Parameters
    ///
    /// - `package_id` - The object ID of any version of the package.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let package_id: ObjectId = "0x2".parse()?;
    ///
    /// let page = client.package_versions(package_id).await?;
    /// for version in &page.body().items {
    ///     println!("Package version: {:?}", version);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let package_id: ObjectId = "0x2".parse()?;
    ///
    /// let all = client
    ///     .package_versions(package_id)
    ///     .page_size(50)
    ///     .collect(None)
    ///     .await?;
    /// for version in all.body() {
    ///     println!("Package version: {:?}", version);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn package_versions(&self, package_id: ObjectId) -> ListPackageVersionsQuery {
        let base_request =
            ListPackageVersionsRequest::default().with_package_id(proto_object_id(package_id));

        ListPackageVersionsQuery::new(
            self.move_package_service_client(),
            base_request,
            self.max_decoding_message_size(),
        )
    }
}
