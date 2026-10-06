// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Package API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::GraphQLMovePackagePage,
        query_types::{GraphQLMoveFunction, GraphQLMoveModule, GraphQLPaginationFilter},
    },
    helpers::SetIfSome,
    types::{address::Address, object::MovePackage, version::Version},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// The package corresponding to the given address (at the optionally given
    /// version). When no version is given, the package is loaded directly
    /// from the address given. Otherwise, the address is translated before
    /// loading to point to the package whose original ID matches
    /// the package at address, but whose version is version. For non-system
    /// packages, this might result in a different address than address
    /// because different versions of a package, introduced by upgrades,
    /// exist at distinct addresses.
    ///
    /// Note that this interpretation of version is different from a historical
    /// object read (the interpretation of version for the object query).
    #[uniffi::method(default(version = None))]
    pub async fn package(
        &self,
        address: &Address,
        version: Option<Arc<Version>>,
    ) -> Result<Option<Arc<MovePackage>>> {
        Ok(self
            .client()
            .package(**address)
            .set_if_some(version.map(|v| **v), |query, value| query.version(value))
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Fetch all versions of package at address (packages that share this
    /// package's original ID), optionally bounding the versions exclusively
    /// from below with afterVersion, or from above with beforeVersion.
    #[uniffi::method(default(pagination_filter = None, after_version = None, before_version = None))]
    pub async fn package_versions(
        &self,
        address: &Address,
        after_version: Option<Arc<Version>>,
        before_version: Option<Arc<Version>>,
        pagination_filter: Option<GraphQLPaginationFilter>,
    ) -> Result<GraphQLMovePackagePage> {
        Ok(self
            .client()
            .package_versions(**address)
            .pagination(pagination_filter.map(Into::into).unwrap_or_default())
            .set_if_some(after_version.map(|v| **v), |query, value| {
                query.after_version(value)
            })
            .set_if_some(before_version.map(|v| **v), |query, value| {
                query.before_version(value)
            })
            .await?
            .map(Into::into)
            .into())
    }

    /// Fetch the latest version of the package at address.
    /// This corresponds to the package with the highest version that shares its
    /// original ID with the package at address.
    pub async fn package_latest(&self, address: &Address) -> Result<Option<Arc<MovePackage>>> {
        Ok(self
            .client()
            .package_latest(**address)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// The Move packages that exist in the network, optionally filtered to be
    /// strictly before beforeCheckpoint and/or strictly after
    /// afterCheckpoint.
    ///
    /// This query returns all versions of a given user package that appear
    /// between the specified checkpoints, but only records the latest
    /// versions of system packages.
    #[uniffi::method(default(pagination_filter = None, after_checkpoint = None, before_checkpoint = None))]
    pub async fn packages(
        &self,
        after_checkpoint: Option<u64>,
        before_checkpoint: Option<u64>,
        pagination_filter: Option<GraphQLPaginationFilter>,
    ) -> Result<GraphQLMovePackagePage> {
        Ok(self
            .client()
            .packages()
            .pagination(pagination_filter.map(Into::into).unwrap_or_default())
            .set_if_some(after_checkpoint, |query, value| {
                query.after_checkpoint(value)
            })
            .set_if_some(before_checkpoint, |query, value| {
                query.before_checkpoint(value)
            })
            .await?
            .map(Into::into)
            .into())
    }

    /// Return the normalized Move function data for the provided package,
    /// module, and function.
    #[uniffi::method(default(version = None))]
    pub async fn normalized_move_function(
        &self,
        package: &Address,
        module: &str,
        function: &str,
        version: Option<Arc<Version>>,
    ) -> Result<Option<Arc<GraphQLMoveFunction>>> {
        Ok(self
            .client()
            .normalized_move_function(**package, module, function)
            .set_if_some(version.map(|v| **v), |query, value| query.version(value))
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Return the normalized Move module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep pagination
    // options?
    #[expect(clippy::too_many_arguments)]
    #[uniffi::method(default(
        version = None,
        pagination_filter_enums = None,
        pagination_filter_friends = None,
        pagination_filter_functions = None,
        pagination_filter_structs = None,
    ))]
    pub async fn normalized_move_module(
        &self,
        package: &Address,
        module: &str,
        version: Option<Arc<Version>>,
        pagination_filter_enums: Option<GraphQLPaginationFilter>,
        pagination_filter_friends: Option<GraphQLPaginationFilter>,
        pagination_filter_functions: Option<GraphQLPaginationFilter>,
        pagination_filter_structs: Option<GraphQLPaginationFilter>,
    ) -> Result<Option<GraphQLMoveModule>> {
        Ok(self
            .client()
            .normalized_move_module(**package, module)
            .set_if_some(version.map(|v| **v), |query, value| query.version(value))
            .enums_pagination(pagination_filter_enums.map(Into::into).unwrap_or_default())
            .friends_pagination(
                pagination_filter_friends
                    .map(Into::into)
                    .unwrap_or_default(),
            )
            .functions_pagination(
                pagination_filter_functions
                    .map(Into::into)
                    .unwrap_or_default(),
            )
            .structs_pagination(
                pagination_filter_structs
                    .map(Into::into)
                    .unwrap_or_default(),
            )
            .await?
            .map(Into::into))
    }
}
