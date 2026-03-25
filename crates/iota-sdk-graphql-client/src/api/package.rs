// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Package API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use iota_types::{Address, MovePackage, Object};

use crate::{
    Client, Page,
    error::Result,
    pagination::PaginationFilter,
    query_types::{
        LatestPackageQuery, MoveFunction, MoveModule, MovePackageVersionFilter,
        MoveSchemaFunctionQuery, MoveSchemaFunctionQueryArgs, MoveSchemaModuleQuery,
        MoveSchemaModuleQueryArgs, PackageCheckpointFilter, PackageQuery, PackageQueryArgs,
        PackageVersionsQuery, PackageVersionsQueryArgs, PackagesQuery, PackagesQueryArgs,
    },
};

impl Client {
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
    pub async fn package(
        &self,
        address: Address,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<MovePackage>> {
        let operation = PackageQuery::build(PackageQueryArgs {
            address,
            version: version.into(),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|x| x.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Object>(&bcs))
            .transpose()?
            .map(|obj| obj.data.into_package()))
    }

    /// Fetch all versions of package at address (packages that share this
    /// package's original ID), optionally bounding the versions exclusively
    /// from below with afterVersion, or from above with beforeVersion.
    pub async fn package_versions(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
        after_version: impl Into<Option<u64>>,
        before_version: impl Into<Option<u64>>,
    ) -> Result<Page<MovePackage>> {
        let pagination = self.pagination_filter(pagination_filter).await;
        let operation = PackageVersionsQuery::build(PackageVersionsQueryArgs {
            address,
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
            filter: Some(MovePackageVersionFilter {
                after_version: after_version.into(),
                before_version: before_version.into(),
            }),
        });

        let response = self.run_query(&operation).await?;

        let pc = response.package_versions;
        let page_info = pc.page_info;
        let bcs = pc
            .nodes
            .iter()
            .map(|p| &p.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let packages = bcs
            .iter()
            .map(|b| Ok(bcs::from_bytes::<Object>(b)?.data.into_package()))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, packages))
    }

    /// Fetch the latest version of the package at address.
    /// This corresponds to the package with the highest version that shares its
    /// original ID with the package at address.
    pub async fn package_latest(&self, address: Address) -> Result<Option<MovePackage>> {
        let operation = LatestPackageQuery::build(PackageQueryArgs {
            address,
            version: None,
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .latest_package
            .and_then(|x| x.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(&bcs.0))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Object>(&bcs))
            .transpose()?
            .map(|obj| obj.data.into_package()))
    }

    /// The Move packages that exist in the network, optionally filtered to be
    /// strictly before beforeCheckpoint and/or strictly after
    /// afterCheckpoint.
    ///
    /// This query returns all versions of a given user package that appear
    /// between the specified checkpoints, but only records the latest
    /// versions of system packages.
    pub async fn packages(
        &self,
        pagination_filter: PaginationFilter,
        after_checkpoint: impl Into<Option<u64>>,
        before_checkpoint: impl Into<Option<u64>>,
    ) -> Result<Page<MovePackage>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = PackagesQuery::build(PackagesQueryArgs {
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
            filter: Some(PackageCheckpointFilter {
                after_checkpoint: after_checkpoint.into(),
                before_checkpoint: before_checkpoint.into(),
            }),
        });

        let response = self.run_query(&operation).await?;

        let pc = response.packages;
        let page_info = pc.page_info;
        let bcs = pc
            .nodes
            .iter()
            .map(|p| &p.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let packages = bcs
            .iter()
            .map(|b| Ok(bcs::from_bytes::<Object>(b)?.data.into_package()))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, packages))
    }

    /// Return Move schema function data for the provided package,
    /// module, and function.
    pub async fn move_schema_function(
        &self,
        package: Address,
        module: &str,
        function: &str,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<MoveFunction>> {
        let operation = MoveSchemaFunctionQuery::build(MoveSchemaFunctionQueryArgs {
            address: package,
            module,
            function,
            version: version.into(),
        });
        let response = self.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|p| p.module)
            .and_then(|m| m.function))
    }

    /// Return Move schema module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep pagination
    // options?
    #[allow(clippy::too_many_arguments)]
    pub async fn move_schema_module(
        &self,
        package: Address,
        module: &str,
        version: impl Into<Option<u64>>,
        pagination_filter_enums: PaginationFilter,
        pagination_filter_friends: PaginationFilter,
        pagination_filter_functions: PaginationFilter,
        pagination_filter_structs: PaginationFilter,
    ) -> Result<Option<MoveModule>> {
        let enums = self.pagination_filter(pagination_filter_enums).await;
        let friends = self.pagination_filter(pagination_filter_friends).await;
        let functions = self.pagination_filter(pagination_filter_functions).await;
        let structs = self.pagination_filter(pagination_filter_structs).await;
        let operation = MoveSchemaModuleQuery::build(MoveSchemaModuleQueryArgs {
            package,
            module,
            version: version.into(),
            after_enums: enums.after.as_deref(),
            after_functions: functions.after.as_deref(),
            after_structs: structs.after.as_deref(),
            after_friends: friends.after.as_deref(),
            before_enums: enums.before.as_deref(),
            before_functions: functions.before.as_deref(),
            before_structs: structs.before.as_deref(),
            before_friends: friends.before.as_deref(),
            first_enums: enums.first,
            first_functions: functions.first,
            first_structs: structs.first,
            first_friends: friends.first,
            last_enums: enums.last,
            last_functions: functions.last,
            last_structs: structs.last,
            last_friends: friends.last,
        });
        let response = self.run_query(&operation).await?;

        Ok(response.package.and_then(|p| p.module))
    }
}

#[cfg(test)]
mod tests {
    use iota_types::Address;

    use crate::{PaginationFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_package() {
        let client = test_client();
        client
            .package(Address::FRAMEWORK, None)
            .await
            .map_err(|e| {
                format!(
                    "Package query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_latest_package_query() {
        let client = test_client();
        client
            .package_latest(Address::FRAMEWORK)
            .await
            .map_err(|e| {
                format!(
                    "Latest package query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_packages_query() {
        let client = test_client();
        let packages = client
            .packages(PaginationFilter::default(), None, None)
            .await
            .map_err(|e| {
                format!(
                    "Packages query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !packages.is_empty(),
            "Packages query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    #[ignore = "requires NETWORK=local or NETWORK=testnet; run with: NETWORK=testnet cargo test -p iota-sdk-graphql-client test_move_schema_function -- --include-ignored"]
    async fn test_move_schema_function() {
        // Uses the IOTA Framework address and the " validator" module's "add_stake" function,
        // which is stable and available on all networks.
        let client = test_client();
        let result = client
            .move_schema_function(
                Address::FRAMEWORK,
                "validator",
                "add_stake",
                None,
            )
            .await
            .map_err(|e| {
                format!(
                    "move_schema_function query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            });

        // Verify the query executed without a network/selection-set error.
        // The result may be None if the function does not exist on this network version,
        // which is not an error condition.
        let _ = result.expect("move_schema_function should not return an error");
    }

    #[tokio::test]
    #[ignore = "requires NETWORK=local or NETWORK=testnet; run with: NETWORK=testnet cargo test -p iota-sdk-graphql-client test_move_schema_module -- --include-ignored"]
    async fn test_move_schema_module() {
        // Uses the IOTA Framework address and " coin" module, which is stable on all networks.
        let client = test_client();
        let result = client
            .move_schema_module(
                Address::FRAMEWORK,
                "coin",
                None,
                PaginationFilter::default(),
                PaginationFilter::default(),
                PaginationFilter::default(),
                PaginationFilter::default(),
            )
            .await
            .map_err(|e| {
                format!(
                    "move_schema_module query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            });

        // Verify the query executed without a network/selection-set error.
        // The result may be None if the module does not exist on this network version,
        // which is not an error condition.
        let _ = result.expect("move_schema_module should not return an error");
    }
}
