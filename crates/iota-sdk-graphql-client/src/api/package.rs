// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Package API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use iota_types::{Address, MovePackage, Object, Version};

use crate::{
    GraphQLClient, Page,
    api::define_query,
    error::GraphQLResult,
    pagination::{PaginationFilter, PaginationFilterResponse},
    query_types::{
        LatestPackageQueryFragment, MoveFunction, MoveModule, MovePackageVersionFilter,
        NormalizedMoveFunctionQueryArgs, NormalizedMoveFunctionQueryFragment,
        NormalizedMoveModuleQueryArgs, NormalizedMoveModuleQueryFragment, PackageArgs,
        PackageCheckpointFilter, PackageQueryFragment, PackageVersionsArgs,
        PackageVersionsQueryFragment, PackagesQueryArgs, PackagesQueryFragment,
    },
};

define_query! {
    /// Query for [`GraphQLClient::package_versions`]. Await it to send the
    /// request.
    pub struct ListPackageVersionsQuery {
        client: GraphQLClient,
        address: Address,
        pagination: PaginationFilter,
        after_version: Option<Version>,
        before_version: Option<Version>,
    }
    output: GraphQLResult<Page<MovePackage>>;
}

impl ListPackageVersionsQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Only return versions after this one.
    pub fn after_version(mut self, after_version: impl Into<Option<Version>>) -> Self {
        self.after_version = after_version.into();
        self
    }

    /// Only return versions before this one.
    pub fn before_version(mut self, before_version: impl Into<Option<Version>>) -> Self {
        self.before_version = before_version.into();
        self
    }

    fn operation<'a>(
        &self,
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<PackageVersionsQueryFragment, PackageVersionsArgs<'a>> {
        PackageVersionsQueryFragment::build(PackageVersionsArgs {
            address: self.address,
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
            filter: Some(MovePackageVersionFilter {
                after_version: self.after_version.map(|v| v.as_u64()),
                before_version: self.before_version.map(|v| v.as_u64()),
            }),
        })
    }

    async fn send(self) -> GraphQLResult<Page<MovePackage>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

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
}

define_query! {
    /// Query for [`GraphQLClient::packages`]. Await it to send the request.
    pub struct ListPackagesQuery {
        client: GraphQLClient,
        pagination: PaginationFilter,
        after_checkpoint: Option<u64>,
        before_checkpoint: Option<u64>,
    }
    output: GraphQLResult<Page<MovePackage>>;
}

impl ListPackagesQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Only return packages published after this checkpoint.
    pub fn after_checkpoint(mut self, after_checkpoint: impl Into<Option<u64>>) -> Self {
        self.after_checkpoint = after_checkpoint.into();
        self
    }

    /// Only return packages published before this checkpoint.
    pub fn before_checkpoint(mut self, before_checkpoint: impl Into<Option<u64>>) -> Self {
        self.before_checkpoint = before_checkpoint.into();
        self
    }

    fn operation<'a>(
        &self,
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<PackagesQueryFragment, PackagesQueryArgs<'a>> {
        PackagesQueryFragment::build(PackagesQueryArgs {
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
            filter: Some(PackageCheckpointFilter {
                after_checkpoint: self.after_checkpoint,
                before_checkpoint: self.before_checkpoint,
            }),
        })
    }

    async fn send(self) -> GraphQLResult<Page<MovePackage>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

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
}

define_query! {
    /// Query for [`GraphQLClient::normalized_move_module`]. Await it to send
    /// the request.
    pub struct GetNormalizedMoveModuleQuery {
        client: GraphQLClient,
        package: Address,
        module: String,
        version: Option<Version>,
        enums_pagination: PaginationFilter,
        friends_pagination: PaginationFilter,
        functions_pagination: PaginationFilter,
        structs_pagination: PaginationFilter,
    }
    output: GraphQLResult<Option<MoveModule>>;
}

struct ModulePagination {
    enums: PaginationFilterResponse,
    friends: PaginationFilterResponse,
    functions: PaginationFilterResponse,
    structs: PaginationFilterResponse,
}

impl GetNormalizedMoveModuleQuery {
    /// Set the package version.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    /// Set the page of the module's enums to fetch.
    pub fn enums_pagination(mut self, pagination: PaginationFilter) -> Self {
        self.enums_pagination = pagination;
        self
    }

    /// Set the page of the module's friends to fetch.
    pub fn friends_pagination(mut self, pagination: PaginationFilter) -> Self {
        self.friends_pagination = pagination;
        self
    }

    /// Set the page of the module's functions to fetch.
    pub fn functions_pagination(mut self, pagination: PaginationFilter) -> Self {
        self.functions_pagination = pagination;
        self
    }

    /// Set the page of the module's structs to fetch.
    pub fn structs_pagination(mut self, pagination: PaginationFilter) -> Self {
        self.structs_pagination = pagination;
        self
    }

    async fn resolved_pagination(&self) -> ModulePagination {
        ModulePagination {
            enums: self
                .client
                .pagination_filter(self.enums_pagination.clone())
                .await,
            friends: self
                .client
                .pagination_filter(self.friends_pagination.clone())
                .await,
            functions: self
                .client
                .pagination_filter(self.functions_pagination.clone())
                .await,
            structs: self
                .client
                .pagination_filter(self.structs_pagination.clone())
                .await,
        }
    }

    fn operation<'a>(
        &'a self,
        pagination: &'a ModulePagination,
    ) -> cynic::Operation<NormalizedMoveModuleQueryFragment, NormalizedMoveModuleQueryArgs<'a>>
    {
        let ModulePagination {
            enums,
            friends,
            functions,
            structs,
        } = pagination;
        NormalizedMoveModuleQueryFragment::build(NormalizedMoveModuleQueryArgs {
            package: self.package,
            module: &self.module,
            version: self.version.map(|v| v.as_u64()),
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
        })
    }

    async fn send(self) -> GraphQLResult<Option<MoveModule>> {
        let pagination = self.resolved_pagination().await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        Ok(response.package.and_then(|p| p.module))
    }
}

define_query! {
    /// Query for [`GraphQLClient::package`]. Await it to send the request.
    pub struct GetPackageQuery {
        client: GraphQLClient,
        address: Address,
        version: Option<Version>,
    }
    output: GraphQLResult<Option<MovePackage>>;
}

impl GetPackageQuery {
    /// Set the package version. Without it, the package is loaded from the
    /// given address.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<MovePackage>> {
        let operation = PackageQueryFragment::build(PackageArgs {
            address: self.address,
            version: self.version.map(|v| v.as_u64()),
        });

        let response = self.client.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|x| x.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Object>(&bcs))
            .transpose()?
            .map(|obj| obj.data.into_package()))
    }
}

define_query! {
    /// Query for [`GraphQLClient::normalized_move_function`]. Await it to send
    /// the request.
    pub struct GetNormalizedMoveFunctionQuery {
        client: GraphQLClient,
        package: Address,
        module: String,
        function: String,
        version: Option<Version>,
    }
    output: GraphQLResult<Option<MoveFunction>>;
}

impl GetNormalizedMoveFunctionQuery {
    /// Set the package version. Without it, the package at the given address
    /// is used.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<MoveFunction>> {
        let operation =
            NormalizedMoveFunctionQueryFragment::build(NormalizedMoveFunctionQueryArgs {
                address: self.package,
                module: &self.module,
                function: &self.function,
                version: self.version.map(|v| v.as_u64()),
            });
        let response = self.client.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|p| p.module)
            .and_then(|m| m.function))
    }
}

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
    pub fn package(&self, address: Address) -> GetPackageQuery {
        GetPackageQuery {
            client: self.clone(),
            address,
            version: None,
        }
    }

    /// Fetch all versions of package at address (packages that share this
    /// package's original ID), optionally bounding the versions exclusively
    /// with [`ListPackageVersionsQuery::after_version`] and
    /// [`ListPackageVersionsQuery::before_version`].
    pub fn package_versions(&self, address: Address) -> ListPackageVersionsQuery {
        ListPackageVersionsQuery {
            client: self.clone(),
            address,
            pagination: PaginationFilter::default(),
            after_version: None,
            before_version: None,
        }
    }

    /// Fetch the latest version of the package at address.
    /// This corresponds to the package with the highest version that shares its
    /// original ID with the package at address.
    pub async fn package_latest(&self, address: Address) -> GraphQLResult<Option<MovePackage>> {
        let operation = LatestPackageQueryFragment::build(PackageArgs {
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

    /// The Move packages that exist in the network, optionally bounded
    /// exclusively with [`ListPackagesQuery::after_checkpoint`] and
    /// [`ListPackagesQuery::before_checkpoint`].
    ///
    /// This query returns all versions of a given user package that appear
    /// between the specified checkpoints, but only records the latest
    /// versions of system packages.
    pub fn packages(&self) -> ListPackagesQuery {
        ListPackagesQuery {
            client: self.clone(),
            pagination: PaginationFilter::default(),
            after_checkpoint: None,
            before_checkpoint: None,
        }
    }

    /// Return the normalized Move function data for the provided package,
    /// module, and function.
    pub fn normalized_move_function(
        &self,
        package: Address,
        module: impl Into<String>,
        function: impl Into<String>,
    ) -> GetNormalizedMoveFunctionQuery {
        GetNormalizedMoveFunctionQuery {
            client: self.clone(),
            package,
            module: module.into(),
            function: function.into(),
            version: None,
        }
    }

    /// Return the normalized Move module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep
    // pagination options?
    pub fn normalized_move_module(
        &self,
        package: Address,
        module: impl Into<String>,
    ) -> GetNormalizedMoveModuleQuery {
        GetNormalizedMoveModuleQuery {
            client: self.clone(),
            package,
            module: module.into(),
            version: None,
            enums_pagination: PaginationFilter::default(),
            friends_pagination: PaginationFilter::default(),
            functions_pagination: PaginationFilter::default(),
            structs_pagination: PaginationFilter::default(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::{Address, Version};

    use crate::{
        Direction, PaginationFilter,
        test_utils::{assert_backward_page, backward_page, sent_variables, test_client},
    };

    #[tokio::test]
    async fn package_sends_the_address_and_version() {
        let vars = sent_variables("PackageQueryFragment", |client| async move {
            let _ = client
                .package(Address::FRAMEWORK)
                .version(Version::from_u64(3))
                .await;
        })
        .await;
        assert_eq!(vars["address"], Address::FRAMEWORK.to_string());
        assert_eq!(vars["version"], 3);

        let vars = sent_variables("PackageQueryFragment", |client| async move {
            let _ = client.package(Address::FRAMEWORK).await;
        })
        .await;
        assert!(vars["version"].is_null());
    }

    #[tokio::test]
    async fn normalized_move_function_sends_the_function_and_version() {
        let vars = sent_variables("NormalizedMoveFunctionQueryFragment", |client| async move {
            let _ = client
                .normalized_move_function(Address::FRAMEWORK, "coin", "value")
                .version(Version::from_u64(3))
                .await;
        })
        .await;
        assert_eq!(vars["address"], Address::FRAMEWORK.to_string());
        assert_eq!(vars["module"], "coin");
        assert_eq!(vars["function"], "value");
        assert_eq!(vars["version"], 3);

        let vars = sent_variables("NormalizedMoveFunctionQueryFragment", |client| async move {
            let _ = client
                .normalized_move_function(Address::FRAMEWORK, "coin", "value")
                .await;
        })
        .await;
        assert!(vars["version"].is_null());
    }

    #[tokio::test]
    async fn package_versions_sends_the_address_versions_and_pagination() {
        let vars = sent_variables("PackageVersionsQueryFragment", |client| async move {
            let _ = client
                .package_versions(Address::FRAMEWORK)
                .after_version(Version::from_u64(2))
                .before_version(Version::from_u64(5))
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["address"], Address::FRAMEWORK.to_string());
        assert_eq!(vars["filter"]["afterVersion"], 2);
        assert_eq!(vars["filter"]["beforeVersion"], 5);
        assert_backward_page(&vars);
    }

    #[tokio::test]
    async fn packages_sends_the_checkpoints_and_pagination() {
        let vars = sent_variables("PackagesQueryFragment", |client| async move {
            let _ = client
                .packages()
                .after_checkpoint(2)
                .before_checkpoint(5)
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["filter"]["afterCheckpoint"], 2);
        assert_eq!(vars["filter"]["beforeCheckpoint"], 5);
        assert_backward_page(&vars);
    }

    #[tokio::test]
    async fn normalized_move_module_sends_each_pagination_to_its_field() {
        let page = |direction, cursor: &str, limit| PaginationFilter {
            direction,
            cursor: Some(cursor.to_owned()),
            limit: Some(limit),
        };
        let vars = sent_variables("NormalizedMoveModuleQueryFragment", |client| async move {
            let _ = client
                .normalized_move_module(Address::FRAMEWORK, "coin")
                .version(Version::from_u64(4))
                .enums_pagination(page(Direction::Forward, "enums", 1))
                .friends_pagination(page(Direction::Backward, "friends", 2))
                .functions_pagination(page(Direction::Forward, "functions", 3))
                .structs_pagination(page(Direction::Backward, "structs", 5))
                .await;
        })
        .await;
        assert_eq!(vars["package"], Address::FRAMEWORK.to_string());
        assert_eq!(vars["module"], "coin");
        assert_eq!(vars["version"], 4);
        for (member, direction, limit) in [
            ("Enums", Direction::Forward, 1),
            ("Friends", Direction::Backward, 2),
            ("Functions", Direction::Forward, 3),
            ("Structs", Direction::Backward, 5),
        ] {
            let cursor = member.to_lowercase();
            let (used, unused) = match direction {
                Direction::Forward => (("after", "first"), ("before", "last")),
                Direction::Backward => (("before", "last"), ("after", "first")),
            };
            assert_eq!(vars[format!("{}{member}", used.0)], cursor);
            assert_eq!(vars[format!("{}{member}", used.1)], limit);
            assert!(vars[format!("{}{member}", unused.0)].is_null());
            assert!(vars[format!("{}{member}", unused.1)].is_null());
        }
    }

    #[tokio::test]
    async fn test_package() {
        let client = test_client();
        client
            .package(Address::FRAMEWORK)
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
            .packages()
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
}
