// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Address;

use crate::query_types::{Base64, PageInfo, schema};

// ===========================================================================
// Package by address (and optional version)
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub(crate) struct PackageQueryFragment {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackageQueryFragment>,
}

// ===========================================================================
// Latest Package
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub(crate) struct LatestPackageQueryFragment {
    #[arguments(address: $address)]
    pub latest_package: Option<MovePackageQueryFragment>,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub(crate) struct PackageArgs {
    pub address: Address,
    pub version: Option<u64>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackage")]
pub(crate) struct MovePackageQueryFragment {
    pub bcs: Option<Base64>,
}

// ===========================================================================
// Packages
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "PackagesQueryArgs"
)]
pub(crate) struct PackagesQueryFragment {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub packages: MovePackageConnection,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub(crate) struct PackagesQueryArgs<'a> {
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
    pub filter: Option<PackageCheckpointFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "MovePackageCheckpointFilter")]
#[non_exhaustive]
pub(crate) struct PackageCheckpointFilter {
    pub after_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackageConnection")]
pub(crate) struct MovePackageConnection {
    pub nodes: Vec<MovePackageQueryFragment>,
    pub page_info: PageInfo,
}

// ===========================================================================
// PackagesVersions
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "PackageVersionsArgs"
)]
pub(crate) struct PackageVersionsQueryFragment {
    #[arguments(address: $address, after: $after, first: $first, last: $last, before: $before, filter:$filter)]
    pub package_versions: MovePackageConnection,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub(crate) struct PackageVersionsArgs<'a> {
    pub address: Address,
    pub after: Option<&'a str>,
    pub first: Option<i32>,
    pub last: Option<i32>,
    pub before: Option<&'a str>,
    pub filter: Option<MovePackageVersionFilter>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "MovePackageVersionFilter")]
#[non_exhaustive]
pub(crate) struct MovePackageVersionFilter {
    pub after_version: Option<u64>,
    pub before_version: Option<u64>,
}
