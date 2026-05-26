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
pub struct PackageQuery {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackageQuery>,
}

// ===========================================================================
// Latest Package
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub struct LatestPackageQuery {
    #[arguments(address: $address)]
    pub latest_package: Option<MovePackageQuery>,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub struct PackageArgs {
    pub address: Address,
    pub version: Option<u64>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackage")]
pub struct MovePackageQuery {
    pub address: Address,
    pub bcs: Option<Base64>,
}

// ===========================================================================
// Packages
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackagesArgs")]
pub struct PackagesQuery {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub packages: MovePackageConnection,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub struct PackagesArgs<'a> {
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
    pub filter: Option<PackageCheckpointFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[deprecated(
    since = "0.0.2",
    note = "renamed to `PackagesArgs` for naming consistency"
)]
pub type PackagesQueryArgs<'a> = PackagesArgs<'a>;

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackageCheckpointFilter")]
pub struct PackageCheckpointFilter {
    pub after_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackageConnection")]
pub struct MovePackageConnection {
    pub nodes: Vec<MovePackageQuery>,
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
pub struct PackageVersionsQuery {
    #[arguments(address: $address, after: $after, first: $first, last: $last, before: $before, filter:$filter)]
    pub package_versions: MovePackageConnection,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub struct PackageVersionsArgs<'a> {
    pub address: Address,
    pub after: Option<&'a str>,
    pub first: Option<i32>,
    pub last: Option<i32>,
    pub before: Option<&'a str>,
    pub filter: Option<MovePackageVersionFilter>,
}

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackageVersionFilter")]
pub struct MovePackageVersionFilter {
    pub after_version: Option<u64>,
    pub before_version: Option<u64>,
}
