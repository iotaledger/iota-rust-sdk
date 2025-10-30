// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Address;

use crate::query_types::{Base64, PageInfo, schema};

// ===========================================================================
// Package by address (and optional version)
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub struct PackageQuery {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackageQuery>,
}

// ===========================================================================
// Latest Package
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub struct LatestPackageQuery {
    #[arguments(address: $address)]
    pub latest_package: Option<MovePackageQuery>,
}

#[derive(cynic::QueryVariables, Debug, Clone)]
pub struct PackageArgs {
    pub address: Address,
    pub version: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MovePackage")]
pub struct MovePackageQuery {
    pub address: Address,
    pub bcs: Option<Base64>,
}

// ===========================================================================
// Packages
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "PackagesQueryArgs"
)]
pub struct PackagesQuery {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub packages: MovePackageConnection,
}

#[derive(cynic::QueryVariables, Debug, Clone)]
pub struct PackagesQueryArgs<'a> {
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
    pub filter: Option<PackageCheckpointFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[derive(cynic::InputObject, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MovePackageCheckpointFilter")]
pub struct PackageCheckpointFilter {
    pub after_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MovePackageConnection")]
pub struct MovePackageConnection {
    pub nodes: Vec<MovePackageQuery>,
    pub page_info: PageInfo,
}

// ===========================================================================
// PackagesVersions
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "PackageVersionsArgs"
)]
pub struct PackageVersionsQuery {
    #[arguments(address: $address, after: $after, first: $first, last: $last, before: $before, filter:$filter)]
    pub package_versions: MovePackageConnection,
}

#[derive(cynic::QueryVariables, Debug, Clone)]
pub struct PackageVersionsArgs<'a> {
    pub address: Address,
    pub after: Option<&'a str>,
    pub first: Option<i32>,
    pub last: Option<i32>,
    pub before: Option<&'a str>,
    pub filter: Option<MovePackageVersionFilter>,
}

#[derive(cynic::InputObject, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MovePackageVersionFilter")]
pub struct MovePackageVersionFilter {
    pub after_version: Option<u64>,
    pub before_version: Option<u64>,
}
