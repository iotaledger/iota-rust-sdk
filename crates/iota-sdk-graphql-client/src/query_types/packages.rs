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
    pub package: Option<MovePackage>,
}

// ===========================================================================
// Latest Package
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "PackageArgs")]
pub struct LatestPackageQuery {
    #[arguments(address: $address)]
    pub latest_package: Option<MovePackage>,
}

#[derive(Clone, cynic::QueryVariables, Debug)]
pub struct PackageArgs {
    pub address: Address,
    pub version: Option<u64>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackage")]
pub struct MovePackage {
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
    pub filter: Option<MovePackageCheckpointFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "MovePackageCheckpointFilter")]
#[non_exhaustive]
pub struct MovePackageCheckpointFilter {
    pub after_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
}

impl MovePackageCheckpointFilter {
    /// Limit to packages published after the given checkpoint, exclusive.
    pub fn with_after_checkpoint(mut self, after_checkpoint: impl Into<Option<u64>>) -> Self {
        self.after_checkpoint = after_checkpoint.into();
        self
    }

    /// Limit to packages published before the given checkpoint, exclusive.
    pub fn with_before_checkpoint(mut self, before_checkpoint: impl Into<Option<u64>>) -> Self {
        self.before_checkpoint = before_checkpoint.into();
        self
    }
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackageConnection")]
pub struct MovePackageConnection {
    pub nodes: Vec<MovePackage>,
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

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "MovePackageVersionFilter")]
#[non_exhaustive]
pub struct MovePackageVersionFilter {
    pub after_version: Option<u64>,
    pub before_version: Option<u64>,
}

impl MovePackageVersionFilter {
    /// Limit to versions after the given version, exclusive.
    pub fn with_after_version(mut self, after_version: impl Into<Option<u64>>) -> Self {
        self.after_version = after_version.into();
        self
    }

    /// Limit to versions before the given version, exclusive.
    pub fn with_before_version(mut self, before_version: impl Into<Option<u64>>) -> Self {
        self.before_version = before_version.into();
        self
    }
}
