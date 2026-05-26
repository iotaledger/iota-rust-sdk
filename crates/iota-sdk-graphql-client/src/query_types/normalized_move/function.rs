// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, MoveFunction, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "NormalizedMoveFunctionArgs"
)]
pub struct NormalizedMoveFunctionQuery {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackage>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct NormalizedMoveFunctionArgs<'a> {
    pub address: Address,
    pub version: Option<u64>,
    pub module: &'a str,
    pub function: &'a str,
}

#[deprecated(
    since = "0.0.2",
    note = "renamed to `NormalizedMoveFunctionArgs` for naming consistency"
)]
pub type NormalizedMoveFunctionQueryArgs<'a> = NormalizedMoveFunctionArgs<'a>;

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MovePackage",
    variables = "NormalizedMoveFunctionArgs"
)]
pub struct MovePackage {
    #[arguments(name: $module)]
    pub module: Option<MoveModule>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MoveModule",
    variables = "NormalizedMoveFunctionArgs"
)]
pub struct MoveModule {
    #[arguments(name: $function)]
    pub function: Option<MoveFunction>,
}
