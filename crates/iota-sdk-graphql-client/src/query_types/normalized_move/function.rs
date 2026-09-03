// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, MoveFunction, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "NormalizedMoveFunctionQueryArgs"
)]
pub struct NormalizedMoveFunctionQuery {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackageModuleFunction>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct NormalizedMoveFunctionQueryArgs<'a> {
    pub address: Address,
    pub version: Option<u64>,
    pub module: &'a str,
    pub function: &'a str,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MovePackage",
    variables = "NormalizedMoveFunctionQueryArgs"
)]
pub struct MovePackageModuleFunction {
    #[arguments(name: $module)]
    pub module: Option<MoveModuleFunction>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MoveModule",
    variables = "NormalizedMoveFunctionQueryArgs"
)]
pub struct MoveModuleFunction {
    #[arguments(name: $function)]
    pub function: Option<MoveFunction>,
}
