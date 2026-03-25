// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, MoveFunction, schema};

// ===========================================================================
// Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "MoveSchemaFunctionQueryArgs"
)]
pub struct MoveSchemaFunctionQuery {
    #[arguments(address: $address, version: $version)]
    pub package: Option<MovePackageLookup>,
}

// ===========================================================================
// Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct MoveSchemaFunctionQueryArgs<'a> {
    pub address: Address,
    pub version: Option<u64>,
    pub module: &'a str,
    pub function: &'a str,
}

// ===========================================================================
// Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MovePackage",
    variables = "MoveSchemaFunctionQueryArgs"
)]
pub struct MovePackageLookup {
    #[arguments(name: $module)]
    pub module: Option<MoveModuleLookup>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MoveModule",
    variables = "MoveSchemaFunctionQueryArgs"
)]
pub struct MoveModuleLookup {
    #[arguments(name: $function)]
    pub function: Option<MoveFunction>,
}
