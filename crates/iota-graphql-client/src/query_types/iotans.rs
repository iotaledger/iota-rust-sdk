// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// ===========================================================================
// IotaNS Queries
// ===========================================================================

use crate::query_types::{Address as SdkAddress, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "ResolveIotaNSQueryArgs"
)]
pub struct ResolveIotaNSQuery {
    #[arguments(domain: $name)]
    #[cynic(rename = "resolveIotaNSAddress")]
    pub resolve_iotans_address: Option<DomainAddress>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ResolveIotaNSQueryArgs<'a> {
    pub name: &'a str,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub struct DomainAddress {
    pub address: SdkAddress,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "DefaultIotaNSNameQueryArgs"
)]
pub struct DefaultIotaNSNameQuery {
    #[arguments(address: $address)]
    pub address: Option<AddressDefaultIotaNS>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct DefaultIotaNSNameQueryArgs {
    pub address: SdkAddress,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub struct AddressDefaultIotaNS {
    #[cynic(rename = "defaultIotaNSName")]
    pub default_iotans_name: Option<String>,
}
