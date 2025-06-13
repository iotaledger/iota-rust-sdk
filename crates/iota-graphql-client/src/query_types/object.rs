// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, Base64, MoveObjectContents, PageInfo, schema};

// ===========================================================================
// Object(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectQueryArgs")]
pub struct ObjectQuery {
    #[arguments(address: $address, version: $version)]
    pub object: Option<Object>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectsQueryArgs")]
pub struct ObjectsQuery {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub objects: ObjectConnection,
}

// ===========================================================================
// Object(s) Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectQueryArgs {
    pub address: Address,
    pub version: Option<u64>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectsQueryArgs {
    pub after: Option<String>,
    pub before: Option<String>,
    pub filter: Option<ObjectFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

// ===========================================================================
// Object(s) Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub struct Object {
    pub as_move_object: Option<MoveObjectContents>,
    pub bcs: Option<Base64>,
}

#[derive(Clone, Default, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectFilter")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ObjectFilter {
    #[cynic(rename = "type")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub type_: Option<String>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub owner: Option<Address>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub object_ids: Option<Vec<Address>>,
}

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectKey")]
pub struct ObjectKey {
    pub object_id: Address,
    pub version: u64,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectConnection")]
pub struct ObjectConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<Object>,
}
