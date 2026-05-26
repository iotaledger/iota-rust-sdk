// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, Base64, MoveObjectContents, ObjectId, PageInfo, schema};

// ===========================================================================
// Object(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectArgs")]
pub struct ObjectQuery {
    #[arguments(address: $object_id, version: $version)]
    pub object: Option<Object>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectsArgs")]
pub struct ObjectsQuery {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub objects: ObjectConnection,
}

// ===========================================================================
// Object(s) Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectArgs {
    pub object_id: ObjectId,
    pub version: Option<u64>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectsArgs {
    pub after: Option<String>,
    pub before: Option<String>,
    pub filter: Option<ObjectFilter>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[deprecated(
    since = "0.0.2",
    note = "renamed to `ObjectArgs` for naming consistency"
)]
pub type ObjectQueryArgs = ObjectArgs;
#[deprecated(
    since = "0.0.2",
    note = "renamed to `ObjectsArgs` for naming consistency"
)]
pub type ObjectsQueryArgs = ObjectsArgs;

// ===========================================================================
// Object(s) Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub struct Object {
    pub as_move_object: Option<MoveObjectContents>,
    pub bcs: Option<Base64>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "ObjectFilter")]
pub struct ObjectFilter {
    #[cynic(rename = "type")]
    pub type_: Option<String>,
    pub owner: Option<Address>,
    pub object_ids: Option<Vec<ObjectId>>,
}

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectKey")]
pub struct ObjectKey {
    pub object_id: ObjectId,
    pub version: u64,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectConnection")]
pub struct ObjectConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<Object>,
}
