// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, Base64, JsonValue, ObjectId, PageInfo, schema};

// ===========================================================================
// Object(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectQueryArgs")]
pub(crate) struct ObjectQueryFragment {
    #[arguments(address: $object_id, version: $version)]
    pub object: Option<Object>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectsQueryArgs")]
pub(crate) struct ObjectsQueryFragment {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub objects: ObjectConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectQueryArgs")]
pub(crate) struct MoveObjectContentsJsonQueryFragment {
    #[arguments(address: $object_id, version: $version)]
    pub object: Option<ObjectContentsJson>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectQueryArgs")]
pub(crate) struct MoveObjectContentsBcsQueryFragment {
    #[arguments(address: $object_id, version: $version)]
    pub object: Option<ObjectContentsBcs>,
}

// ===========================================================================
// Object(s) Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct ObjectQueryArgs {
    pub object_id: ObjectId,
    pub version: Option<u64>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct ObjectsQueryArgs {
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
pub(crate) struct Object {
    pub bcs: Option<Base64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub(crate) struct ObjectContentsJson {
    pub as_move_object: Option<MoveObjectContentsJson>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub(crate) struct MoveObjectContentsJson {
    pub contents: Option<MoveValueJson>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub(crate) struct MoveValueJson {
    pub json: JsonValue,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub(crate) struct ObjectContentsBcs {
    pub as_move_object: Option<MoveObjectContentsBcs>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub(crate) struct MoveObjectContentsBcs {
    pub contents: Option<MoveValueBcs>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub(crate) struct MoveValueBcs {
    pub bcs: Base64,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "ObjectFilter")]
#[non_exhaustive]
pub struct ObjectFilter {
    #[cynic(rename = "type")]
    pub type_tag: Option<String>,
    pub owner: Option<Address>,
    pub object_ids: Option<Vec<ObjectId>>,
}

impl ObjectFilter {
    /// Filter by package, module, or fully qualified type, e.g. `"0x02"`,
    /// `"0x02::coin"`, or `"0x02::coin::Coin"`.
    pub fn with_type(mut self, type_tag: impl Into<String>) -> Self {
        self.type_tag = Some(type_tag.into());
        self
    }

    /// Filter by the address owning the object.
    pub fn with_owner(mut self, owner: Address) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Filter by object ids.
    pub fn with_object_ids(mut self, object_ids: Vec<ObjectId>) -> Self {
        self.object_ids = Some(object_ids);
        self
    }
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectConnection")]
pub(crate) struct ObjectConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<Object>,
}
