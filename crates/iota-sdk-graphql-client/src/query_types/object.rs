// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, Base64, MoveObjectContents, ObjectId, PageInfo, schema};

// ===========================================================================
// Object(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectQueryArgs")]
pub struct ObjectQuery {
    #[arguments(address: $object_id, version: $version)]
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
    pub object_id: ObjectId,
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
    pub fn with_type(mut self, type_tag: impl Into<Option<String>>) -> Self {
        self.type_tag = type_tag.into();
        self
    }

    /// Filter by the address owning the object.
    pub fn with_owner(mut self, owner: impl Into<Option<Address>>) -> Self {
        self.owner = owner.into();
        self
    }

    /// Filter by object ids.
    pub fn with_object_ids(mut self, object_ids: impl Into<Option<Vec<ObjectId>>>) -> Self {
        self.object_ids = object_ids.into();
        self
    }
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
