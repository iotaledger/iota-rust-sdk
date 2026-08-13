// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Shared scalars and fragments used across multiple query type modules.

use cynic::impl_scalar;
pub use iota_types::{Address, ObjectId};
pub use serde_json::Value as JsonValue;

use super::schema;
use crate::error;

// ===========================================================================
// Scalars
// ===========================================================================

impl_scalar!(Address, schema::IotaAddress);
impl_scalar!(ObjectId, schema::IotaAddress);
impl_scalar!(u64, schema::UInt53);
impl_scalar!(JsonValue, schema::JSON);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "Base64")]
pub struct Base64(pub String);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "BigInt")]
pub struct BigInt(pub String);

#[derive(Clone, cynic::Scalar, Debug)]
#[cynic(graphql_type = "DateTime")]
pub struct DateTime(pub String);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "MoveData")]
pub struct MoveData(pub serde_json::Value);

// ===========================================================================
// Types used in several queries
// ===========================================================================

#[derive(Clone, Copy, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub struct GQLAddress {
    pub address: Address,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub struct MoveObject {
    pub bcs: Option<Base64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub struct MoveObjectContents {
    pub contents: Option<MoveValue>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub struct MoveValue {
    pub type_: MoveType,
    pub bcs: Base64,
    pub json: Option<JsonValue>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveType")]
pub struct MoveType {
    pub repr: String,
}

// ===========================================================================
// Utility Types
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "PageInfo")]
/// Information about pagination in a connection.
pub struct PageInfo {
    /// When paginating backwards, are there more items?
    pub has_previous_page: bool,
    /// Are there more items when paginating forwards?
    pub has_next_page: bool,
    /// When paginating backwards, the cursor to continue.
    pub start_cursor: Option<String>,
    /// When paginating forwards, the cursor to continue.
    pub end_cursor: Option<String>,
}

impl TryFrom<BigInt> for u64 {
    type Error = error::Error;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(value.0.parse::<u64>()?)
    }
}
