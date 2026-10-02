// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The GraphQL operations as the server sees them. Nothing in here is public:
//! every query decodes its wire types into SDK types before returning them.

mod scalars;

pub(crate) use self::scalars::{Bcs, Bytes, DateTime, Num};

#[cynic::schema("rpc")]
pub(crate) mod schema {}

cynic::impl_scalar!(iota_types::Address, schema::IotaAddress);
cynic::impl_scalar!(iota_types::ObjectId, schema::IotaAddress);
cynic::impl_scalar!(u64, schema::UInt53);
cynic::impl_scalar!(serde_json::Value, schema::JSON);

/// The pagination state of a connection.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "PageInfo")]
pub(crate) struct PageInfo {
    pub(crate) has_previous_page: bool,
    pub(crate) has_next_page: bool,
    pub(crate) start_cursor: Option<String>,
    pub(crate) end_cursor: Option<String>,
}

/// A Move type's canonical string representation.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveType")]
pub(crate) struct MoveTypeRepr {
    pub(crate) repr: String,
}

/// The address of an `Address` node.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub(crate) struct AddressOnly {
    pub(crate) address: iota_types::Address,
}

/// The digest of a transaction block.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub(crate) struct TransactionDigestOnly {
    pub(crate) digest: Option<String>,
}

/// The BCS of a transaction's effects.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockEffects")]
pub(crate) struct EffectsBcs {
    pub(crate) bcs: Option<Bcs<iota_types::TransactionEffects>>,
}
