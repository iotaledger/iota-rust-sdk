// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{
    Address, Base64, DateTime, GQLAddress, JsonValue, MoveData, MoveType, PageInfo,
    normalized_move::MoveModuleQuery, schema,
};

// ===========================================================================
// Events Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EventsQueryArgs")]
pub struct EventsQuery {
    #[arguments(after: $after, before: $before, filter: $filter, first: $first, last: $last)]
    pub events: EventConnection,
}

// ===========================================================================
// Events Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct EventsQueryArgs<'a> {
    pub filter: Option<EventFilter>,
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

// ===========================================================================
// Events Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "EventConnection")]
pub struct EventConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<Event>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "EventFilter")]
#[non_exhaustive]
pub struct EventFilter {
    pub emitting_module: Option<String>,
    pub event_type: Option<String>,
    pub sender: Option<Address>,
    pub transaction_digest: Option<String>,
}

impl EventFilter {
    /// Filter by the module emitting the event, e.g. `"0x02"` (package) or
    /// `"0x02::coin"` (module).
    pub fn with_emitting_module(mut self, emitting_module: impl Into<Option<String>>) -> Self {
        self.emitting_module = emitting_module.into();
        self
    }

    /// Filter by event type, e.g. `"0x02::coin::CoinMetadata"`.
    pub fn with_event_type(mut self, event_type: impl Into<Option<String>>) -> Self {
        self.event_type = event_type.into();
        self
    }

    /// Filter by the address that sent the transaction emitting the event.
    pub fn with_sender(mut self, sender: impl Into<Option<Address>>) -> Self {
        self.sender = sender.into();
        self
    }

    /// Filter by the digest of the transaction emitting the event.
    pub fn with_transaction_digest(
        mut self,
        transaction_digest: impl Into<Option<String>>,
    ) -> Self {
        self.transaction_digest = transaction_digest.into();
        self
    }
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Event")]
pub struct Event {
    pub sending_module: Option<MoveModuleQuery>,
    pub sender: Option<GQLAddress>,
    pub type_: MoveType,
    pub bcs: Base64,
    pub timestamp: Option<DateTime>,
    pub data: MoveData,
    pub json: JsonValue,
}
