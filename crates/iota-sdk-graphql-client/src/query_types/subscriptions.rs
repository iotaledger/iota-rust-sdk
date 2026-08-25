// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Subscription operations for the live `events` and `transactions` streams.
//!
//! These map the GraphQL `Subscription` root, whose `events` and
//! `transactions` fields each return a union of the payload type and
//! [`Lagged`] (emitted when the server's broker had to drop messages).

use base64ct::Encoding;
use iota_types::{SenderSignedTransaction, SignedTransaction};

use crate::{
    error::{self, Error, Kind},
    query_types::{
        Address, Base64, DateTime, Event, GQLAddress, JsonValue, MoveData, MoveType,
        TransactionBlockKindInput, normalized_move::MoveModuleQuery, schema,
    },
};

// ===========================================================================
// Subscription roots
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Subscription",
    variables = "EventsSubscriptionArgs"
)]
pub struct EventsSubscription {
    #[arguments(startAfter: $start_after, filter: $filter)]
    pub events: EventSubscriptionPayload,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Subscription",
    variables = "TransactionsSubscriptionArgs"
)]
pub struct TransactionsSubscription {
    #[arguments(startAfter: $start_after, filter: $filter)]
    pub transactions: TransactionBlockSubscriptionPayload,
}

// ===========================================================================
// Subscription args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct EventsSubscriptionArgs {
    pub start_after: Option<String>,
    pub filter: Option<SubscriptionEventFilter>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionsSubscriptionArgs {
    pub start_after: Option<String>,
    pub filter: Option<SubscriptionTransactionFilter>,
}

// ===========================================================================
// Subscription filters
// ===========================================================================

/// Filter incoming events in a subscription. Exactly one field must be set
/// (the GraphQL input is `@oneOf`).
#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "SubscriptionEventFilter")]
#[non_exhaustive]
pub struct SubscriptionEventFilter {
    /// Filter incoming events by emitting module, e.g. `"0x02"` (package) or
    /// `"0x02::coin"` (module).
    pub emitting_module: Option<String>,
}

impl SubscriptionEventFilter {
    /// Filter incoming events by emitting module, e.g. `"0x02"` (package) or
    /// `"0x02::coin"` (module).
    pub fn with_emitting_module(mut self, emitting_module: impl Into<Option<String>>) -> Self {
        self.emitting_module = emitting_module.into();
        self
    }
}

/// Filter incoming transactions in a subscription. Exactly one field must be
/// set (the GraphQL input is `@oneOf`).
#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "SubscriptionTransactionFilter")]
#[non_exhaustive]
pub struct SubscriptionTransactionFilter {
    /// Filter incoming transactions by kind.
    pub kind: Option<TransactionBlockKindInput>,
    /// Filter incoming transactions by sender address.
    ///
    /// Only the sender is compared, despite the name — a sponsored
    /// transaction is not matched by its sponsor's (gas owner's) address,
    /// even though the sponsor also signed it.
    pub signing_address: Option<Address>,
    /// Filter incoming transactions by package, module, or function name, e.g.
    /// `"0x03"`, `"0x03::iota_system"`, or
    /// `"0x03::iota_system::request_add_stake"`.
    pub function: Option<String>,
}

impl SubscriptionTransactionFilter {
    /// Filter incoming transactions by kind.
    pub fn with_kind(mut self, kind: impl Into<Option<TransactionBlockKindInput>>) -> Self {
        self.kind = kind.into();
        self
    }

    /// Filter incoming transactions by sender address.
    ///
    /// Only the sender is compared, despite the name — a sponsored transaction
    /// is not matched by its sponsor's (gas owner's) address, even though the
    /// sponsor also signed it.
    pub fn with_signing_address(mut self, signing_address: impl Into<Option<Address>>) -> Self {
        self.signing_address = signing_address.into();
        self
    }

    /// Filter incoming transactions by package, module, or function name, e.g.
    /// `"0x03"`, `"0x03::iota_system"`, or
    /// `"0x03::iota_system::request_add_stake"`.
    pub fn with_function(mut self, function: impl Into<Option<String>>) -> Self {
        self.function = function.into();
        self
    }
}

// ===========================================================================
// Payload unions
// ===========================================================================

#[derive(cynic::InlineFragments, Debug)]
#[cynic(schema = "rpc", graphql_type = "EventSubscriptionPayload")]
#[non_exhaustive]
pub enum EventSubscriptionPayload {
    Event(Box<SubscriptionEvent>),
    Lagged(Lagged),
    #[cynic(fallback)]
    Unknown,
}

#[derive(cynic::InlineFragments, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockSubscriptionPayload")]
#[non_exhaustive]
pub enum TransactionBlockSubscriptionPayload {
    TransactionBlock(SubscriptionTransactionBlock),
    Lagged(Lagged),
    #[cynic(fallback)]
    Unknown,
}

/// Emitted when the server dropped one or more payloads before this one
/// because the subscriber could not keep up.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Lagged")]
pub struct Lagged {
    /// Number of missed payloads since the previously emitted one.
    pub count: i32,
}

// ===========================================================================
// Payload bodies
// ===========================================================================

/// An event as delivered over a subscription. Mirrors [`Event`] but also
/// selects the emitting transaction's digest, which is used as the stream
/// recovery cursor (`startAfter`).
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Event")]
pub struct SubscriptionEvent {
    pub transaction_block: Option<TxBlockDigest>,
    pub sending_module: Option<MoveModuleQuery>,
    pub sender: Option<GQLAddress>,
    #[cynic(rename = "type")]
    pub move_type: MoveType,
    pub bcs: Base64,
    pub timestamp: Option<DateTime>,
    pub data: MoveData,
    pub json: JsonValue,
}

impl SubscriptionEvent {
    /// Digest of the transaction that emitted this event, if available.
    pub(crate) fn transaction_digest(&self) -> Option<String> {
        self.transaction_block
            .as_ref()
            .and_then(|tb| tb.digest.clone())
    }
}

impl From<SubscriptionEvent> for Event {
    fn from(event: SubscriptionEvent) -> Self {
        Event {
            sending_module: event.sending_module,
            sender: event.sender,
            move_type: event.move_type,
            bcs: event.bcs,
            timestamp: event.timestamp,
            data: event.data,
            json: event.json,
        }
    }
}

/// A transaction block as delivered over a subscription. Selects the digest
/// (used as the stream recovery cursor) alongside the `SenderSignedData` BCS
/// that a [`SignedTransaction`] is rebuilt from.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct SubscriptionTransactionBlock {
    pub digest: Option<String>,
    pub bcs: Option<Base64>,
}

impl TryFrom<SubscriptionTransactionBlock> for SignedTransaction {
    type Error = error::Error;

    fn try_from(value: SubscriptionTransactionBlock) -> Result<Self, Self::Error> {
        let transaction = value
            .bcs
            .map(|tx| base64ct::Base64::decode_vec(tx.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<SenderSignedTransaction>(&bcs))
            .transpose()?;

        if let Some(transaction) = transaction {
            Ok(transaction.into())
        } else {
            Err(Error::from_error(
                Kind::Other,
                "Expected a deserialized transaction but got None",
            ))
        }
    }
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct TxBlockDigest {
    pub digest: Option<String>,
}
