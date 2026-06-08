// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Subscription operations for the live `events` and `transactions` streams.
//!
//! These map the GraphQL `Subscription` root, whose `events` and
//! `transactions` fields each return a union of the payload type and
//! [`Lagged`] (emitted when the server's broker had to drop messages).

use base64ct::Encoding;
use iota_types::{SenderSignedTransaction, SignedTransaction, UserSignature};

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

/// Filter incoming events in a subscription. Exactly one field may be set
/// (the GraphQL input is `@oneOf`).
#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "SubscriptionEventFilter")]
pub struct SubscriptionEventFilter {
    /// Filter incoming events by emitting module, e.g. `"0x02"` (package) or
    /// `"0x02::coin"` (module).
    pub emitting_module: Option<String>,
}

/// Filter incoming transactions in a subscription. Exactly one field may be
/// set (the GraphQL input is `@oneOf`).
#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "SubscriptionTransactionFilter")]
pub struct SubscriptionTransactionFilter {
    /// Filter incoming transactions by kind.
    pub kind: Option<TransactionBlockKindInput>,
    /// Filter incoming transactions by signing address.
    pub signing_address: Option<Address>,
    /// Filter incoming transactions by package, module, or function name, e.g.
    /// `"0x03"`, `"0x03::iota_system"`, or
    /// `"0x03::iota_system::request_add_stake"`.
    pub function: Option<String>,
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
    pub type_: MoveType,
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
            type_: event.type_,
            bcs: event.bcs,
            timestamp: event.timestamp,
            data: event.data,
            json: event.json,
        }
    }
}

/// A transaction block as delivered over a subscription. Selects the digest
/// (used as the stream recovery cursor) alongside the fields needed to rebuild
/// a [`SignedTransaction`].
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct SubscriptionTransactionBlock {
    pub digest: Option<String>,
    pub bcs: Option<Base64>,
    pub signatures: Option<Vec<Base64>>,
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

        let signatures = if let Some(sigs) = value.signatures {
            sigs.iter()
                .map(|s| UserSignature::from_base64(&s.0))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };

        if let Some(transaction) = transaction {
            Ok(SignedTransaction {
                transaction: transaction.0.transaction,
                signatures,
            })
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
