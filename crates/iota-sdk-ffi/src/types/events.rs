// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::Identifier;

use crate::{
    error::Result,
    types::{
        address::Address, digest::TransactionEventsDigest, move_core::StructTag, object::ObjectId,
    },
};

/// An event emitted during the successful execution of a transaction.
///
/// This mirrors the core chain [`iota_sdk::types::Event`] one-to-one: every
/// field is required and the type round-trips through BCS/JSON. For events
/// returned by the GraphQL `events` query — which may originate from system
/// transactions and therefore lack a sender or emitting module — see
/// [`GraphQLEvent`](crate::graphql::query_types::GraphQLEvent).
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// event = object-id identifier address struct-tag bytes
/// ```
#[derive(Clone, uniffi::Record)]
pub struct Event {
    /// Package id of the top-level function invoked by a MoveCall command which
    /// triggered this event to be emitted.
    pub package_id: Arc<ObjectId>,
    /// Module name of the top-level function invoked by a MoveCall command
    /// which triggered this event to be emitted.
    pub module: String,
    /// Address of the account that sent the transaction where this event was
    /// emitted.
    pub sender: Arc<Address>,
    /// The type of the event emitted
    pub struct_tag: Arc<StructTag>,
    /// BCS serialized bytes of the event
    pub contents: Vec<u8>,
}

impl From<Event> for iota_sdk::types::Event {
    fn from(value: Event) -> Self {
        Self {
            package_id: (**value.package_id),
            module: Identifier::new_unchecked(&value.module),
            sender: (**value.sender),
            struct_tag: value.struct_tag.0.clone(),
            contents: value.contents,
        }
    }
}

impl From<iota_sdk::types::Event> for Event {
    fn from(value: iota_sdk::types::Event) -> Self {
        Self {
            package_id: Arc::new(value.package_id.into()),
            module: value.module.to_string(),
            sender: Arc::new(value.sender.into()),
            struct_tag: Arc::new(value.struct_tag.into()),
            contents: value.contents,
        }
    }
}

/// Events emitted during the successful execution of a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-events = vector event
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct TransactionEvents(pub iota_sdk::types::TransactionEvents);

#[uniffi::export]
impl TransactionEvents {
    #[uniffi::constructor]
    pub fn new(events: Vec<Event>) -> Result<Self> {
        Ok(Self(iota_sdk::types::TransactionEvents(
            events.into_iter().map(Into::into).collect::<Vec<_>>(),
        )))
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.0.iter().cloned().map(Into::into).collect()
    }

    pub fn digest(&self) -> TransactionEventsDigest {
        self.0.digest().into()
    }
}

crate::export_iota_types_bcs_conversion!(Event);
crate::export_iota_types_json_conversion!(Event);
crate::export_iota_types_display!(Event);
crate::export_iota_types_objects_bcs_conversion!(TransactionEvents);
crate::export_iota_types_objects_json_conversion!(TransactionEvents);
crate::export_iota_types_objects_display!(TransactionEvents);
