// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_sdk::types::{Identifier, StructTag};

use crate::{
    error::Result,
    types::{address::Address, digest::Digest, object::ObjectId},
};

/// An event emitted during the successful execution of a transaction.
///
/// This mirrors the core chain [`iota_sdk::types::Event`] one-to-one: every
/// field is required and the type round-trips through BCS/JSON. For events
/// returned by the GraphQL `events` query — which may originate from system
/// transactions and therefore lack a sender or emitting module — see
/// [`GraphQlEvent`](crate::graphql::query_types::GraphQlEvent).
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// event = object-id identifier address struct-tag bytes
/// ```
#[derive(uniffi::Record)]
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
    pub type_: String,
    /// BCS serialized bytes of the event
    pub contents: Vec<u8>,
}

impl TryFrom<Event> for iota_sdk::types::Event {
    type Error = crate::error::SdkFfiError;

    fn try_from(value: Event) -> Result<Self> {
        Ok(Self {
            package_id: (**value.package_id),
            module: Identifier::from_str(&value.module)?,
            sender: (**value.sender),
            type_: StructTag::from_str(&value.type_)?,
            contents: value.contents,
        })
    }
}

impl From<iota_sdk::types::Event> for Event {
    fn from(value: iota_sdk::types::Event) -> Self {
        Self {
            package_id: Arc::new(value.package_id.into()),
            module: value.module.to_string(),
            sender: Arc::new(value.sender.into()),
            type_: value.type_.to_string(),
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
            events
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
        )))
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.0.iter().cloned().map(Into::into).collect()
    }

    pub fn digest(&self) -> Digest {
        self.0.digest().into()
    }
}

/// Create an [`Event`] from BCS encoded bytes.
#[uniffi::export]
pub fn event_from_bcs(bcs: Vec<u8>) -> Result<Event> {
    Ok(bcs::from_bytes::<iota_sdk::types::Event>(&bcs)?.into())
}

/// Convert an [`Event`] to BCS encoded bytes.
#[uniffi::export]
pub fn event_to_bcs(data: Event) -> Result<Vec<u8>> {
    let data: iota_sdk::types::Event = data.try_into()?;
    Ok(bcs::to_bytes(&data)?)
}

/// Create an [`Event`] from a JSON encoded string.
#[uniffi::export]
pub fn event_from_json(json: &str) -> Result<Event> {
    Ok(serde_json::from_str::<iota_sdk::types::Event>(json)?.into())
}

/// Convert an [`Event`] to a JSON encoded string.
#[uniffi::export]
pub fn event_to_json(data: Event) -> Result<String> {
    let data: iota_sdk::types::Event = data.try_into()?;
    Ok(serde_json::to_string(&data)?)
}

crate::export_iota_types_objects_bcs_conversion!(TransactionEvents);
crate::export_iota_types_objects_json_conversion!(TransactionEvents);
