// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_types::{Identifier, StructTag};

use crate::types::{address::Address, digest::Digest, object::ObjectId};

/// An event
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
    /// UTC timestamp in milliseconds since epoch (1/1/1970)
    pub timestamp: String,
    /// Structured contents of a Move value
    pub data: String,
    /// Representation of a Move value in JSON
    pub json: String,
}

impl From<iota_types::Event> for Event {
    fn from(value: iota_types::Event) -> Self {
        Self {
            package_id: Arc::new(value.package_id.into()),
            module: value.module.to_string(),
            sender: Arc::new(value.sender.into()),
            type_: value.type_.to_string(),
            contents: value.contents,
            timestamp: value.timestamp.clone(),
            data: value.data.clone(),
            json: value.json.to_string(),
        }
    }
}

impl From<Event> for iota_types::Event {
    fn from(value: Event) -> Self {
        Self {
            package_id: (**value.package_id),
            module: Identifier::from_str(&value.module).unwrap(),
            sender: (**value.sender),
            type_: StructTag::from_str(&value.type_).unwrap(),
            contents: value.contents,
            timestamp: value.timestamp.clone(),
            data: value.data.clone(),
            json: value.json.clone(),
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
pub struct TransactionEvents(pub iota_types::TransactionEvents);

#[uniffi::export]
impl TransactionEvents {
    #[uniffi::constructor]
    pub fn new(events: Vec<Event>) -> Self {
        Self(iota_types::TransactionEvents(
            events.into_iter().map(Into::into).collect(),
        ))
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.0.iter().cloned().map(Into::into).collect()
    }

    pub fn digest(&self) -> Digest {
        self.0.digest().into()
    }
}
