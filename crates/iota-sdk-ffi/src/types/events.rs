// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_types::{Identifier, StructTag};

use crate::types::{address::Address, object::ObjectId};

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
}

impl From<iota_types::Event> for Event {
    fn from(value: iota_types::Event) -> Self {
        Self {
            package_id: Arc::new(value.package_id.into()),
            module: value.module.to_string(),
            sender: Arc::new(value.sender.into()),
            type_: value.type_.to_string(),
            contents: value.contents,
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
        }
    }
}
