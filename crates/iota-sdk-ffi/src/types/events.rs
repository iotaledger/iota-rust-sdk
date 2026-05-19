// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use base64ct::Encoding;
use iota_sdk::{
    graphql_client::query_types::{
        Base64, DateTime, GQLAddress, MoveData, MoveModuleQuery, MovePackageQuery, MoveType,
    },
    types::{Identifier, StructTag},
};

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
    /// triggered this event to be emitted. Optional because some system
    /// events (e.g. validator events) are emitted without a sending module.
    pub package_id: Option<Arc<ObjectId>>,
    /// Module name of the top-level function invoked by a MoveCall command
    /// which triggered this event to be emitted. Optional because some system
    /// events (e.g. validator events) are emitted without a sending module.
    pub module: Option<String>,
    /// Address of the account that sent the transaction where this event was
    /// emitted. Optional because some system events are emitted without a
    /// sender.
    pub sender: Option<Arc<Address>>,
    /// The type of the event emitted
    pub type_: String,
    /// BCS serialized bytes of the event
    pub contents: Vec<u8>,
    /// UTC timestamp in milliseconds since epoch (1/1/1970)
    pub timestamp: Option<String>,
    /// Structured contents of a Move value
    pub data: String,
    /// Representation of a Move value in JSON
    pub json: String,
}

impl From<iota_sdk::graphql_client::query_types::Event> for Event {
    fn from(value: iota_sdk::graphql_client::query_types::Event) -> Self {
        let sending_module = value.sending_module.as_ref();
        Self {
            package_id: sending_module.map(|module| {
                Arc::new(ObjectId(iota_sdk::types::ObjectId::from(
                    module.package.address,
                )))
            }),
            module: sending_module.map(|module| module.name.clone()),
            sender: value
                .sender
                .as_ref()
                .map(|sender| Arc::new(Address(sender.address))),
            type_: value.type_.repr.clone(),
            contents: base64ct::Base64::decode_vec(&value.bcs.0).unwrap_or_default(),
            timestamp: value.timestamp.as_ref().map(|ts| ts.0.clone()),
            data: value.data.0.to_string(),
            json: value.json.to_string(),
        }
    }
}

impl From<Event> for iota_sdk::types::Event {
    fn from(value: Event) -> Self {
        Self {
            package_id: value
                .package_id
                .map(|id| **id)
                .unwrap_or(iota_sdk::types::ObjectId::ZERO),
            module: Identifier::from_str(value.module.as_deref().unwrap_or("")).unwrap(),
            sender: value
                .sender
                .map(|s| **s)
                .unwrap_or(iota_sdk::types::Address::ZERO),
            type_: StructTag::from_str(&value.type_).unwrap(),
            contents: value.contents,
        }
    }
}

impl From<Event> for iota_sdk::graphql_client::query_types::Event {
    fn from(value: Event) -> Self {
        Self {
            sending_module: value.package_id.as_ref().map(|package_id| MoveModuleQuery {
                package: MovePackageQuery {
                    address: iota_sdk::types::Address::from(***package_id),
                    bcs: None,
                },
                name: value.module.clone().unwrap_or_default(),
            }),
            sender: value
                .sender
                .as_ref()
                .map(|sender| GQLAddress { address: ***sender }),
            type_: MoveType {
                repr: value.type_.clone(),
            },
            bcs: Base64(base64ct::Base64::encode_string(&value.contents)),
            timestamp: value.timestamp.clone().map(DateTime),
            data: MoveData(serde_json::from_str(&value.data).unwrap_or_default()),
            json: serde_json::Value::from_str(&value.json).unwrap_or_default(),
        }
    }
}

impl From<iota_sdk::types::Event> for Event {
    fn from(value: iota_sdk::types::Event) -> Self {
        Self {
            package_id: Some(Arc::new(value.package_id.into())),
            module: Some(value.module.to_string()),
            sender: Some(Arc::new(value.sender.into())),
            type_: value.type_.to_string(),
            contents: value.contents,
            timestamp: None,
            data: String::new(),
            json: String::new(),
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
    pub fn new(events: Vec<Event>) -> Self {
        Self(iota_sdk::types::TransactionEvents(
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

crate::export_iota_types_bcs_conversion!(Event);
crate::export_iota_types_objects_bcs_conversion!(TransactionEvents);
crate::export_iota_types_json_conversion!(Event);
crate::export_iota_types_objects_json_conversion!(TransactionEvents);
