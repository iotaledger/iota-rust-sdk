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

use crate::{
    error::Result,
    types::{address::Address, digest::Digest, object::ObjectId},
};

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

impl From<iota_sdk::graphql_client::query_types::Event> for Event {
    fn from(value: iota_sdk::graphql_client::query_types::Event) -> Self {
        let sending_module = value.sending_module.as_ref().unwrap();
        Self {
            package_id: Arc::new(ObjectId(iota_sdk::types::ObjectId::from(
                sending_module.package.address,
            ))),
            module: sending_module.name.clone(),
            sender: Arc::new(Address(value.sender.as_ref().unwrap().address)),
            type_: value.type_.repr.clone(),
            contents: base64ct::Base64::decode_vec(&value.bcs.0).unwrap_or_default(),
            timestamp: value.timestamp.as_ref().unwrap().0.clone(),
            data: value.data.0.to_string(),
            json: value.json.to_string(),
        }
    }
}

impl From<Event> for iota_sdk::types::Event {
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

impl From<Event> for iota_sdk::graphql_client::query_types::Event {
    fn from(value: Event) -> Self {
        Self {
            sending_module: Some(MoveModuleQuery {
                package: MovePackageQuery {
                    address: iota_sdk::types::Address::from(**value.package_id),
                    bcs: None,
                },
                name: value.module.clone(),
            }),
            sender: Some(GQLAddress {
                address: (**value.sender),
            }),
            type_: MoveType {
                repr: value.type_.clone(),
            },
            bcs: Base64(base64ct::Base64::encode_string(&value.contents)),
            timestamp: Some(DateTime(value.timestamp.clone())),
            data: MoveData(serde_json::from_str(&value.data).unwrap_or_default()),
            json: serde_json::Value::from_str(&value.json).unwrap_or_default(),
        }
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
            timestamp: String::new(),
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
