// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, Identifier, ObjectId, StructTag};

/// Events emitted during the successful execution of a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-events = vector event
/// ```
#[derive(Clone, Debug, Default, derive_more::Deref, derive_more::DerefMut, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct TransactionEvents(pub Vec<Event>);

impl crate::TreeDisplay for TransactionEvents {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Transaction Events")?;
        w.children("Events", &self.0, true)
    }
}

/// An event
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// event = object-id identifier address struct-tag bytes
/// ```
#[derive(Clone, derive_more::Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct Event {
    /// Package id of the top-level function invoked by a MoveCall command which
    /// triggered this event to be emitted.
    pub package_id: ObjectId,
    /// Module name of the top-level function invoked by a MoveCall command
    /// which triggered this event to be emitted.
    pub module: Identifier,
    /// Address of the account that sent the transaction where this event was
    /// emitted.
    pub sender: Address,
    /// The type of the event emitted
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub struct_tag: StructTag,
    /// BCS serialized bytes of the event
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::ReadableBase64Encoded")
    )]
    #[debug("{:?}", <base64ct::Base64 as base64ct::Encoding>::encode_string(contents))]
    pub contents: Vec<u8>,
}

impl Event {
    fn is_system_epoch_info_event_type(&self, name: Identifier) -> bool {
        self.struct_tag.address() == Address::SYSTEM
            && *self.struct_tag.module() == Identifier::IOTA_SYSTEM_STATE_INNER_MODULE
            && *self.struct_tag.name() == name
    }

    /// Checks if this is a `SystemEpochInfoEvent` of any version (V1 or V2).
    pub fn is_system_epoch_info_event(&self) -> bool {
        self.is_system_epoch_info_event_v1() || self.is_system_epoch_info_event_v2()
    }

    /// Checks if this is
    /// `0x3::iota_system_state_inner::SystemEpochInfoEventV1`.
    pub fn is_system_epoch_info_event_v1(&self) -> bool {
        self.is_system_epoch_info_event_type(Identifier::SYSTEM_EPOCH_INFO_EVENT_V1)
    }

    /// Checks if this is
    /// `0x3::iota_system_state_inner::SystemEpochInfoEventV2`.
    pub fn is_system_epoch_info_event_v2(&self) -> bool {
        self.is_system_epoch_info_event_type(Identifier::SYSTEM_EPOCH_INFO_EVENT_V2)
    }
}

impl crate::TreeDisplay for Event {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Event")?;
        w.leaf("Package ID", &self.package_id, false)?;
        w.leaf("Module", &self.module, false)?;
        w.leaf("Sender", &self.sender, false)?;
        w.leaf("Struct Tag", &self.struct_tag, false)?;
        w.leaf("Contents", &hex::encode(&self.contents), true)
    }
}

crate::impl_tree_display!(TransactionEvents, Event);
