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
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct TransactionEvents(pub Vec<Event>);

/// An event
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// event = object-id identifier address struct-tag bytes
/// ```
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    pub type_: StructTag,
    /// BCS serialized bytes of the event
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::ReadableBase64Encoded")
    )]
    pub contents: Vec<u8>,
}

impl Event {
    fn is_system_epoch_info_event_type(&self, name: Identifier) -> bool {
        self.type_.address() == Address::SYSTEM
            && *self.type_.module() == Identifier::IOTA_SYSTEM_STATE_INNER_MODULE
            && *self.type_.name() == name
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

impl core::fmt::Display for Event {
    fn fmt(&self, f: &mut core::fmt::Display::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Event {{\n  package_id: {},\n  module: {},\n  sender: {},\n  type: {}\n}}",
            self.package_id, self.module, self.sender, self.type_
        )
    }
}

impl core::fmt::Display for TransactionEvents {
    fn fmt(&self, f: &mut core::fmt::Display::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "TransactionEvents [")?;
        for event in &self.0 {
            let s = format!("{}", event);
            for line in s.lines() {
                writeln!(f, "  {}", line)?;
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, Identifier, ObjectId, StructTag};

    #[test]
    fn test_event_display() {
        let event = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("test").unwrap(),
            sender: Address::ZERO,
            type_: StructTag {
                address: Address::ZERO,
                module: Identifier::new("m").unwrap(),
                name: Identifier::new("n").unwrap(),
                type_params: vec![],
            },
            contents: vec![],
        };
        let s = format!("{}", event);
        assert!(s.contains("package_id:"));
        assert!(s.contains("sender:"));
    }
}
