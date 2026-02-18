// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, Identifier, ObjectId, StructTag, TypeTag};

/// Events emitted during the successful execution of a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// transaction-events = vector event
/// ```
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct BalanceChange {
    /// Owner of the balance change
    pub address: Address,
    /// Type of the Coin
    pub coin_type: TypeTag,
    /// The amount indicate the balance value changes.
    ///
    /// A negative amount means spending coin value and positive means receiving
    /// coin value.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::I128"))]
    pub amount: i128,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TransactionEvents tests ---

    #[test]
    fn transaction_events_empty() {
        let events = TransactionEvents(vec![]);
        assert!(events.0.is_empty());
    }

    #[test]
    fn transaction_events_with_events() {
        let event = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("test_module").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("m").unwrap(),
                Identifier::new("E").unwrap(),
                Vec::new(),
            ),
            contents: vec![1, 2, 3],
        };
        let events = TransactionEvents(vec![event]);
        assert_eq!(events.0.len(), 1);
    }

    #[test]
    fn transaction_events_clone_eq() {
        let events = TransactionEvents(vec![]);
        let cloned = events.clone();
        assert_eq!(events, cloned);
    }

    // --- Event tests ---

    #[test]
    fn event_field_access() {
        let event = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("my_module").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("mod").unwrap(),
                Identifier::new("MyEvent").unwrap(),
                Vec::new(),
            ),
            contents: vec![0xAB, 0xCD],
        };
        assert_eq!(event.package_id, ObjectId::ZERO);
        assert_eq!(event.module.as_str(), "my_module");
        assert_eq!(event.sender, Address::ZERO);
        assert_eq!(event.contents, vec![0xAB, 0xCD]);
    }

    #[test]
    fn event_clone_eq() {
        let event = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("m").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("m").unwrap(),
                Identifier::new("E").unwrap(),
                Vec::new(),
            ),
            contents: vec![],
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn event_ne_different_contents() {
        let e1 = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("m").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("m").unwrap(),
                Identifier::new("E").unwrap(),
                Vec::new(),
            ),
            contents: vec![1],
        };
        let e2 = Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("m").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("m").unwrap(),
                Identifier::new("E").unwrap(),
                Vec::new(),
            ),
            contents: vec![2],
        };
        assert_ne!(e1, e2);
    }

    // --- BalanceChange tests ---

    #[test]
    fn balance_change_positive_amount() {
        let bc = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 1000,
        };
        assert_eq!(bc.amount, 1000);
        assert!(bc.amount > 0);
    }

    #[test]
    fn balance_change_negative_amount() {
        let bc = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: -500,
        };
        assert_eq!(bc.amount, -500);
        assert!(bc.amount < 0);
    }

    #[test]
    fn balance_change_zero_amount() {
        let bc = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 0,
        };
        assert_eq!(bc.amount, 0);
    }

    #[test]
    fn balance_change_clone_eq() {
        let bc1 = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 42,
        };
        let bc2 = bc1.clone();
        assert_eq!(bc1, bc2);
    }

    #[test]
    fn balance_change_ordering() {
        let bc1 = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: -100,
        };
        let bc2 = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 100,
        };
        assert!(bc1 < bc2);
    }

    #[test]
    fn balance_change_ne_different_amount() {
        let bc1 = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 1,
        };
        let bc2 = BalanceChange {
            address: Address::ZERO,
            coin_type: TypeTag::Bool,
            amount: 2,
        };
        assert_ne!(bc1, bc2);
    }

    #[test]
    fn transaction_events_multiple_events() {
        let mk_event = |contents: Vec<u8>| Event {
            package_id: ObjectId::ZERO,
            module: Identifier::new("m").unwrap(),
            sender: Address::ZERO,
            type_: StructTag::new(
                Address::ZERO,
                Identifier::new("m").unwrap(),
                Identifier::new("E").unwrap(),
                Vec::new(),
            ),
            contents,
        };
        let events = TransactionEvents(vec![mk_event(vec![1]), mk_event(vec![2]), mk_event(vec![3])]);
        assert_eq!(events.0.len(), 3);
        assert_eq!(events.0[0].contents, vec![1]);
        assert_eq!(events.0[2].contents, vec![3]);
    }
}
