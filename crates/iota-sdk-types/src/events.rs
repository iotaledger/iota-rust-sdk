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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
