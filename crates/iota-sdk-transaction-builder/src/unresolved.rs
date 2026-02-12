// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types representing unresolved data in a PTB.

use std::collections::HashMap;

use iota_types::{Identifier, ObjectId, ObjectReference, TypeTag};

/// An identifier indicating the unresolved index of an input.
pub type InputId = usize;

/// A PTB input tracked before full on-chain resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The unresolved input variant.
    pub kind: InputKind,
    /// Whether this input is treated as gas.
    pub is_gas: bool,
}

impl Input {
    /// Returns the referenced object id when this input points to an object.
    ///
    /// Returns `None` for pure-value inputs.
    pub fn object_id(&self) -> Option<&ObjectId> {
        match &self.kind {
            InputKind::ImmutableOrOwned(object_id)
            | InputKind::Shared { object_id, .. }
            | InputKind::Receiving(object_id) => Some(object_id),
            InputKind::Input(input) => match input {
                iota_types::Input::Pure { .. } => None,
                iota_types::Input::ImmutableOrOwned(ObjectReference { object_id, .. })
                | iota_types::Input::Shared { object_id, .. }
                | iota_types::Input::Receiving(ObjectReference { object_id, .. }) => {
                    Some(object_id)
                }
                _ => unimplemented!("a new enum variant was added and needs to be handled"),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Unresolved input variants used during PTB construction.
pub enum InputKind {
    /// Immutable or owned object identified by id.
    ImmutableOrOwned(ObjectId),
    /// Shared object with mutability information.
    Shared { object_id: ObjectId, mutable: bool },
    /// Receiving object identified by id.
    Receiving(ObjectId),
    /// Already-resolved input from `iota_types`.
    Input(iota_types::Input),
}

impl InputKind {
    /// Returns the object id for object-based inputs.
    ///
    /// Returns `None` for non-object inputs.
    pub fn object_id(&self) -> Option<ObjectId> {
        if let Self::ImmutableOrOwned(object_id)
        | Self::Receiving(object_id)
        | Self::Shared { object_id, .. }
        | Self::Input(
            iota_types::Input::ImmutableOrOwned(ObjectReference { object_id, .. })
            | iota_types::Input::Receiving(ObjectReference { object_id, .. })
            | iota_types::Input::Shared { object_id, .. },
        ) = self
        {
            Some(*object_id)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, derive_more::From)]
#[non_exhaustive]
/// Unresolved PTB command variants.
pub enum Command {
    /// Call a Move function.
    MoveCall(MoveCall),
    /// Transfer a list of objects to an address.
    TransferObjects(TransferObjects),
    /// Split a coin into multiple amounts.
    SplitCoins(SplitCoins),
    /// Merge multiple coins into one target coin.
    MergeCoins(MergeCoins),
    /// Publish a package.
    Publish(Publish),
    /// Construct a Move vector.
    MakeMoveVector(MakeMoveVector),
    /// Upgrade an existing package.
    Upgrade(Upgrade),
}

impl Command {
    /// Resolves unresolved command arguments into `iota_types::Command`.
    pub fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::Command {
        match self {
            Command::MoveCall(move_call) => {
                iota_types::Command::MoveCall(move_call.resolve(input_map))
            }
            Command::TransferObjects(transfer_objects) => {
                iota_types::Command::TransferObjects(transfer_objects.resolve(input_map))
            }
            Command::SplitCoins(split_coins) => {
                iota_types::Command::SplitCoins(split_coins.resolve(input_map))
            }
            Command::MergeCoins(merge_coins) => {
                iota_types::Command::MergeCoins(merge_coins.resolve(input_map))
            }
            Command::Publish(publish) => iota_types::Command::Publish(publish.resolve()),
            Command::MakeMoveVector(make_move_vector) => {
                iota_types::Command::MakeMoveVector(make_move_vector.resolve(input_map))
            }
            Command::Upgrade(upgrade) => iota_types::Command::Upgrade(upgrade.resolve(input_map)),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for a Move call command.
pub struct MoveCall {
    /// Package object id containing the target module and function.
    pub package: ObjectId,
    /// Move module name.
    pub module: Identifier,
    /// Move function name.
    pub function: Identifier,
    /// Generic type arguments.
    pub type_arguments: Vec<TypeTag>,
    /// Positional function arguments.
    pub arguments: Vec<Argument>,
}

impl MoveCall {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::MoveCall {
        iota_types::MoveCall {
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: self.type_arguments,
            arguments: self
                .arguments
                .into_iter()
                .map(|c| c.resolve(input_map))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for a package upgrade command.
pub struct Upgrade {
    /// Compiled Move modules.
    pub modules: Vec<Vec<u8>>,
    /// Package dependency ids.
    pub dependencies: Vec<ObjectId>,
    /// Target package id to upgrade.
    pub package: ObjectId,
    /// Upgrade capability ticket argument.
    pub ticket: Argument,
}

impl Upgrade {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::Upgrade {
        iota_types::Upgrade {
            modules: self.modules,
            dependencies: self.dependencies,
            package: self.package,
            ticket: self.ticket.resolve(input_map),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for creating a Move vector.
pub struct MakeMoveVector {
    /// Optional element type tag.
    pub type_: Option<TypeTag>,
    /// Vector elements.
    pub elements: Vec<Argument>,
}

impl MakeMoveVector {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::MakeMoveVector {
        iota_types::MakeMoveVector {
            type_: self.type_,
            elements: self
                .elements
                .into_iter()
                .map(|c| c.resolve(input_map))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for transferring objects.
pub struct TransferObjects {
    /// Objects to transfer.
    pub objects: Vec<Argument>,
    /// Recipient address argument.
    pub address: Argument,
}

impl TransferObjects {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::TransferObjects {
        iota_types::TransferObjects {
            objects: self
                .objects
                .into_iter()
                .map(|c| c.resolve(input_map))
                .collect(),
            address: self.address.resolve(input_map),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for splitting a coin.
pub struct SplitCoins {
    /// Source coin.
    pub coin: Argument,
    /// Amount arguments for each split output.
    pub amounts: Vec<Argument>,
}

impl SplitCoins {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::SplitCoins {
        iota_types::SplitCoins {
            coin: self.coin.resolve(input_map),
            amounts: self
                .amounts
                .into_iter()
                .map(|c| c.resolve(input_map))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for merging coins.
pub struct MergeCoins {
    /// Destination coin.
    pub coin: Argument,
    /// Coins to merge into `coin`.
    pub coins_to_merge: Vec<Argument>,
}

impl MergeCoins {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::MergeCoins {
        iota_types::MergeCoins {
            coin: self.coin.resolve(input_map),
            coins_to_merge: self
                .coins_to_merge
                .into_iter()
                .map(|c| c.resolve(input_map))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
/// Unresolved payload for publishing a package.
pub struct Publish {
    /// Compiled Move modules.
    pub modules: Vec<Vec<u8>>,
    /// Package dependency ids.
    pub dependencies: Vec<ObjectId>,
}

impl Publish {
    fn resolve(self) -> iota_types::Publish {
        iota_types::Publish {
            modules: self.modules,
            dependencies: self.dependencies,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
/// Unresolved command argument variants.
pub enum Argument {
    /// Gas coin argument.
    Gas,
    /// Input index argument.
    Input(InputId),
    /// Command result argument.
    Result(u16),
    /// Nested result argument (`command_index`, `result_index`).
    NestedResult(u16, u16),
}

impl Argument {
    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::Argument {
        match self {
            Argument::Gas => iota_types::Argument::Gas,
            Argument::Input(i) => input_map
                .get(&i)
                .map(|i| iota_types::Argument::Input(*i))
                .unwrap_or(iota_types::Argument::Gas),
            Argument::Result(i) => iota_types::Argument::Result(i),
            Argument::NestedResult(i1, i2) => iota_types::Argument::NestedResult(i1, i2),
        }
    }
}
