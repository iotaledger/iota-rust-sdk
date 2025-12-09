// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types representing unresolved data in a PTB.

use std::collections::HashMap;

use iota_types::{Identifier, ObjectId, ObjectReference, TypeTag};

/// An identifier indicating the unresolved index of an input.
pub type InputId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub kind: InputKind,
    pub is_gas: bool,
}

impl Input {
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
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKind {
    ImmutableOrOwned(ObjectId),
    Shared { object_id: ObjectId, mutable: bool },
    Receiving(ObjectId),
    Input(iota_types::Input),
}

impl InputKind {
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
pub enum Command {
    MoveCall(MoveCall),
    TransferObjects(TransferObjects),
    SplitCoins(SplitCoins),
    MergeCoins(MergeCoins),
    Publish(Publish),
    MakeMoveVector(MakeMoveVector),
    Upgrade(Upgrade),
}

impl Command {
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
pub struct MoveCall {
    pub package: ObjectId,
    pub module: Identifier,
    pub function: Identifier,
    pub type_arguments: Vec<TypeTag>,
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
pub struct Upgrade {
    pub modules: Vec<Vec<u8>>,
    pub dependencies: Vec<ObjectId>,
    pub package: ObjectId,
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
pub struct MakeMoveVector {
    pub type_: Option<TypeTag>,
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
pub struct TransferObjects {
    pub objects: Vec<Argument>,
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
pub struct SplitCoins {
    pub coin: Argument,
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
pub struct MergeCoins {
    pub coin: Argument,
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
pub struct Publish {
    pub modules: Vec<Vec<u8>>,
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
pub enum Argument {
    Gas,
    Input(InputId),
    Result(u16),
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
