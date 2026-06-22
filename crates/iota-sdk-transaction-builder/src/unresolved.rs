// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types representing unresolved data in a PTB.

use std::collections::HashMap;

use iota_types::{Identifier, ObjectId, ObjectReference, SharedObjectReference, TypeTag};

/// An identifier indicating the unresolved index of an input.
pub type InputId = usize;

#[derive(Clone, Debug, Eq, PartialEq)]
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
                iota_types::Input::Pure(..) => None,
                iota_types::Input::ImmutableOrOwned(ObjectReference { object_id, .. })
                | iota_types::Input::Shared(SharedObjectReference { object_id, .. })
                | iota_types::Input::Receiving(ObjectReference { object_id, .. }) => {
                    Some(object_id)
                }
                _ => unimplemented!("a new enum variant was added and needs to be handled"),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
            | iota_types::Input::Shared(SharedObjectReference { object_id, .. }),
        ) = self
        {
            Some(*object_id)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, derive_more::From)]
#[non_exhaustive]
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

impl From<iota_types::Command> for Command {
    fn from(cmd: iota_types::Command) -> Self {
        match cmd {
            iota_types::Command::MoveCall(c) => Self::MoveCall(MoveCall {
                package: c.package,
                module: c.module,
                function: c.function,
                type_arguments: c.type_arguments,
                arguments: c.arguments.into_iter().map(Into::into).collect(),
            }),
            iota_types::Command::TransferObjects(c) => Self::TransferObjects(TransferObjects {
                objects: c.objects.into_iter().map(Into::into).collect(),
                address: c.address.into(),
            }),
            iota_types::Command::SplitCoins(c) => Self::SplitCoins(SplitCoins {
                coin: c.coin.into(),
                amounts: c.amounts.into_iter().map(Into::into).collect(),
            }),
            iota_types::Command::MergeCoins(c) => Self::MergeCoins(MergeCoins {
                coin: c.coin.into(),
                coins_to_merge: c.coins_to_merge.into_iter().map(Into::into).collect(),
            }),
            iota_types::Command::Publish(c) => Self::Publish(Publish {
                modules: c.modules,
                dependencies: c.dependencies,
            }),
            iota_types::Command::MakeMoveVector(c) => Self::MakeMoveVector(MakeMoveVector {
                type_: c.type_,
                elements: c.elements.into_iter().map(Into::into).collect(),
            }),
            iota_types::Command::Upgrade(c) => Self::Upgrade(Upgrade {
                modules: c.modules,
                dependencies: c.dependencies,
                package: c.package,
                ticket: c.ticket.into(),
            }),
            _ => unimplemented!("a new Command enum variant was added and needs to be handled"),
        }
    }
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
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

impl From<iota_types::Argument> for Argument {
    fn from(arg: iota_types::Argument) -> Self {
        match arg {
            iota_types::Argument::Gas => Self::Gas,
            iota_types::Argument::Input(i) => Self::Input(i as InputId),
            iota_types::Argument::Result(i) => Self::Result(i),
            iota_types::Argument::NestedResult(i1, i2) => Self::NestedResult(i1, i2),
            _ => unimplemented!("a new Argument enum variant was added and needs to be handled"),
        }
    }
}
