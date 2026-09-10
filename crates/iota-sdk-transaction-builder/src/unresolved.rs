// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types representing unresolved data in a PTB.

use std::collections::HashMap;

use iota_types::{Identifier, ObjectId, ObjectReference, SharedObjectReference, TypeTag};

/// An identifier indicating the unresolved index of an input.
pub type InputId = usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    pub(crate) kind: InputKind,
    pub(crate) is_gas: bool,
}

impl Input {
    /// Construct an input of the given kind.
    pub fn new(kind: InputKind, is_gas: bool) -> Self {
        Self { kind, is_gas }
    }

    /// What this input refers to.
    pub fn kind(&self) -> &InputKind {
        &self.kind
    }

    /// Whether this input is part of the gas payment.
    pub fn is_gas(&self) -> bool {
        self.is_gas
    }

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
                _ => unimplemented!("a new Input enum variant was added and needs to be handled"),
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

    /// The arguments of this command that cannot be replaced by
    /// [`Argument::Gas`].
    ///
    /// [`Argument::Gas`] stands for the whole gas payment — every gas coin
    /// smashed into one — so substituting it for an argument that names a
    /// single coin changes what the command operates on. The positions left
    /// out take a coin without consuming it: a coin split from or merged into
    /// is still there afterwards.
    pub(crate) fn arguments_that_cannot_be_gas(&self) -> &[Argument] {
        match self {
            Command::MoveCall(MoveCall { arguments, .. }) => arguments,
            Command::TransferObjects(TransferObjects { objects, .. }) => objects,
            Command::MergeCoins(MergeCoins { coins_to_merge, .. }) => coins_to_merge,
            _ => &[],
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
                type_tag: c.type_tag,
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
    pub(crate) package: ObjectId,
    pub(crate) module: Identifier,
    pub(crate) function: Identifier,
    pub(crate) type_arguments: Vec<TypeTag>,
    pub(crate) arguments: Vec<Argument>,
}

impl MoveCall {
    /// Construct a call to `package::module::function`.
    pub fn new(
        package: ObjectId,
        module: Identifier,
        function: Identifier,
        type_arguments: Vec<TypeTag>,
        arguments: Vec<Argument>,
    ) -> Self {
        Self {
            package,
            module,
            function,
            type_arguments,
            arguments,
        }
    }

    /// The package holding the function being called.
    pub fn package(&self) -> &ObjectId {
        &self.package
    }

    /// The module holding the function being called.
    pub fn module(&self) -> &Identifier {
        &self.module
    }

    /// The function being called.
    pub fn function(&self) -> &Identifier {
        &self.function
    }

    /// The type arguments the call is instantiated with.
    pub fn type_arguments(&self) -> &[TypeTag] {
        &self.type_arguments
    }

    /// The arguments passed to the call.
    pub fn arguments(&self) -> &[Argument] {
        &self.arguments
    }

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
    pub(crate) modules: Vec<Vec<u8>>,
    pub(crate) dependencies: Vec<ObjectId>,
    pub(crate) package: ObjectId,
    pub(crate) ticket: Argument,
}

impl Upgrade {
    /// Construct an upgrade of `package` authorized by `ticket`.
    pub fn new(
        modules: Vec<Vec<u8>>,
        dependencies: Vec<ObjectId>,
        package: ObjectId,
        ticket: Argument,
    ) -> Self {
        Self {
            modules,
            dependencies,
            package,
            ticket,
        }
    }

    /// The bytecode modules of the new package version.
    pub fn modules(&self) -> &[Vec<u8>] {
        &self.modules
    }

    /// The packages the new version depends on.
    pub fn dependencies(&self) -> &[ObjectId] {
        &self.dependencies
    }

    /// The package being upgraded.
    pub fn package(&self) -> &ObjectId {
        &self.package
    }

    /// The `UpgradeTicket` authorizing the upgrade.
    pub fn ticket(&self) -> Argument {
        self.ticket
    }

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
    pub(crate) type_tag: Option<TypeTag>,
    pub(crate) elements: Vec<Argument>,
}

impl MakeMoveVector {
    /// Construct a Move vector of `elements`.
    ///
    /// `type_tag` names the element type; it may be omitted when the type can
    /// be inferred from the elements.
    pub fn new(type_tag: Option<TypeTag>, elements: Vec<Argument>) -> Self {
        Self { type_tag, elements }
    }

    /// The element type, if it was given explicitly.
    pub fn type_tag(&self) -> Option<&TypeTag> {
        self.type_tag.as_ref()
    }

    /// The elements of the vector.
    pub fn elements(&self) -> &[Argument] {
        &self.elements
    }

    fn resolve(self, input_map: &HashMap<InputId, u16>) -> iota_types::MakeMoveVector {
        iota_types::MakeMoveVector {
            type_tag: self.type_tag,
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
    pub(crate) objects: Vec<Argument>,
    pub(crate) address: Argument,
}

impl TransferObjects {
    /// Construct a transfer of `objects` to `address`.
    pub fn new(objects: Vec<Argument>, address: Argument) -> Self {
        Self { objects, address }
    }

    /// The objects being transferred.
    pub fn objects(&self) -> &[Argument] {
        &self.objects
    }

    /// The recipient.
    pub fn address(&self) -> Argument {
        self.address
    }

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
    pub(crate) coin: Argument,
    pub(crate) amounts: Vec<Argument>,
}

impl SplitCoins {
    /// Construct a split of `coin` into `amounts`.
    pub fn new(coin: Argument, amounts: Vec<Argument>) -> Self {
        Self { coin, amounts }
    }

    /// The coin being split.
    pub fn coin(&self) -> Argument {
        self.coin
    }

    /// The amount to put in each new coin.
    pub fn amounts(&self) -> &[Argument] {
        &self.amounts
    }

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
    pub(crate) coin: Argument,
    pub(crate) coins_to_merge: Vec<Argument>,
}

impl MergeCoins {
    /// Construct a merge of `coins_to_merge` into `coin`.
    pub fn new(coin: Argument, coins_to_merge: Vec<Argument>) -> Self {
        Self {
            coin,
            coins_to_merge,
        }
    }

    /// The coin the others are merged into.
    pub fn coin(&self) -> Argument {
        self.coin
    }

    /// The coins being merged in and consumed.
    pub fn coins_to_merge(&self) -> &[Argument] {
        &self.coins_to_merge
    }

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
    pub(crate) modules: Vec<Vec<u8>>,
    pub(crate) dependencies: Vec<ObjectId>,
}

impl Publish {
    /// Construct a publish of `modules`.
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<ObjectId>) -> Self {
        Self {
            modules,
            dependencies,
        }
    }

    /// The bytecode modules of the package.
    pub fn modules(&self) -> &[Vec<u8>] {
        &self.modules
    }

    /// The packages this one depends on.
    pub fn dependencies(&self) -> &[ObjectId] {
        &self.dependencies
    }

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
