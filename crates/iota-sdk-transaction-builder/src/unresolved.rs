// Copyright (c) 2025 IOTA Stiftung
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
                _ => unimplemented!("a new enum variant was added and needs to be handled"),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use iota_types::{Identifier, ObjectId, ObjectReference, TypeTag};

    use super::*;

    // --- InputKind::object_id tests ---

    #[test]
    fn input_kind_immutable_or_owned_returns_object_id() {
        let id = ObjectId::ZERO;
        let kind = InputKind::ImmutableOrOwned(id);
        assert_eq!(kind.object_id(), Some(id));
    }

    #[test]
    fn input_kind_shared_returns_object_id() {
        let id = ObjectId::ZERO;
        let kind = InputKind::Shared {
            object_id: id,
            mutable: true,
        };
        assert_eq!(kind.object_id(), Some(id));
    }

    #[test]
    fn input_kind_receiving_returns_object_id() {
        let id = ObjectId::ZERO;
        let kind = InputKind::Receiving(id);
        assert_eq!(kind.object_id(), Some(id));
    }

    #[test]
    fn input_kind_pure_input_returns_none() {
        let kind = InputKind::Input(iota_types::Input::Pure {
            value: vec![1, 2, 3],
        });
        assert_eq!(kind.object_id(), None);
    }

    #[test]
    fn input_kind_input_immutable_returns_object_id() {
        let id = ObjectId::ZERO;
        let obj_ref = ObjectReference::new(id, 1, iota_types::Digest::ZERO);
        let kind = InputKind::Input(iota_types::Input::ImmutableOrOwned(obj_ref));
        assert_eq!(kind.object_id(), Some(id));
    }

    #[test]
    fn input_kind_input_shared_returns_object_id() {
        let id = ObjectId::ZERO;
        let kind = InputKind::Input(iota_types::Input::Shared {
            object_id: id,
            initial_shared_version: 1,
            mutable: false,
        });
        assert_eq!(kind.object_id(), Some(id));
    }

    #[test]
    fn input_kind_input_receiving_returns_object_id() {
        let id = ObjectId::ZERO;
        let obj_ref = ObjectReference::new(id, 1, iota_types::Digest::ZERO);
        let kind = InputKind::Input(iota_types::Input::Receiving(obj_ref));
        assert_eq!(kind.object_id(), Some(id));
    }

    // --- Input::object_id tests ---

    #[test]
    fn input_object_id_with_immutable_or_owned() {
        let id = ObjectId::ZERO;
        let input = Input {
            kind: InputKind::ImmutableOrOwned(id),
            is_gas: false,
        };
        assert_eq!(input.object_id(), Some(&id));
    }

    #[test]
    fn input_object_id_with_pure_returns_none() {
        let input = Input {
            kind: InputKind::Input(iota_types::Input::Pure {
                value: vec![0, 1, 2],
            }),
            is_gas: false,
        };
        assert_eq!(input.object_id(), None);
    }

    #[test]
    fn input_object_id_with_shared() {
        let id = ObjectId::ZERO;
        let input = Input {
            kind: InputKind::Shared {
                object_id: id,
                mutable: false,
            },
            is_gas: false,
        };
        assert_eq!(input.object_id(), Some(&id));
    }

    // --- Argument::resolve tests ---

    #[test]
    fn argument_resolve_gas() {
        let map = HashMap::new();
        let resolved = Argument::Gas.resolve(&map);
        assert_eq!(resolved, iota_types::Argument::Gas);
    }

    #[test]
    fn argument_resolve_input_found() {
        let mut map = HashMap::new();
        map.insert(0usize, 5u16);
        let resolved = Argument::Input(0).resolve(&map);
        assert_eq!(resolved, iota_types::Argument::Input(5));
    }

    #[test]
    fn argument_resolve_input_not_found_defaults_to_gas() {
        let map = HashMap::new();
        let resolved = Argument::Input(99).resolve(&map);
        assert_eq!(resolved, iota_types::Argument::Gas);
    }

    #[test]
    fn argument_resolve_result() {
        let map = HashMap::new();
        let resolved = Argument::Result(7).resolve(&map);
        assert_eq!(resolved, iota_types::Argument::Result(7));
    }

    #[test]
    fn argument_resolve_nested_result() {
        let map = HashMap::new();
        let resolved = Argument::NestedResult(3, 4).resolve(&map);
        assert_eq!(resolved, iota_types::Argument::NestedResult(3, 4));
    }

    // --- Command::resolve tests ---

    #[test]
    fn command_resolve_transfer_objects() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);
        map.insert(1usize, 1u16);

        let cmd = Command::TransferObjects(TransferObjects {
            objects: vec![Argument::Input(0)],
            address: Argument::Input(1),
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::TransferObjects(t) => {
                assert_eq!(t.objects.len(), 1);
                assert_eq!(t.objects[0], iota_types::Argument::Input(0));
                assert_eq!(t.address, iota_types::Argument::Input(1));
            }
            _ => panic!("expected TransferObjects"),
        }
    }

    #[test]
    fn command_resolve_split_coins() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);
        map.insert(1usize, 1u16);

        let cmd = Command::SplitCoins(SplitCoins {
            coin: Argument::Gas,
            amounts: vec![Argument::Input(1)],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::SplitCoins(s) => {
                assert_eq!(s.coin, iota_types::Argument::Gas);
                assert_eq!(s.amounts.len(), 1);
                assert_eq!(s.amounts[0], iota_types::Argument::Input(1));
            }
            _ => panic!("expected SplitCoins"),
        }
    }

    #[test]
    fn command_resolve_merge_coins() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);
        map.insert(1usize, 1u16);
        map.insert(2usize, 2u16);

        let cmd = Command::MergeCoins(MergeCoins {
            coin: Argument::Input(0),
            coins_to_merge: vec![Argument::Input(1), Argument::Input(2)],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::MergeCoins(m) => {
                assert_eq!(m.coin, iota_types::Argument::Input(0));
                assert_eq!(m.coins_to_merge.len(), 2);
            }
            _ => panic!("expected MergeCoins"),
        }
    }

    #[test]
    fn command_resolve_publish() {
        let map = HashMap::new();
        let cmd = Command::Publish(Publish {
            modules: vec![vec![1, 2, 3]],
            dependencies: vec![ObjectId::ZERO],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::Publish(p) => {
                assert_eq!(p.modules.len(), 1);
                assert_eq!(p.dependencies.len(), 1);
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn command_resolve_move_call() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);

        let cmd = Command::MoveCall(MoveCall {
            package: ObjectId::ZERO,
            module: Identifier::new("test_module").unwrap(),
            function: Identifier::new("test_fn").unwrap(),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0)],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::MoveCall(mc) => {
                assert_eq!(mc.package, ObjectId::ZERO);
                assert_eq!(mc.module.as_str(), "test_module");
                assert_eq!(mc.function.as_str(), "test_fn");
                assert_eq!(mc.arguments.len(), 1);
            }
            _ => panic!("expected MoveCall"),
        }
    }

    #[test]
    fn command_resolve_make_move_vector() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);

        let cmd = Command::MakeMoveVector(MakeMoveVector {
            type_: Some(TypeTag::U64),
            elements: vec![Argument::Input(0)],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::MakeMoveVector(mv) => {
                assert_eq!(mv.type_, Some(TypeTag::U64));
                assert_eq!(mv.elements.len(), 1);
            }
            _ => panic!("expected MakeMoveVector"),
        }
    }

    #[test]
    fn command_resolve_upgrade() {
        let mut map = HashMap::new();
        map.insert(0usize, 0u16);

        let cmd = Command::Upgrade(Upgrade {
            modules: vec![vec![1, 2]],
            dependencies: vec![],
            package: ObjectId::ZERO,
            ticket: Argument::Result(0),
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::Upgrade(u) => {
                assert_eq!(u.modules.len(), 1);
                assert_eq!(u.package, ObjectId::ZERO);
                assert_eq!(u.ticket, iota_types::Argument::Result(0));
            }
            _ => panic!("expected Upgrade"),
        }
    }

    // --- Clone and Debug trait tests ---

    #[test]
    fn input_kind_clone_and_eq() {
        let kind1 = InputKind::ImmutableOrOwned(ObjectId::ZERO);
        let kind2 = kind1.clone();
        assert_eq!(kind1, kind2);
    }

    #[test]
    fn input_clone_and_eq() {
        let input1 = Input {
            kind: InputKind::ImmutableOrOwned(ObjectId::ZERO),
            is_gas: true,
        };
        let input2 = input1.clone();
        assert_eq!(input1, input2);
    }

    #[test]
    fn argument_copy() {
        let arg = Argument::Result(5);
        let copy = arg;
        // Both should be valid since Argument is Copy
        assert!(matches!(arg, Argument::Result(5)));
        assert!(matches!(copy, Argument::Result(5)));
    }

    // --- From trait tests ---

    #[test]
    fn command_from_move_call() {
        let mc = MoveCall {
            package: ObjectId::ZERO,
            module: Identifier::new("m").unwrap(),
            function: Identifier::new("f").unwrap(),
            type_arguments: vec![],
            arguments: vec![],
        };
        let cmd: Command = mc.into();
        assert!(matches!(cmd, Command::MoveCall(_)));
    }

    #[test]
    fn command_from_transfer_objects() {
        let to = TransferObjects {
            objects: vec![],
            address: Argument::Gas,
        };
        let cmd: Command = to.into();
        assert!(matches!(cmd, Command::TransferObjects(_)));
    }

    #[test]
    fn command_from_split_coins() {
        let sc = SplitCoins {
            coin: Argument::Gas,
            amounts: vec![],
        };
        let cmd: Command = sc.into();
        assert!(matches!(cmd, Command::SplitCoins(_)));
    }

    #[test]
    fn command_from_merge_coins() {
        let mc = MergeCoins {
            coin: Argument::Gas,
            coins_to_merge: vec![],
        };
        let cmd: Command = mc.into();
        assert!(matches!(cmd, Command::MergeCoins(_)));
    }

    #[test]
    fn command_from_publish() {
        let p = Publish {
            modules: vec![],
            dependencies: vec![],
        };
        let cmd: Command = p.into();
        assert!(matches!(cmd, Command::Publish(_)));
    }

    #[test]
    fn command_from_make_move_vector() {
        let mv = MakeMoveVector {
            type_: None,
            elements: vec![],
        };
        let cmd: Command = mv.into();
        assert!(matches!(cmd, Command::MakeMoveVector(_)));
    }

    #[test]
    fn command_from_upgrade() {
        let u = Upgrade {
            modules: vec![],
            dependencies: vec![],
            package: ObjectId::ZERO,
            ticket: Argument::Gas,
        };
        let cmd: Command = u.into();
        assert!(matches!(cmd, Command::Upgrade(_)));
    }

    // --- Multiple argument resolution tests ---

    #[test]
    fn resolve_multiple_arguments_in_command() {
        let mut map = HashMap::new();
        map.insert(0usize, 10u16);
        map.insert(1usize, 20u16);
        map.insert(2usize, 30u16);

        let cmd = Command::TransferObjects(TransferObjects {
            objects: vec![
                Argument::Input(0),
                Argument::Input(1),
                Argument::Result(5),
            ],
            address: Argument::Input(2),
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::TransferObjects(t) => {
                assert_eq!(t.objects[0], iota_types::Argument::Input(10));
                assert_eq!(t.objects[1], iota_types::Argument::Input(20));
                assert_eq!(t.objects[2], iota_types::Argument::Result(5));
                assert_eq!(t.address, iota_types::Argument::Input(30));
            }
            _ => panic!("expected TransferObjects"),
        }
    }

    #[test]
    fn resolve_empty_split_coins() {
        let map = HashMap::new();
        let cmd = Command::SplitCoins(SplitCoins {
            coin: Argument::Gas,
            amounts: vec![],
        });
        let resolved = cmd.resolve(&map);
        match resolved {
            iota_types::Command::SplitCoins(s) => {
                assert_eq!(s.coin, iota_types::Argument::Gas);
                assert!(s.amounts.is_empty());
            }
            _ => panic!("expected SplitCoins"),
        }
    }
}
