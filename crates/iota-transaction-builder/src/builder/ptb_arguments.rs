// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{ObjectId, ObjectReference};

use crate::{
    builder::TransactionBuildData,
    types::{MoveArg, MoveArgCollection},
    unresolved::{Argument, InputKind},
};

/// A trait which defines an argument for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
pub trait PTBArgument {
    /// Get the argument.
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument;
}

impl PTBArgument for Argument {
    fn arg(self, _ptb: &mut TransactionBuildData) -> Argument {
        self
    }
}

impl PTBArgument for iota_types::Input {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.input(self)
    }
}

impl PTBArgument for ObjectId {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(InputKind::ImmutableOrOwned(self), false)
    }
}

impl PTBArgument for ObjectReference {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Input(iota_types::Input::ImmutableOrOwned(self)),
            false,
        )
    }
}

impl<T: MoveArgCollection> PTBArgument for T {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.pure_bytes(self.collection_bytes().0)
    }
}

/// A trait which defines arguments for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
pub trait PTBArguments {
    /// Get the arguments.
    fn args(self, ptb: &mut TransactionBuildData) -> Vec<Argument>
    where
        Self: Sized,
    {
        let mut args = Vec::new();
        self.push_args(ptb, &mut args);
        args
    }

    /// Push the args onto the list.
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>);
}

macro_rules! impl_ptb_args_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> PTBArguments for ($($T),+)
        where $($T: PTBArguments),+
        {
            fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
                $(
                    self.$n.push_args(ptb, args);
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_ptb_args_tuple, 2, 15, T);

impl<T> PTBArguments for std::sync::Arc<T>
where
    for<'a> &'a T: PTBArguments,
{
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        self.as_ref().push_args(ptb, args);
    }
}

impl<T: PTBArgument> PTBArguments for T {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        args.push(self.arg(ptb))
    }
}

impl PTBArguments for Vec<Argument> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize> PTBArguments for [Argument; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl PTBArguments for Vec<iota_types::Input> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize> PTBArguments for [iota_types::Input; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl PTBArguments for Vec<ObjectId> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize> PTBArguments for [ObjectId; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl PTBArguments for Vec<ObjectReference> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize> PTBArguments for [ObjectReference; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl PTBArguments for Vec<Res> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize> PTBArguments for [Res; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<T> PTBArguments for &[T]
where
    for<'a> &'a T: PTBArgument,
{
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

/// Allows specifying shared parameters.
pub struct Shared<T>(pub T);

impl<T: MoveArg> PTBArgument for Shared<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }
}

impl PTBArgument for Shared<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &Shared<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Shared {
                object_id: self.0,
                mutable: false,
            },
            false,
        )
    }
}

impl PTBArgument for Shared<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &Shared<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Input(iota_types::Input::Shared {
                object_id: self.0.object_id,
                mutable: false,
                initial_shared_version: self.0.version,
            }),
            false,
        )
    }
}

/// Allows specifying shared mutable parameters.
pub struct SharedMut<T>(pub T);

impl<T: MoveArg> PTBArgument for SharedMut<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }
}

impl PTBArgument for SharedMut<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &SharedMut<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Shared {
                object_id: self.0,
                mutable: true,
            },
            false,
        )
    }
}

impl PTBArgument for SharedMut<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &SharedMut<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Input(iota_types::Input::Shared {
                object_id: self.0.object_id,
                mutable: true,
                initial_shared_version: self.0.version,
            }),
            false,
        )
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveArg> PTBArgument for Receiving<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }
}

impl PTBArgument for Receiving<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &Receiving<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(InputKind::Receiving(self.0), false)
    }
}

impl PTBArgument for Receiving<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &Receiving<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(
            InputKind::Input(iota_types::Input::Receiving(self.0.clone())),
            false,
        )
    }
}

/// The result of a previous command by name.
pub struct Res(String);

/// Get the result of a previous command by name.
pub fn res(name: impl Into<String>) -> Res {
    Res(name.into())
}

impl PTBArgument for Res {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }
}

impl PTBArgument for &Res {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        if let Some(arg) = ptb.named_results.get(&self.0) {
            *arg
        } else {
            panic!("no command named `{}` exists", self.0)
        }
    }
}
