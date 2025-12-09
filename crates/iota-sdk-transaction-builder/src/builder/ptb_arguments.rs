// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{ObjectId, ObjectReference};

use crate::{
    builder::TransactionBuildData,
    types::MoveArg,
    unresolved::{Argument, InputKind},
};

/// A trait which defines a single argument for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
#[diagnostic::on_unimplemented(message = "Provided value is not a valid move argument.")]
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

impl PTBArgument for &ObjectId {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (*self).arg(ptb)
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

impl<T: MoveArg> PTBArgument for T {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.pure_bytes(self.pure_bytes().0)
    }
}

impl<T> PTBArgument for std::sync::Arc<T>
where
    for<'a> &'a T: PTBArgument,
{
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.as_ref().arg(ptb)
    }
}

/// A trait which defines a list of arguments for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
#[diagnostic::on_unimplemented(
    message = "Provided value is not a valid list of arguments.",
    note = "Expected a tuple, vector, array, or slice of types that implement `PTBArgument`."
)]
pub trait PTBArgumentList {
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
        impl<$($T),+> PTBArgumentList for ($($T),+)
        where $($T: PTBArgument),+
        {
            fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
                $(
                    args.push(self.$n.arg(ptb));
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_ptb_args_tuple, 2, 15, T);

impl<T: PTBArgument> PTBArgumentList for Vec<T> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<const N: usize, T: PTBArgument> PTBArgumentList for [T; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }
}

impl<T> PTBArgumentList for &[T]
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
#[derive(Debug, Clone)]
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
            panic!("no command result named `{}` exists", self.0)
        }
    }
}
